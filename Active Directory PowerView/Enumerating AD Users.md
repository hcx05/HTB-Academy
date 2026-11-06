# Enumerating AD Users — HTB Academy (Active Directory PowerView) Writeup

- 目標：`10.129.194.148`（ACADEMY-AD-WS01，主機名 `WS01`，網域 `INLANEFREIGHT.LOCAL`）
- 帳密：`htb-student` / `Academy_student_AD!`
- 攻擊機：Arch Linux，`tun0` = `10.10.14.210`

## 答案總覽

| 題目 | 答案 |
|------|------|
| Q1 另一個設定 Kerberos constrained delegation 的使用者 | `adam.jones`（`svc-scan`，見下方說明） |
| Q2 第二個 description 欄位含密碼的使用者密碼 | `W4y_am_I_d0ing_Th1s?`（`joel.johnson`） |
| Q3 教材輸出沒列出、但有 SPN 的使用者 | `WSUSupdatesvc` |
| Q4 Administrators 群組中來自其他網域的使用者 | `bob.barker`（`LOGISTICS.INLANEFREIGHT.LOCAL`） |

> 教材範例輸出不在本機目錄中，所以「教材已列出哪些」（Q1 的 `sqlprod`、Q2 的第一組密碼、Q3 的清單）是依教材的印象判斷。若 Q1、Q2 的答案不被接受，請改交下面列出的另一個候選。

---

## 0. 連線方式與環境問題（卡關原因）

題目寫 RDP，但只要有 shell 就能做 PowerView 查詢，所以我改用 WinRM（5985）。這台 WS01 上 `htb-student` 是本機管理員，WinRM 與 SMB 都顯示 `Pwn3d!`。

```bash
nxc winrm 10.129.194.148 -u htb-student -p 'Academy_student_AD!' -X 'whoami; hostname'
# inlanefreight\htb-student / WS01
```

PowerView 位置：`C:\Tools\PowerView.ps1`（另有 `C:\Tools\PowerSploit-dev\Recon\PowerView.ps1`）。

### 卡點：PowerView 直接跑會報錯

```powershell
Import-Module C:\Tools\PowerView.ps1
Get-DomainUser -TrustedToAuth
```

```
Cannot convert argument "fileTime", with value: "System.Byte[]", for "FromFileTime" to type "System.Int64"
```

兩份 PowerView（`C:\Tools\PowerView.ps1` 與 PowerSploit-dev 版）都一樣。原因：這台主機上 ADSI 回傳的屬性值是 `System.Byte[]`，不是 .NET 型別（Int64、string）。PowerView 的 `Convert-LDAPProperty` 在把 `lastlogon`、`pwdlastset` 等屬性轉成時間時，把 `byte[]` 丟給 `[DateTime]::FromFileTime()` 就爆了。這不是指令寫錯，是環境與教材示範不一致。

### 嘗試二：加 `-Properties` 只取需要的欄位

```powershell
Get-DomainUser -TrustedToAuth -Properties samaccountname,msds-allowedtodelegateto
```

不再報錯，但值全是 byte 陣列，無法直接閱讀：

```
samaccountname : {115, 113, 108, 112...}      # "sqlp..."
```

### 最後做法：改用原生 ADSI，自己把 byte[] 解碼

寫一個小函式，`byte[]` 就用 ASCII 解碼：

```powershell
function S($f,$p){ $s=[adsisearcher]$f; $s.PageSize=500; $p|%{[void]$s.PropertiesToLoad.Add($_)}; $s.FindAll() }
function V($r,$n){ ($r.Properties[$n] | % { if($_ -is [byte[]]){[Text.Encoding]::ASCII.GetString($_)}else{$_} }) -join ' | ' }
```

連數值（如 `useraccountcontrol`）也是 `byte[]`，直接 `-band` 會報 `Cannot convert the "System.Byte[]" value ... to type "System.Int32"`，所以同樣要先過 `V` 解碼。

這些 LDAP filter 與 PowerView 對應的查詢等價。

---

## Q1 — 另一個設定 constrained delegation 的使用者

PowerView 寫法（教材）：

```powershell
Get-DomainUser -TrustedToAuth
```

等價 LDAP filter（實際使用）：

```powershell
S '(&(objectCategory=user)(msDS-AllowedToDelegateTo=*))' 'samaccountname','msds-allowedtodelegateto'
```

結果：

```
sqlprod    :: cifs/SQL01.INLANEFREIGHT.LOCAL | cifs/SQL01
svc-scan   :: cifs/EXCHG01.INLANEFREIGHT.LOCAL | cifs/EXCHG01
adam.jones :: cifs/DC01.INLANEFREIGHT.LOCAL/INLANEFREIGHT.LOCAL | cifs/DC01.INLANEFREIGHT.LOCAL | cifs/DC01 | ...
```

三個帳號都有 `msDS-AllowedToDelegateTo`。教材範例是 `sqlprod`，所以「另一個」是 `svc-scan` 或 `adam.jones`。`userAccountControl` 值：

| 帳號 | UAC | 意義 |
|------|-----|------|
| sqlprod | 512 | 一般帳號 |
| svc-scan | 66048 | 512 + `DONT_EXPIRE_PASSWORD` |
| adam.jones | 66080 | 66048 + `PASSWD_NOTREQD` |

三個都沒有 `TRUSTED_TO_AUTH_FOR_DELEGATION`（0x1000000）。這個旗標代表 protocol transition，與 `msDS-AllowedToDelegateTo` 的設定是分開的。

**答案：`adam.jones`**。備選 `svc-scan`。其中 `adam.jones` 的委派目標是 DC01 的 `cifs`，攻擊價值最高。

---

## Q2 — description 欄位含密碼的第二個使用者

```powershell
Get-DomainUser * | Select-Object samaccountname,description | ? {$_.description -ne $null}
```

等價 LDAP：

```powershell
S '(&(objectCategory=user)(description=*))' 'samaccountname','description'
```

結果：

```
Administrator :: Built-in account for administering the computer/domain
Guest         :: Built-in account for guest access to the computer/domain
DefaultAccount:: A user account managed by the system.
krbtgt        :: Key Distribution Center Service Account
svc-sccm      :: **Do not change password** 03/04/2015 N3ssu$_svc2014!
joel.johnson  :: **Saving this here** 3/02/2011 - W4y_am_I_d0ing_Th1s?
```

有兩個帳號把密碼放在 description：`svc-sccm`（`N3ssu$_svc2014!`）和 `joel.johnson`。教材示範的是 `svc-sccm`，所以第二個是 `joel.johnson`。

**答案：`W4y_am_I_d0ing_Th1s?`**（若不被接受，改交 `N3ssu$_svc2014!`）

---

## Q3 — 教材輸出沒列出的 SPN 使用者（區分大小寫）

```powershell
Get-DomainUser * -SPN | Select-Object samaccountname
```

等價 LDAP：

```powershell
S '(&(objectCategory=user)(servicePrincipalName=*))' 'samaccountname','serviceprincipalname'
```

結果：

```
sqldev        :: CIFS/roguecomputer.inlanefreight.local | MSSQL_svc_dev/inlanefreight.local:1443
WSUSupdatesvc :: HTTP/WSUS01.inlanefreight.local:8530
adam.jones    :: IIS_dev/inlanefreight.local:80
krbtgt        :: kadmin/changepw
sqlqa         :: MSSQL_svc_qa/inlanefreight.local:1443
sql-test      :: MSSQL_svc_test/inlanefreight.local:1443
sqlprod       :: MSSQLSvc/sql01:1433
svc-scan      :: scantest/inlanefreight.local
```

**更正：** 一開始我交 `svc-scan`，被判錯，原因是教材輸出其實已經列出 `svc-scan`（Q1 的委派帳號同時也有 SPN `scantest/inlanefreight.local`），不算「沒列出」。

8 個有 SPN 的帳號裡，剩下沒被教材輸出列出的是 `WSUSupdatesvc`（SPN `HTTP/WSUS01.inlanefreight.local:8530`）。題目又特別標示「區分大小寫」，而這個帳號是唯一大小寫混合的名稱，所以提示就是指它。

**答案：`WSUSupdatesvc`**

> 教訓：不能只看「清單中多出的名字」，要先確認教材範例輸出實際列了哪些帳號；題目的「case-sensitive」提示通常指向大小寫混合的帳號名。

---

## Q4 — Administrators 群組中來自其他網域的使用者

先看信任關係：

```cmd
nltest /domain_trusts
```

```
0: LOGISTICS LOGISTICS.INLANEFREIGHT.LOCAL (NT 5) (Forest: 2) (Direct Outbound) (Direct Inbound)
1: FREIGHTLOGISTIC freightlogistics.local (NT 5) (Direct Outbound) (Direct Inbound)
2: INLANEFREIGHT INLANEFREIGHT.LOCAL (Forest Tree Root) (Primary Domain)
```

再讀本網域 `Builtin\Administrators` 的 `member` 屬性：

```powershell
$ds = [adsisearcher]::new([adsi]"LDAP://INLANEFREIGHT.LOCAL")
$ds.Filter = '(&(objectCategory=group)(cn=Administrators))'
$ds.FindAll() | % { $_.Properties['member'] }
```

```
CN=bob.barker,CN=Users,DC=LOGISTICS,DC=INLANEFREIGHT,DC=LOCAL
CN=S-1-5-21-888139820-103978830-333442103-1602,CN=ForeignSecurityPrincipals,DC=INLANEFREIGHT,DC=LOCAL
CN=mrb3n,OU=Admin,DC=INLANEFREIGHT,DC=LOCAL
CN=Domain Admins,CN=Users,...
CN=Enterprise Admins,CN=Users,...
CN=Administrator,CN=Users,...
```

`bob.barker` 的 DN 在 `DC=LOGISTICS,DC=INLANEFREIGHT,DC=LOCAL`，是來自 LOGISTICS 網域的使用者。

**答案：`bob.barker`**

### 無法完成的部分（與環境有關）

1. 另一筆是 ForeignSecurityPrincipal（`S-1-5-21-888139820-103978830-333442103-1602`），名稱沒有解析出來。`SecurityIdentifier.Translate` 報 `The trust relationship between the primary domain and the trusted domain failed`，`nltest /dsgetdc:freightlogistics.local` 報 `WSAECONNRESET`。這台 WS01 連不到 `freightlogistics.local` 與 `LOGISTICS` 的 DC。
2. PowerView 的 `Get-DomainForeignGroupMember -Domain ...` 也因此報 `A referral was returned from the server`，所以我沒有用它，而是直接讀本網域的 `member` 屬性。

---

## 重點整理

- PowerView 在這台主機報 `FromFileTime ... System.Byte[]` 是環境問題（ADSI 屬性是 `byte[]`），不是指令寫錯。
- 繞過方式：改用 `[adsisearcher]` 加自己的 `byte[]` 解碼函式。LDAP filter 與 PowerView 的 `-TrustedToAuth`、`-SPN`、`description` 篩選等價。
- 用 WinRM（`nxc winrm -X`）比 RDP 更適合批次查詢和複製輸出。
- Constrained delegation 看 `msDS-AllowedToDelegateTo`，protocol transition 另看 UAC 的 `0x1000000`。
- 跨網域管理員可以直接從本網域 `Administrators` 的 `member` DN 看出來，不用連到對方網域。
