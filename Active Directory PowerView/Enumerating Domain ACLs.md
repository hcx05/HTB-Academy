# Enumerating Domain ACLs

HTB Academy 授權教學 lab 的學習紀錄。模組：Active Directory PowerView。

## 環境

- 目標：ACADEMY-AD-WS01（10.129.4.40），網域 INLANEFREIGHT.LOCAL
- 登入方式：WinRM（evil-winrm）與 SMB，使用 lab 配給的 htb-student 帳號
- 工具：evil-winrm、netexec（nxc）、PowerView（C:\Tools\PowerView.ps1）

## 題目

1. 找出對 joe.evans 使用者擁有 GenericAll 權限的使用者（first.last 格式）。
2. 找出 WS01 上一個非標準的 share 名稱。
3. 找出另一個擁有 DCSync 權限的使用者（first.last 格式）。

## Q1：GenericAll over joe.evans

### 做法與指令

先確認連線與權限：

```bash
nxc smb 10.129.4.40 -u htb-student -p 'Academy_student_AD!'
nxc winrm 10.129.4.40 -u htb-student -p 'Academy_student_AD!'
evil-winrm -i 10.129.4.40 -u htb-student -p 'Academy_student_AD!'
```

用 PowerView 查 joe.evans 的 ACL：

```powershell
. C:\Tools\PowerView.ps1
Get-ObjectAcl -Identity joe.evans -ResolveGUIDs | Where-Object { $_.ActiveDirectoryRights -match 'GenericAll' }
```

用 ADSI 直接讀 ACL（PowerView 失敗後的替代做法）：

```powershell
$s = [adsisearcher]"(sAMAccountName=joe.evans)"
$dn = $s.FindOne().Properties.distinguishedname[0]
$de = [adsi]("LDAP://" + $dn)
$de.ObjectSecurity.Access | Where-Object { $_.ActiveDirectoryRights -match 'GenericAll' } | Select-Object IdentityReference,ActiveDirectoryRights,AccessControlType
```

### 卡關原因

1. `C:\Tools\PowerView.ps1` 執行 `Get-DomainUser` / `Get-ObjectAcl` 時報錯：

   ```
   Cannot convert argument "fileTime", with value: "System.Byte[]", for "FromFileTime" to type "System.Int64"
   ```

   錯誤發生在 PowerView.ps1 第 3210、3224 行，`[datetime]::FromFileTime()` 收到 `System.Byte[]`，而非 `Int64`。推測是此 PowerView 版本與這台機器的 PowerShell/.NET 版本不相容（未進一步驗證）。

2. `-ResolveGUIDs` 觸發 `Get-DomainGUIDMap`，它需要 `Get-Forest`，又因為上一點失敗而中斷：

   ```
   [Get-DomainGUIDMap] Error in retrieving forest schema path from Get-Forest
   ```

3. 改用 `C:\Tools\PowerSploit-dev\Recon\PowerView.ps1` 仍然有同樣的 fileTime 錯誤，而且長時間查詢會卡住。

4. 試過 `Import-Module ActiveDirectory`，失敗：

   ```
   Unable to contact the server. This may be because this server does not exist, it is currently down, or it does not have the Active Directory Web Services running.
   ```

   表示 ADWS 沒有在跑，RSAT AD 模組無法使用。

### 正確做法

不依賴 PowerView 的 user 物件解析，直接用 ADSI（LDAP）讀 `nTSecurityDescriptor`。ADSI 不經過 ADWS，這台機器上可用。

### 答案

ACL 中對 joe.evans 具有 GenericAll 的使用者為：

- `douglas.bull`

其餘 GenericAll 的 principal 為群組或系統帳號（Domain Admins、Enterprise Admins、Organization Management、Exchange Trusted Subsystem、NT AUTHORITY\SYSTEM、S-1-5-32-548），不符合「first.last 格式使用者」的題目要求。

## Q2：WS01 上的非標準 share

### 做法與指令

```bash
nxc smb 10.129.4.40 -u htb-student -p 'Academy_student_AD!' --shares
```

在 WinRM 內確認 share 對應路徑：

```powershell
Get-SmbShare | Select Name,Path
```

### 卡關原因

無。Share 列表直接取得。

### 正確做法

標準 share 為 `ADMIN$`、`C$`、`IPC$`。其餘皆為非標準 share：

| Share 名稱 | 路徑 | 權限（htb-student） |
|---|---|---|
| Client_Invoices | C:\Client_Invoices | READ,WRITE |
| Financials | C:\Financials | READ,WRITE |
| Old_reports | C:\Old_reports | READ,WRITE |

三個資料夾內容皆為空（遞迴列出無檔案）。

### 答案

`Client_Invoices`

## Q3：另一個擁有 DCSync 權限的使用者

### 做法與指令

DCSync 需要網域根物件上的 Replicating Directory Changes 相關 extended rights。GUID 如下：

- `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2`：DS-Replication-Get-Changes
- `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2`：DS-Replication-Get-Changes-All
- `89e95b76-444d-4c62-991a-0facbeda640c`：DS-Replication-Get-Changes-In-Filtered-Set

```powershell
$root = [adsi]"LDAP://RootDSE"
$de = [adsi]("LDAP://" + $root.defaultNamingContext)
$de.ObjectSecurity.Access | Where-Object { $_.ObjectType -in @([guid]'1131f6aa-9c07-11d1-f79f-00c04fc2dcd2',[guid]'1131f6ad-9c07-11d1-f79f-00c04fc2dcd2',[guid]'89e95b76-444d-4c62-991a-0facbeda640c') } | Select-Object IdentityReference,ObjectType,ActiveDirectoryRights,AccessControlType
```

### 卡關原因

同 Q1：PowerView 的 `Get-DomainObjectAcl -ResolveGUIDs` 因 GUID 對映失敗而無法使用。改用 ADSI 直接讀網域根 ACL 即可。

### 正確做法

對網域根物件讀 ACL，篩出上述三個 GUID 都具備（或 Get-Changes + Get-Changes-All）的 principal。

### 答案

在網域根物件上具備 DCSync 權限（Get-Changes + Get-Changes-All）的使用者：

- `INLANEFREIGHT\gillian.fisher`


