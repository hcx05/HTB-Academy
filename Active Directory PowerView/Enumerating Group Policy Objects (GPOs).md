# Enumerating Group Policy Objects (GPOs) — HTB Academy Writeup

## 題目

> Q1: Find the GUID of the Audit Policy GPO.
> RDP to 10.129.80.1 (ACADEMY-AD-WS01), user `htb-student` / `Academy_student_AD!`

**正解：`8bb15712-8a05-47e7-9dcf-897999d695fe`**（GPO 的 `objectGUID`，非資料夾/`cn` GUID）

---

## 連線方式

題目要求 RDP，但本機沒有 GUI/RDP client，實際用 **evil-winrm** 連進 `ACADEMY-AD-WS01` 代替：

```bash
evil-winrm -i 10.129.80.1 -u htb-student -p 'Academy_student_AD!'
```

連線成功，拿到 shell：

```
*Evil-WinRM* PS C:\Users\htb-student\Documents>
whoami
inlanefreight\htb-student
```

Domain: `INLANEFREIGHT.LOCAL`（`Get-Domain` 確認，Forest 同名）。

---

## 第一次嘗試：直接用 PowerView

目標機已有工具箱，找到 PowerView：

```powershell
Get-ChildItem -Path C:\Tools -Recurse -Filter *.ps1
# -> C:\Tools\PowerView.ps1
```

載入並查 GPO：

```powershell
Import-Module C:\Tools\PowerView.ps1
Get-DomainGPO -Identity "Audit Policy" -Properties displayname,name | Format-List
```

**結果：完全沒輸出。** 連 `Get-DomainGPO`（不帶任何過濾條件）也回傳 0 筆：

```powershell
$gpos = Get-DomainGPO
$gpos.Count   # 0
```

---

## 除錯過程

### 1. 確認 PowerView 本身有載入、網域連得到

```powershell
Get-Command Get-DomainGPO     # 函式存在
Get-Domain | Format-List      # Forest=INLANEFREIGHT.LOCAL, Name=INLANEFREIGHT.LOCAL
(Get-DomainUser -Identity htb-student).samaccountname   # 能查到使用者，LDAP 基本功能正常
```

→ PowerView 可用、LDAP 可連，但 GPO 查詢特別失敗。

### 2. 用 Verbose 看 PowerView 實際發出的 LDAP filter

```powershell
Get-DomainGPO -Verbose -ErrorAction Continue | Out-Null
```

```
Verbose: [Get-DomainSearcher] search base: LDAP://DC=INLANEFREIGHT,DC=LOCAL
Verbose: [Get-DomainGPO] filter string: (&(objectCategory=groupPolicyContainer))
```

filter 語法正常，但從網域根（`DC=INLANEFREIGHT,DC=LOCAL`）、`Subtree` 範圍去搜，回傳 0。

### 3. 繞過 PowerView，手刻 LDAP 查詢定位問題

先確認 GPO 容器真的存在、且 `htb-student` 能列出其下物件：

```powershell
$s3 = New-Object System.DirectoryServices.DirectorySearcher(
        [ADSI]"LDAP://CN=Policies,CN=System,DC=INLANEFREIGHT,DC=LOCAL")
$s3.Filter = "(objectClass=*)"
$s3.SearchScope = "OneLevel"
($s3.FindAll()).Count    # 21 -> 確實有 21 個 GPO container
```

→ **直接針對 `CN=Policies,CN=System,...` 做 OneLevel 查詢可以列出 21 個 GPO**，但從網域根做 `Subtree` + `(objectCategory=groupPolicyContainer)` 過濾卻是 0。

進一步發現，連 `objectClass`、`displayName`、`cn` 這些屬性值全部讀不到，只有 `adspath`：

```powershell
$s3.PropertiesToLoad.Add("displayName")
$s3.PropertiesToLoad.Add("objectClass")
$r = $s3.FindOne()
$r.Properties.PropertyNames    # 只有 adspath，其餘屬性全部空白
```

用 `[ADSI]` 直接 bind 單一 GPO 再 `RefreshCache()` 更明顯報錯：

```powershell
$e = [ADSI]"LDAP://CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=INLANEFREIGHT,DC=LOCAL"
$e.RefreshCache(@("displayName"))
```

```
The following exception occurred while retrieving member "RefreshCache":
"The specified directory service attribute or value does not exist."
```

**同一組命令對 `htb-student` 自己的 user 物件卻完全正常**（能讀到 `displayName`/`samAccountName`），證明不是帳號整體沒有讀取 LDAP 屬性的能力，而是**這個 WinRM session 讀 GPO 容器屬性時被卡住**。

### 4. 根因：WinRM 的 double-hop 問題

`evil-winrm` 用 NTLM/Negotiate 對 `ACADEMY-AD-WS01` 做的是 **network logon（Type 3）**，這種 token 不帶可委派的密碼/雜湊，所以 session 內的程式（PowerView / `DirectorySearcher`）用「環境目前的身份」去跟 DC 做第二次驗證（second hop）時失敗或退化，導致 LDAP bind 拿不到足夠權限把屬性值讀回來（只能看到物件存在/路徑，讀不到內容）——這就是經典 **double-hop 限制**，而不是 ACL 真的擋掉這個帳號。

RDP 走 interactive logon（Type 2），完整快取密碼，不會有這個問題，這也是題目特別指定 RDP 的原因。

### 5. 繞過方法：LDAP bind 時明確帶帳密

不依賴 WinRM session 的環境 token，改用 `DirectoryEntry` 建構子直接傳入帳密，繞開 double-hop：

```powershell
$de = New-Object System.DirectoryServices.DirectoryEntry(
        "LDAP://CN=Policies,CN=System,DC=INLANEFREIGHT,DC=LOCAL",
        "inlanefreight\htb-student",
        "Academy_student_AD!")
$s  = New-Object System.DirectoryServices.DirectorySearcher($de)
$s.Filter = "(objectClass=groupPolicyContainer)"
$s.SearchScope = "OneLevel"
$s.PropertiesToLoad.AddRange(@("displayName","cn"))

foreach ($r in $s.FindAll()) {
    ($r.Properties["cn"] -join ",") + " => " + ($r.Properties["displayName"] -join ",")
}
```

**成功**，列出全部 21 個 GPO 的 displayName，包含：

```
{2954AA86-C58F-4F4C-B3C7-5D49C5AE6EC4} => Audit Policy
```

---

## cn/name GUID vs objectGUID — 答案錯誤的原因

上面拿到的 `{2954AA86-C58F-4F4C-B3C7-5D49C5AE6EC4}` 是 GPO 的 **`cn`/`name` 屬性**（也是 SYSVOL 資料夾名稱），**提交後錯誤**。

AD 裡每個 GPO 物件其實有兩個不同的 GUID：

| 屬性 | 值 | 用途 |
|---|---|---|
| `cn` / `name` | `{2954AA86-C58F-4F4C-B3C7-5D49C5AE6EC4}` | GPO 的「識別資料夾」GUID，等於 SYSVOL 路徑 `\Policies\{GUID}`、`gpLink` 裡引用的值 |
| `objectGUID` | `8bb15712-8a05-47e7-9dcf-897999d695fe` | AD 物件本身的通用 GUID（二進位屬性，每個 AD object 都有） |

題目要的是後者（`objectGUID`）。補查：

```powershell
$s.PropertiesToLoad.AddRange(@("displayName","cn","name","objectGUID","gPCFileSysPath"))
foreach ($r in $s.FindAll()) {
    if (($r.Properties["displayName"] -join ",") -eq "Audit Policy") {
        "cn="   + ($r.Properties["cn"] -join ",")
        "guid=" + ([guid]($r.Properties["objectGUID"][0])).ToString()
        "path=" + ($r.Properties["gPCFileSysPath"] -join ",")
    }
}
```

輸出：

```
cn=    {2954AA86-C58F-4F4C-B3C7-5D49C5AE6EC4}
guid=  8bb15712-8a05-47e7-9dcf-897999d695fe
path=  \\INLANEFREIGHT.LOCAL\SysVol\INLANEFREIGHT.LOCAL\Policies\{2954AA86-C58F-4F4C-B3C7-5D49C5AE6EC4}
```

`objectGUID` 是 byte array，必須用 `[guid]` 轉型才能印成標準字串格式；直接 `-join` 會印出一堆無意義的位元組字元。

---

## 最終答案

```
8bb15712-8a05-47e7-9dcf-897999d695fe
```

---

## 學習重點

1. **PowerView 在 evil-winrm 下可能查不到東西，不代表 ACL 擋你** —— 先用 `-Verbose` 看它真正送出的 LDAP filter 跟 search base，再用原生 `System.DirectoryServices.DirectorySearcher` 手動重現，才能定位是查詢邏輯錯、範圍錯、還是權限/連線問題。
2. **WinRM double-hop** 是 PSRemoting 老問題：session 內對第三台機器（這裡是 DC）的驗證可能失敗或降級。解法除了 CredSSP/Kerberos delegation，最簡單是在程式碼裡「自己再帳密驗證一次」（`DirectoryEntry(path, user, pass)`），不依賴 WinRM 幫你傳遞身份。
3. **GPO 有兩個 GUID**：`cn`/`name`（= SYSVOL 資料夾名、`gpLink` 用的值）跟 `objectGUID`（AD 物件 GUID）。兩者常被搞混，題目問「GPO 的 GUID」多半指 `objectGUID`，而不是資料夾 GUID。
4. `objectGUID` 從 LDAP 讀回來是 raw byte array，要 `[guid]$bytes` 轉型才能得到人類可讀格式。
