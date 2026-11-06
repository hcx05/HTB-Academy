# Enumerating AD Groups — HTB Academy (Active Directory PowerView) Writeup

- 目標：`10.129.40.46`（ACADEMY-AD-WS01，主機名 `WS01`，網域 `INLANEFREIGHT.LOCAL`）
- 帳密：`htb-student` / `Academy_student_AD!`
- 攻擊機：Arch Linux

## 答案總覽

| 題目 | 答案 |
|------|------|
| Q1 Records Management 群組中的使用者（first.last） | `jennifer.chandler` |
| Q2 WS01 上 Remote Management Users 群組的成員 | `samantha.patel`（`INLANEFREIGHT\samantha.patel`） |

---

## 0. 連線方式

題目寫 RDP，但只要有 shell 就能做查詢，所以和上一份 writeup（Enumerating AD Users）一樣改用 WinRM（5985）。`htb-student` 在 WS01 是本機管理員，顯示 `Pwn3d!`。

```bash
nxc winrm 10.129.40.46 -u htb-student -p 'Academy_student_AD!' -X 'whoami; hostname'
# inlanefreight\htb-student / WS01
```

PowerView 位置：`C:\Tools\PowerView.ps1`。

### 已知環境問題：PowerView 輸出是 byte 陣列

這台主機上 ADSI 回傳的字串屬性是 `System.Byte[]`，不是 .NET 字串。PowerView 的 `Convert-LDAPProperty` 因此出問題：有些屬性直接顯示成 byte 陣列，有些（如 `lastlogon`）會直接報 `Cannot convert argument "fileTime" ... System.Byte[]`。

這次用 `Get-DomainGroup`、`Get-DomainGroupMember` 沒有報錯，但輸出被截成 byte 陣列：

```
samaccountname : {82, 101, 99, 111...}      # "Reco..."
MemberName     : {106, 101, 110, 110...}    # "jenn..."
```

`distinguishedname` 與 `MemberDistinguishedName` 是正常文字，所以可以從 DN 讀出名字；`MemberName` 要自己解碼才拿得到 `samaccountname`。解法：改用原生 ADSI，並加一個 `byte[]` 解碼函式：

```powershell
function V($r,$n){ ($r.Properties[$n] | % { if($_ -is [byte[]]){[Text.Encoding]::ASCII.GetString($_)}else{$_} }) -join " | " }
```

---

## Q1 — Records Management 群組的成員

### 步驟 1：找群組

```powershell
Import-Module C:\Tools\PowerView.ps1
Get-DomainGroup *Records* | select samaccountname,distinguishedname | fl
```

```
samaccountname    : {82, 101, 99, 111...}
distinguishedname : CN=Records Management,OU=Microsoft Exchange Security Groups,DC=INLANEFREIGHT,DC=LOCAL
```

群組在 `Microsoft Exchange Security Groups` OU 下。

### 步驟 2：列成員

```powershell
Get-DomainGroupMember -Identity "Records Management" | select MemberName,MemberDistinguishedName | fl
```

```
MemberName              : {106, 101, 110, 110...}
MemberDistinguishedName : CN=Jennifer Chandler,OU=Help Desk,DC=INLANEFREIGHT,DC=LOCAL
```

只有一個成員。`MemberName` 是 byte 陣列，所以要確認真正的 `samaccountname` 格式（題目要 `first.last`）。

### 步驟 3：用 ADSI 解碼並確認

```powershell
$s=[adsisearcher]"(&(objectCategory=group)(cn=Records Management))"
$g=$s.FindOne(); "member: " + (V $g "member")

# 直接成員
$u=[adsisearcher]"(&(objectCategory=user)(memberOf=CN=Records Management,OU=Microsoft Exchange Security Groups,DC=INLANEFREIGHT,DC=LOCAL))"
$u.FindAll() | % { "sam=" + (V $_ "samaccountname") + " name=" + (V $_ "cn") }

# 含巢狀群組（LDAP_MATCHING_RULE_IN_CHAIN）
$u2=[adsisearcher]"(&(objectCategory=user)(memberOf:1.2.840.113556.1.4.1941:=CN=Records Management,OU=Microsoft Exchange Security Groups,DC=INLANEFREIGHT,DC=LOCAL))"
$u2.FindAll() | % { "nested sam=" + (V $_ "samaccountname") }
```

```
member: CN=Jennifer Chandler,OU=Help Desk,DC=INLANEFREIGHT,DC=LOCAL
sam=jennifer.chandler name=Jennifer Chandler
nested sam=jennifer.chandler
```

直接成員與巢狀成員結果相同，沒有被漏掉的帳號。

**答案：`jennifer.chandler`**

---

## Q2 — WS01 上 Remote Management Users 群組的成員

這是 WS01 的**本機群組**，不是網域群組，所以 `Get-DomainGroupMember` 查不到。要查本機群組：用內建的 `net localgroup`（或 PowerView 的 `Get-NetLocalGroupMember`）。

```powershell
net localgroup "Remote Management Users"
```

```
Alias name     Remote Management Users
Comment        Members of this group can access WMI resources over management protocols (such as WS-Management via the Windows Remote Management service). ...

Members

-------------------------------------------------------------------------------
INLANEFREIGHT\samantha.patel
The command completed successfully.
```

成員是網域使用者 `samantha.patel`（回答時只填 `samantha.patel`）。

**答案：`samantha.patel`**

> 這類本機群組的成員是以 `DOMAIN\user` 格式存在本機 SAM，AD 端的 `memberOf` 看不到。所以查 AD 群組要用 `Get-DomainGroupMember`，查某台主機的本機群組要用 `net localgroup`、`Get-NetLocalGroupMember` 或 `Get-LocalGroupMember`。

---

## 重點整理

- 查群組：`Get-DomainGroup *關鍵字*` 找 DN，`Get-DomainGroupMember -Identity "群組名"` 列成員，`-Recurse` 可展開巢狀群組。
- 本機群組與網域群組是兩回事：Q2 的 Remote Management Users 在 WS01 本機，要在該主機上用 `net localgroup` 查。
- PowerView 在這台主機把字串屬性顯示成 `System.Byte[]`（如 `MemberName`）。DN 欄位仍可讀；需要 `samaccountname` 時改用 `[adsisearcher]` 加 `byte[]` 解碼函式 `V`。
- 巢狀成員的 LDAP 寫法：`memberOf:1.2.840.113556.1.4.1941:=<群組 DN>`。
- 用 WinRM（`nxc winrm -X`）比 RDP 更適合批次查詢和複製輸出。
