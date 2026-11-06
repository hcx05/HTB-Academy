# Enumerating AD Computers

HTB Academy – Active Directory PowerView 模組 lab writeup。

- 目標：`10.129.46.179`（ACADEMY-AD-WS01，主機名 `WS01`，網域 `INLANEFREIGHT.LOCAL`）
- 帳號：`htb-student` / `Academy_student_AD!`
- 工具：PowerView（`C:\Tools\PowerView.ps1`）

## 題目與答案

| # | 問題 | 答案 |
|---|------|------|
| q1 | How many hosts are present in the domain? | `5` |
| q2 | What is the objectguid value of the EXCHG01 host? | `ec252fbd-765d-4833-9f9d-f1eaf712089e` |
| q3 | What OU does the WS01 host belong to? (2 words) | `Staff Workstations` |

---

## 1. 連線與環境確認

題目指定用 RDP，我這次從攻擊機改用 WinRM（5985）執行指令，效果相同，方便把輸出直接貼進紀錄。

先確認埠有開：

```bash
nc -zv -w 3 10.129.46.179 3389 5985 445
```

3389、5985、445 皆通。用 NetExec 驗證帳密：

```bash
nxc winrm 10.129.46.179 -u htb-student -p 'Academy_student_AD!' -x 'whoami /all & hostname'
```

結果顯示 `[+] INLANEFREIGHT.LOCAL\htb-student:Academy_student_AD! (Pwn3d!)`。`htb-student` 在 `BUILTIN\Administrators` 內，所以 WinRM 可用。

找 PowerView 在哪：

```powershell
Get-ChildItem C:\ -Recurse -Filter PowerView*.ps1 -ErrorAction SilentlyContinue | Select -Expand FullName
```

得到 `C:\Tools\PowerView.ps1` 與 `C:\Tools\PowerSploit-dev\Recon\PowerView.ps1`。

## 2. 卡關點：`Get-DomainComputer` 直接報錯

教材範例是直接跑 `Get-DomainComputer`，但在這個環境會出現：

```
Cannot convert argument "fileTime", with value: "System.Byte[]", for "FromFileTime"
to type "System.Int64": "Cannot convert the "System.Byte[]" value ... to type "System.Int64"."
```

我另外用 `Get-DomainComputer -Identity <name>` 對 5 台主機各跑一次，**全部**都是同樣的錯誤，所以不是某一台主機的資料問題。

錯誤訊息指出 PowerView 在把某個時間屬性（`FromFileTime`，像 `lastlogon`、`pwdlastset`、`accountexpires` 這類）轉成日期時，拿到的是 `byte[]` 而不是 `Int64`。我沒有追到是哪個屬性、為什麼型別不同，也沒有確認這是 WinRM 非互動 session 造成的還是 PowerView 版本問題。這一點我沒有驗證，只確定「不要求全部屬性」可以繞過。

**繞法：用 `-Properties` 只取需要的欄位**，就不會觸發轉換：

```powershell
Import-Module C:\Tools\PowerView.ps1
Get-DomainComputer -Properties name
```

加上 `-Properties` 後，PowerView 只向 LDAP 要這些屬性，所以不會碰到有問題的時間欄位。

## 3. q1 – 網域內有幾台主機

```powershell
$c = Get-DomainComputer -Properties name
($c | Measure-Object).Count
($c | Select -Expand name) -join ", "
```

輸出：

```
5
DC01, EXCHG01, SQL01, WS01, DC02
```

**答案：`5`**

## 4. q2 – EXCHG01 的 objectguid

```powershell
Get-DomainComputer -Identity EXCHG01 -Properties name,objectguid,distinguishedname | Format-List
```

輸出：

```
distinguishedname : CN=EXCHG01,OU=Mail Servers,OU=Servers,DC=INLANEFREIGHT,DC=LOCAL
name              : EXCHG01
objectguid        : ec252fbd-765d-4833-9f9d-f1eaf712089e
```

**答案：`ec252fbd-765d-4833-9f9d-f1eaf712089e`**

## 5. q3 – WS01 所屬的 OU

```powershell
Get-DomainComputer -Identity WS01 -Properties name,distinguishedname | Format-List
```

輸出：

```
distinguishedname : CN=WS01,OU=Staff Workstations,OU=Workstations,DC=INLANEFREIGHT,DC=LOCAL
name              : WS01
```

DN 由左往右讀：`CN=WS01` 是物件本身，緊接著的 `OU=Staff Workstations` 是直接所屬的 OU，再上一層是 `OU=Workstations`。題目要 2 個字、大小寫敏感，所以是最近的一層。

**答案：`Staff Workstations`**

## 6. 失敗的嘗試（記錄用）

**ActiveDirectory 模組交叉驗證失敗。** `Get-Module -ListAvailable ActiveDirectory` 顯示模組存在（1.0.0.0），但 `Get-ADComputer` 回報：

```
Unable to contact the server. This may be because this server does not exist, it is currently down, or it does not have the Active Directory Web Services running.
```

這個模組走 ADWS（port 9389），目前環境連不到，所以沒能用它來交叉驗證。PowerView 走的是 LDAP，不受影響。

**從攻擊機用 `ldapsearch` 計數失敗。** 我用 `htb-student` 做 simple bind 查 `(objectClass=computer)`，結果 0 筆。我沒有進一步查原因（可能是綁定被拒或 389 不通），所以沒有拿它當第二個證據。

因此這三個答案的證據只有 PowerView 一條路徑；其中 q1 的 5 台主機名稱與 q2、q3 的 DN 彼此一致（DC01、EXCHG01、SQL01、WS01、DC02）。

## 7. 重點整理

- `Get-DomainComputer` 沒加參數時會抓全部屬性；這個環境下會因 `FromFileTime` 的 `byte[]` 轉換錯誤失敗。
- 用 `-Properties name,objectguid,distinguishedname` 只取需要的屬性可以避開，而且查詢也比較精簡。
- 計數用 `Measure-Object`，OU 看 `distinguishedname` 從左數第二段。
- `-Identity` 可直接給電腦名稱，不需要自己寫 LDAP filter。
