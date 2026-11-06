# HTB Academy AD 模組 Writeup

目標：`10.129.2.174`（WS01，網域 `INLANEFREIGHT.LOCAL`），帳號 `htb-student` / `Academy_student_AD!`。

## 答案

| 題 | 問題 | 答案 |
|---|---|---|
| q1 | liam.jones 的 SID | `S-1-5-21-2974783224-3764228556-2640795941-1705` |
| q2 | 目前網域的 child domain | `LOGISTICS.INLANEFREIGHT.LOCAL` |
| q3 | `...-1893` 對應的使用者 | `rita.grant` |

## 環境確認

```bash
ping -c2 -W2 10.129.2.174
nc -zv -w3 10.129.2.174 3389 445 5985 389
```

結果：ICMP 通（TTL 127，Windows），3389 / 445 / 5985 開，389 被拒（WS01 不是 DC，LDAP 查詢要打到 DC）。

教材用 RDP 操作。本次沒有開 RDP，改用已開的 WinRM（5985），以 netexec 執行 PowerShell，效果相同。`nxc` 回報 `Pwn3d!`，表示此帳號在 WS01 有 WinRM 執行權限。

## 除錯過程

### 1. `Get-ADUser` 失敗

```bash
nxc winrm 10.129.2.174 -u htb-student -p 'Academy_student_AD!' \
  -X 'Get-ADUser liam.jones | Select Name,SID | fl; Get-ADDomain | ...'
```

錯誤：

```
Unable to contact the server. This may be because this server does not exist, it is currently down, or it does not have the Active Directory Web Services running.
```

ActiveDirectory 模組的 cmdlet 靠 AD Web Services（ADWS，TCP 9389）通訊。這條路在此環境連不到，所以改用不依賴 ADWS 的 .NET / 原生工具。本次沒有進一步查明 ADWS 連不到的確切原因。

### 2. 改用 `[adsisearcher]`、.NET 與 `nltest`

```powershell
nltest /domain_trusts /all_trusts

# q1：LDAP 查使用者，把 objectSid 位元組轉成字串 SID
$s=[adsisearcher]"(samaccountname=liam.jones)"; $r=$s.FindOne()
(New-Object System.Security.Principal.SecurityIdentifier($r.Properties.objectsid[0],0)).Value

# q2：列出 child domain
([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).Children | % Name

# q3：SID 轉帳號
(New-Object System.Security.Principal.SecurityIdentifier("S-1-5-21-2974783224-3764228556-2640795941-1893")).Translate([System.Security.Principal.NTAccount]).Value
```

為了避免引號轉義問題，指令先寫進檔案，再以 `-X "$(cat q.ps1)"` 傳給 `nxc`。

## 各題結果

**q1**：`[adsisearcher]` 走 LDAP，不需要 ADWS。objectSid 是二進位，要用 `SecurityIdentifier` 轉成字串。結果為 `...-1705`。

**q2**：`nltest /domain_trusts` 輸出：

```
0: LOGISTICS LOGISTICS.INLANEFREIGHT.LOCAL (NT 5) (Forest: 2) (Direct Outbound) (Direct Inbound) ( Attr: 0x20 )
1: FREIGHTLOGISTIC freightlogistics.local (NT 5) (Direct Outbound) (Direct Inbound) ( Attr: 0x8 )
2: INLANEFREIGHT INLANEFREIGHT.LOCAL (NT 5) (Forest Tree Root) (Primary Domain) (Native)
```

- `LOGISTICS.INLANEFREIGHT.LOCAL` 是我們網域名稱的子網域，且與 `INLANEFREIGHT.LOCAL` 同 forest（`Forest: 2` 對應 forest tree root 那一行），Attr `0x20` 為 within-forest trust。
- `freightlogistics.local` 的 Attr 是 `0x8`（forest trust），是另一個 forest，不是 child。
- 注意：`Domain.GetCurrentDomain().Children` 沒有輸出任何東西，所以 q2 的答案是由 trust 列表與域名判斷，並沒有被 `.Children` 直接證實。

**q3**：`SecurityIdentifier.Translate` 回傳 `INLANEFREIGHT\rita.grant`。

## 重點整理

- 用 `Get-ADUser` 之類的 cmdlet 遇到 ADWS 錯誤時，可改用 `[adsisearcher]`、`System.DirectoryServices` 或 `nltest`。
- SID 與帳號互查：帳號到 SID 查 `objectSid`，SID 到帳號用 `SecurityIdentifier.Translate`。
- 判斷 child domain 看 `nltest /domain_trusts` 的 `Forest` 欄位與域名是否為本域的子網域。
