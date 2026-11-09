# Enumerating AD Trusts — HTB Academy Writeup

## 題目

> Q1: What is the name of the child domain our current domain has a trust with? (case-sensitive)
> Q2: What other forest does the current domain have a trust with? (case-sensitive)
> Q3: What is the trust direction for this trust? (case-sensitive)
> RDP to 10.129.109.212 (ACADEMY-AD-WS01), user `htb-student` / `Academy_student_AD!`

**答案**
- Q1: `LOGISTICS.INLANEFREIGHT.LOCAL`
- Q2: `freightlogistics.local`
- Q3: `Bidirectional`

---

## 連線方式

同前幾題，GUI/RDP client 本機沒有，改用 evil-winrm：

```bash
evil-winrm -i 10.129.109.212 -u htb-student -p 'Academy_student_AD!'
```

```
whoami
inlanefreight\htb-student
```

---

## 枚舉 Trust

### 1. 先用 `nltest`（不依賴 LDAP，直接問本機 netlogon service，不會踩 WinRM double-hop）

```powershell
nltest /domain_trusts
```

```
List of domain trusts:
    0: LOGISTICS LOGISTICS.INLANEFREIGHT.LOCAL (NT 5) (Forest: 2) (Direct Outbound) (Direct Inbound) ( Attr: 0x20 )
    1: FREIGHTLOGISTIC freightlogistics.local (NT 5) (Direct Outbound) (Direct Inbound) ( Attr: 0x8 )
    2: INLANEFREIGHT INLANEFREIGHT.LOCAL (NT 5) (Forest Tree Root) (Primary Domain) (Native)
```

三筆記錄解讀：

| # | 目標 | 關鍵旗標 | 意義 |
|---|---|---|---|
| 0 | `LOGISTICS.INLANEFREIGHT.LOCAL` | `(Forest: 2)` + `Attr: 0x20` (`WITHIN_FOREST`) | 同一個 forest 裡的**子網域** |
| 1 | `freightlogistics.local` | 無 `Forest:` 標記 + `Attr: 0x8` (`FOREST_TRANSITIVE`) | **另一個 forest** 的 forest trust |
| 2 | `INLANEFREIGHT.LOCAL` | `Forest Tree Root` + `Primary Domain` | 自己本身（目前所在網域） |

兩筆跨域 trust 都同時標 `Direct Outbound` + `Direct Inbound` → 方向為 **Bidirectional**。

`Attr` 旗標對照（`msDS-TrustAttributes` bitmask）：
- `0x1` NON_TRANSITIVE
- `0x2` UPLEVEL_ONLY
- `0x4` QUARANTINED_DOMAIN
- `0x8` FOREST_TRANSITIVE
- `0x10` CROSS_ORGANIZATION
- `0x20` WITHIN_FOREST
- `0x40` TREAT_AS_EXTERNAL
- `0x80` USES_RC4_ENCRYPTION

### 2. 用 PowerView 交叉驗證（`TargetName` 可信，`TrustDirection`/`TrustAttributes` 壞掉）

```powershell
Import-Module C:\Tools\PowerView.ps1
Get-DomainTrust | Format-List
```

輸出大量報錯：

```
Cannot convert argument "fileTime", with value: "System.Byte[]", for "FromFileTime" to type "System.Int64" ...
Method invocation failed because [System.Byte[]] does not contain a method named 'op_BitwiseAnd'.
```

```
SourceName      : INLANEFREIGHT.LOCAL
TargetName      : LOGISTICS.INLANEFREIGHT.LOCAL
TrustType       :
TrustAttributes :
TrustDirection  :
WhenCreated     : {50, 48, 50, 48...}
WhenChanged     : {50, 48, 50, 50...}

SourceName      : INLANEFREIGHT.LOCAL
TargetName      : freightlogistics.local
TrustType       :
TrustAttributes :
TrustDirection  :
...
```

**原因**：這台 DC 回傳的 LDAP 屬性型別跟 Windows 原生 AD 不一致（同一套問題在前一題 GPO 枚舉時也出現過）——`whenCreated`/`trustAttributes`/`trustDirection` 這類本該是 Integer/FILETIME 的屬性，被回成 `System.Byte[]`，導致 PowerView 內部 `Convert-LDAPProperty` 的 `[datetime]::FromFileTime(...)` 和 `-band` 位元運算直接拋例外，這幾個欄位因此空白。但不影響字串型欄位 `TargetName`，可拿來跟 `nltest` 的結果互相印證：兩邊 target 名稱完全一致 → `LOGISTICS.INLANEFREIGHT.LOCAL` 與 `freightlogistics.local`，確認大小寫無誤。

---

## 結論

- 子網域（同 forest）：`LOGISTICS.INLANEFREIGHT.LOCAL`
- 另一個 forest：`freightlogistics.local`
- Trust 方向：`Bidirectional`

---

## 學習重點

1. `nltest /domain_trusts` 比 `Get-DomainTrust` 更可靠在這種 LDAP 屬性型別被搞壞的環境下用——它問的是 netlogon RPC，不是 LDAP，不受影響也不會踩 WinRM double-hop。
2. `Forest:` 標記 + `Attr 0x20 (WITHIN_FOREST)` 分辨「子網域」；沒有 `Forest:` 標記但有 `Attr 0x8 (FOREST_TRANSITIVE)` 分辨「外部 forest trust」。
3. 工具輸出裡某幾個欄位空白/報錯時，不要假設資料不存在——先換一個不同實作路徑（這裡是 `nltest` vs `Get-DomainTrust`）交叉驗證，才能判斷是環境 bug 還是真的查無結果。
