# Active Directory PowerView — Skills Assessment Writeup

## 題目

> RDP to 10.129.2.187 (ACADEMY-ADENUM2-MS01), user `htb-student` / `Acad_ad_enum_skillz!`
>
> q1. What is the passwordhistorysize of the domain?
> q2. What is the SID of the user rachel.flemmings?
> q3. What is the domain functional level? (1 single number)
> q4. What GPO is applied to the ENUM2-MS01 host? (case sensitive)
> q5. Find a non-standard share on the ENUM2-DC01 host. Access it and submit the contents of share.txt.
> q6. Find a domain computer with a password in the description field. Submit the password as your answer.
> q7. Who is the group manager of the Citrix Admins group?

**答案**

| # | 答案 |
|---|---|
| q1 | `24` |
| q2 | `S-1-5-21-3394586996-1871716043-2583881113-1105` |
| q3 | `5` |
| q4 | `Disable Defender` |
| q5 | `HTB{r3v1ew_s4ar3_p3Rms!}` |
| q6 | `Just_f0r_adm1n_@cess!` |
| q7 | `poppy.louis` |

---

## 連線：WinRM 被擋，改走真正的 RDP

先照慣例試 evil-winrm：

```bash
evil-winrm -i 10.129.2.187 -u htb-student -p 'Acad_ad_enum_skillz!'
```

```
Error: Cannot establish connection to remote endpoint. Check credentials and network.
Error: WinRM::WinRMAuthorizationError: WinRM::WinRMAuthorizationError
```

換帳密格式（`htb-student@INLANEFREIGHTENUM2.LOCAL`）也一樣。`WinRMAuthorizationError`（不是 AuthenticationError）代表**認證有過，但沒有存取 WinRM 的授權** —— 這台機器刻意不給 `htb-student` WinRM 權限，逼你走 RDP。用 `nxc` 驗證帳密本身沒問題：

```bash
nxc smb 10.129.2.187 -u htb-student -p 'Acad_ad_enum_skillz!'
# [+] INLANEFREIGHTENUM2.LOCAL\htb-student:Acad_ad_enum_skillz!
```

帳密正確、網域是 `INLANEFREIGHTENUM2.LOCAL`，只是 WinRM 這條路被鎖。改用 `xfreerdp3`：

```bash
xfreerdp3 /v:10.129.2.187 /u:htb-student /p:'Acad_ad_enum_skillz!' \
  /d:INLANEFREIGHTENUM2.LOCAL /cert:ignore /size:1280x800
```

連上後用 `xdotool`（滑鼠/鍵盤自動化）+ `import -window root`（截圖）操作這個 RDP 視窗 —— 等於用程式化方式「人工」操作遠端桌面。

---

## 除錯：螢幕座標縮放，踩了兩次

截圖回傳的圖片是縮小過的（原生 2560×1440，顯示給我看的是 2000×1125），縮放係數 **1.28**。第一次踩坑：直接拿「看到的」顯示座標餵給 `xdotool mousemove`，沒有乘回 1.28，導致點擊全部落在錯誤位置——點「設定」視窗的關閉鈕點到空氣、點 PowerShell 主控台邊緣點到別的地方。

症狀：點擊後鍵入的文字沒出現在預期視窗，甚至意外點開了 Windows 設定頁、誤觸 Windows Update 分頁。修法很單純：**所有從截圖判讀的座標，一律先乘 1.28 再丟給 xdotool**。

```bash
# 錯誤：直接用顯示座標
xdotool mousemove 1144 288 click 1   # 沒打中關閉鈕

# 正確：顯示座標 × 1.28 還原成真實螢幕座標
xdotool mousemove 1464 370 click 1   # 1144*1.28, 288*1.28
```

第二個坑：`xdotool key Return`（不指定 `--window`）即使滑鼠點擊視窗內容區，按鍵事件仍可能送不進 FreeRDP 視窗（click-to-focus 在這個 WM 下對 override-redirect 類視窗不可靠）。修法：抓到視窗 ID，顯式 `windowactivate` + `windowfocus`，之後所有 `xdotool type`／`key` 都帶 `--window "$WID"`：

```bash
WID=$(xdotool search --name "FreeRDP" | head -1)
xdotool windowactivate --sync "$WID"
xdotool windowfocus --sync "$WID"
xdotool type --window "$WID" --delay 25 "net accounts /domain"
xdotool key --window "$WID" Return
```

第三個坑：這個遠端鍵盤對應表不完整（連線一開始就有 `no RDP scancode found` 警告），`$` 字元在 `xdotool type` 底下有時會被吃掉（例如 `$c = Get-ADComputer ...` 打出來變成 ` = Get-ADComputer ...`，`$c` 整段消失）。修法：**命令盡量避開 PowerShell 變數賦值，直接用 pipeline**（`Get-ADComputer ... | Select ...` 取代 `$c = Get-ADComputer ...; $c.xxx`），真的需要 `$` 時改用跳脫字元讓 bash 完整保留（例如 `Where-Object {\$_.Description -ne \$null}`）。

---

## q1 — passwordhistorysize

直接問，不需要 LDAP：

```powershell
net accounts /domain
```

```
The request will be processed at a domain controller for domain INLANEFREIGHTENUM2.LOCAL.
...
Length of password history maintained:      24
...
```

**答案：`24`**

---

## q2 — rachel.flemmings 的 SID

此時已在互動式 RDP session（非 WinRM 的 network logon），不會踩前幾題遇過的 double-hop 問題，直接用 RSAT 的 `ActiveDirectory` 模組：

```powershell
Import-Module ActiveDirectory
Get-ADUser rachel.flemmings | Select SID
```

```
SID
---
S-1-5-21-3394586996-1871716043-2583881113-1105
```

**答案：`S-1-5-21-3394586996-1871716043-2583881113-1105`**

---

## q3 — Domain Functional Level

```powershell
(Get-ADDomain).DomainMode
# Windows2012Domain
```

題目要「單一數字」，`DomainMode` 是個 enum，轉成底層整數值才是乾淨答案：

```powershell
(Get-ADDomain).DomainMode.value__
# 5
```

`ADDomainMode` 對照：`Windows2000Domain=0, 2003Interim=1, 2003=2, 2008=3, 2008R2=4, 2012=5, 2012R2=6, 2016=7`。`Windows2012Domain` → **5**。

**答案：`5`**

---

## q4 — ENUM2-MS01 套用的 GPO

### 先試標準做法，踩雷

```powershell
gpresult /r /scope:computer
```

```
ERROR: Access Denied.
```

非管理員權限查不了 Computer Policy 的 RSOP。退而求其次：

```powershell
gpresult /r
```

只印出 `USER SETTINGS`（`Applied Group Policy Objects: N/A`），**完全沒有 `COMPUTER SETTINGS` 區塊**——同樣因為非管理員權限，電腦端策略整段被略過不顯示，不是真的沒套用。

### 改用 LDAP 直接查 gpLink

```powershell
Get-ADComputer ENUM2-MS01 | Select DistinguishedName
# CN=ENUM2-MS01,CN=Computers,DC=INLANEFREIGHTENUM2,DC=LOCAL
```

這台電腦物件**直接躺在預設的 `CN=Computers` 容器裡，不在任何 OU 下**。`CN=Computers` 不是 OU，GPMC 畫面上無法對它連結 GPO——所以唯一可能套用到它的，只有連結在「網域根」的 GPO（網域根連結的 GPO 預設對整個網域所有電腦生效，不管在不在 OU 裡）。

```powershell
(Get-ADObject -Identity (Get-ADDomain).DistinguishedName -Properties gplink).gplink
```

```
[LDAP://cn={DD311E96-1455-445F-BAF5-D49044A7A662},cn=policies,cn=system,DC=INLANEFREIGHTENUM2,DC=LOCAL;0]
[LDAP://cn={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=INLANEFREIGHTENUM2,DC=LOCAL;0]
```

兩個 GUID，解析顯示名稱：

```powershell
Get-ADObject -Filter {objectClass -eq 'groupPolicyContainer'} -Properties displayName,distinguishedName |
  Select displayName,distinguishedName
```

```
displayName                      distinguishedName
-----------                      -----------------
Default Domain Policy            CN={31B2F340-016D-11D2-945F-00C04FB984F9},...
Default Domain Controllers Policy CN={6AC1786C-016F-11D2-945F-00C04FB984F9},...
Disable Defender                 CN={DD311E96-1455-445F-BAF5-D49044A7A662},...
Map User Share                   CN={2FDD0F5B-42C6-4E80-8942-45E0AD050ABB},...
```

`{31B2F340-...}` = Default Domain Policy（固定 GUID，每個網域都有）；`{DD311E96-...}` = **Disable Defender**。後者是非預設、額外連結在網域根的 GPO，就是題目要的答案。

**答案：`Disable Defender`**

---

## q5 — ENUM2-DC01 的非標準 share

```powershell
Get-WmiObject -Class Win32_Share -ComputerName ENUM2-DC01 | Select Name,Path,Description
# 或
net view \\ENUM2-DC01 /all
```

```
Share name  Type  Used as  Comment
--------------------------------------------------------
ADMIN$      Disk           Remote Admin
C$          Disk           Default share
IPC$        IPC            Remote IPC
NETLOGON    Disk           Logon server share
Payroll     Disk           Logon server share
SYSVOL      Disk           Logon server share
```

`ADMIN$ / C$ / IPC$ / NETLOGON / SYSVOL` 都是 Windows 預設 share，**`Payroll` 是唯一非標準的**。讀取內容：

```powershell
dir \\ENUM2-DC01\Payroll
type \\ENUM2-DC01\Payroll\share.txt
```

```
HTB{r3v1ew_s4ar3_p3Rms!}
```

**答案：`HTB{r3v1ew_s4ar3_p3Rms!}`**

---

## q6 — description 欄位裡的密碼

```powershell
Get-ADComputer -Filter * -Properties Description |
  Where-Object {$_.Description -ne $null} |
  Select Name,Description
```

```
Name     Description
----     -----------
JUMP02   ** Jump to Citrix farm ** ctrx_adm:Just_f0r_adm1n_@cess!
```

電腦 `JUMP02` 的 description 裡直接寫死一組帳密。題目只要密碼部分。

**答案：`Just_f0r_adm1n_@cess!`**

---

## q7 — Citrix Admins 的 group manager

```powershell
Get-ADGroup 'Citrix Admins' -Properties ManagedBy | Select ManagedBy
```

```
ManagedBy
---------
CN=poppy.louis,CN=Users,DC=INLANEFREIGHTENUM2,DC=LOCAL
```

```powershell
Get-ADUser poppy.louis -Properties Name,DisplayName | Select Name,DisplayName
```

```
Name          DisplayName
----          -----------
poppy.louis
```

`DisplayName` 沒設定，帳號本身只有 `poppy.louis` 可用。

**答案：`poppy.louis`**

---

## 學習重點

1. **`WinRMAuthorizationError` ≠ 帳密錯**：代表認證成功但沒有 WinRM 存取授權，碰到這個錯誤別浪費時間換帳密格式，先用 `nxc smb` 驗證帳密，再判斷是不是這台機器刻意鎖了 WinRM、逼你走 RDP。
2. **螢幕自動化前先確認座標系統**：截圖顯示給我的尺寸常被縮放過，所有從截圖判讀出的座標都要乘回縮放係數，才是 `xdotool` 該用的真實螢幕座標；點歪了的後果（誤觸其他視窗/應用程式）往往比「沒反應」更難察覺。
3. **點擊不等於拿到鍵盤焦點**：某些視窗（尤其 FreeRDP 這種 override-redirect 視窗）對滑鼠點擊的 focus 處理不可靠，鍵盤事件務必綁定明確的 `--window $WID`，不要只靠「點了應該就有焦點」的假設。
4. **`gpresult` 非管理員權限會整段吃掉 Computer Policy**，不會報錯提示你權限不足，而是直接不印出該區塊，容易誤判成「沒套用任何 GPO」。改用 `gpLink` 屬性配合 `groupPolicyContainer` 的 `displayName` 手動解析，才是可靠做法，尤其當目標電腦物件根本不在任何 OU、GPMC 畫面邏輯對不上時。
5. **電腦物件不一定在 OU 裡**：預設 `CN=Computers` 容器就不能連結 GPO，這種情況下能生效的只有網域根連結的 GPO（和 Site-linked GPO），排查套用的 GPO 時不能只看 OU 結構。
