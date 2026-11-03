# Windows 工作组信息收集

> 非域环境本机侦察。拿到shell后第一轮命令。

## §1 系统基本信息

```
systeminfo                          # OS版本/补丁/架构/启动时间
whoami /all                         # 当前用户+SID+权限+组
hostname                            # 主机名
echo %LOGONSERVER%                  # 返回本机名=工作组，返回\\DC=域
set                                 # 所有环境变量（看PATH/TEMP/USERDOMAIN）
```

## §2 网络信息

```
ipconfig /all                       # IP/DNS/DHCP/网关/MAC
netstat -ano                        # 开放端口+PID（找高端口服务/反连）
arp -a                              # ARP表 → 同网段存活主机
ipconfig /displaydns                # DNS缓存 → 内部域名/访问过的目标
route print                         # 路由表 → 多网卡/内网段
nslookup 127.0.0.1                  # 反查DNS配置
ping -n 1 -a <gateway_ip>          # 网关主机名
```

## §3 用户与共享

```
net user                            # 本地用户列表
net localgroup administrators       # 管理员组成员
net share                           # 共享资源（看C$/ADMIN$/IPC$）
net session                         # 谁连了我（活跃会话）
net use                             # 我连了谁（已建立连接）
cmdkey /list                        # 保存的凭据（RDP/SMB）
```

## §4 进程与服务

```
tasklist /v                         # 进程+用户+窗口标题（找杀软/远控）
tasklist /svc                       # 进程↔服务映射
sc query                            # 所有服务状态
wmic service get name,pathname,startmode | findstr /i "auto"  # 自启服务路径（找Unquoted）
wmic product get name,version       # 安装软件（慢，但全）
```

## §5 防火墙与杀软

```
netsh advfirewall show allprofiles state                     # 防火墙开关
netsh advfirewall firewall show rule name=all dir=in         # 入站规则
wmic /namespace:\\root\securitycenter2 path antivirusproduct get displayname,productstate
# productstate: 397568=启用&最新, 266240=关闭, 393472=启用但过期
```

## §6 敏感文件搜索

```
findstr /si password *.xml *.ini *.txt *.config *.php        # 当前目录递归找密码
dir /s /b C:\Users\*.txt C:\Users\*.ini C:\Users\*.config    # 用户目录敏感文件
dir /s /b C:\inetpub\web.config                              # IIS配置
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall /s | findstr /i "display"  # 注册表软件列表
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s      # PuTTY保存的会话
```

## §7 快速一键收集

```bat
@echo off
systeminfo > %TEMP%\i.txt & whoami /all >> %TEMP%\i.txt & ipconfig /all >> %TEMP%\i.txt
netstat -ano >> %TEMP%\i.txt & arp -a >> %TEMP%\i.txt & net user >> %TEMP%\i.txt
net localgroup administrators >> %TEMP%\i.txt & tasklist /v >> %TEMP%\i.txt
```
