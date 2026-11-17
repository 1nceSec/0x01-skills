# Worker模板变量注入说明

> 各模式主Agent spawn Worker时，按此表填充 worker-prompt-template.md 中的变量。

## 通用变量（所有模式必填）

| 变量 | 说明 |
|------|------|
| `${WORKER_ID}` | w-{round}-{slot} |
| `${INTENT_DESCRIPTION}` | 本次任务描述 |
| `${TARGET_URL}` | 目标URL/IP |
| `${ATTACK_TYPE}` | 攻击类型标签 |
| `${SPECIFIC_ACTIONS}` | 具体操作步骤 |
| `${STOP_CONDITION}` | 终止条件 |
| `${MAX_STEPS}` | 最大步数 |
| `${SCOPE_NOTES}` | 范围约束 |
| `${CONTEXT_SLICE}` | 黑板切片JSON |
| `${FAILURE_RECORDS_SLICE}` | 已证死路JSON |
| `${KNOWLEDGE_MODULE_CONTENT}` | 知识卡内容 |
| `${REQUEST_HEADERS}` | 从Burp提取的完整请求头基线（Host/Cookie/Token/UA/Accept/Origin/Referer等） |
| `${BLACKBOARD_PATH}` | 工作目录路径 |
| `${CURRENT_ROUND}` | 当前轮次 |
| `${TOOL_CONFIRM}` | 工具确认结果（如"禁止使用Burp MCP"/"禁止使用Playwright"/"Burp+Playwright均可用"，由主Agent根据用户确认填入） |

## 模式专用变量

### 渗透测试 / 漏洞挖掘

```
${MODE_ROLE} = "渗透测试Worker"
${SEND_METHOD} = "用Burp时: curl.exe -sk -x http://127.0.0.1:8080 | 不用Burp时: curl.exe -sk"
${HEADER_RULE} = "以下头每次请求必须携带（Host/Cookie/Token/UA/Accept/Origin/Referer一个不少）"
${MAX_STEPS} = 8

${MODE_RULES} = """
- 可用专项脚本：sqli_detect.py / jwt_forge.py / idor_sweep.py / ssrf_probe.py / ssti_detect.py / path_traverse.py / rce_fuzz.py
- 垃圾洞不报：CORS配置 | 安全头缺失 | 版本指纹 | Self-XSS | SSL警告 | Rate limiting缺失 | 无PoC
"""

${SAFETY_RULES} = "RCE仅回显(whoami/id) | SQLi仅version/库名 | 禁DoS/OOB外带/写真实数据 | 仅测指定目标"

${CHAIN_HINTS} = """
- SSRF确认 → 回连验证地址(src-ssrf.bytedance.net/ssrf)证明能力即停（禁元数据/内网探测）
- IDOR确认 → 证明读取他人数据能力（累计≤5组）即停
- SQLi确认 → 版本/库名即止（禁读表/列/数据、堆叠、写文件）
- JWT弱密钥 → 证明可伪造即停（禁用伪造token访问接口）
- 上传成功 → 证明可访问/可执行即停 → 删验证文件（禁WebShell）
- 信息泄露 → 证明泄露即停；AK/SK类凭证直接提交漏洞，不使用
"""
```

### 红队评估

```
${MODE_ROLE} = "红队执行Worker"
${SEND_METHOD} = "用Burp时: curl -sk -x http://127.0.0.1:8080 | 不用Burp时: curl -sk"
${HEADER_RULE} = "按目标要求携带（内网场景可能无需完整Web头）"
${MAX_STEPS} = 12

${MODE_RULES} = """
- OPSEC意识：能用系统自带工具就不上传第三方工具
- 内网操作优先Living-off-the-Land（net/wmic/powershell/certutil）
- 发现凭证立即写入findings，不在输出中裸露完整密码
- EDR拦截记为L3失败，不自行尝试绕过
"""

${SAFETY_RULES} = "严格遵守ROE | 不实际破坏/删除数据 | 持久化操作需标注（由主Agent确认）| 仅限授权范围"

${CHAIN_HINTS} = """
- 获得管理员权限 → 导出凭证(SAM/NTDS/mimikatz)
- 获得域用户凭证 → Kerberoasting/委派攻击
- 发现内网服务 → 凭证复用(PTH/PTT)
- 发现域环境 → BloodHound/SPN扫描
"""
```

### CTF Benchmark（benchmark-orchestrator专用）

```
${MODE_ROLE} = "CTF解题执行单元"
${SEND_METHOD} = "curl.exe -sk 直连靶场地址（VPN直连，不走代理）"
${HEADER_RULE} = "按靶场要求"
${MAX_STEPS} = 15（easy）/ 25（medium）/ 40（hard）

${MODE_RULES} = """
- 目标是找flag，不需要写报告
- flag格式：flag{...} 或 FLAG{...} 或平台自定义
- 不确定格式时把原始值和包裹值都写入
- 不调benchmark API（start/close/hint/submit）
"""

${SAFETY_RULES} = "仅限靶场环境 | 不对外部目标发请求"

${CHAIN_HINTS} = """
- 常见flag位置：/flag.txt /challenge/flag.txt 环境变量FLAG 数据库flag表
- 多flag题后续flag通常在更深层（内网/Redis/数据库）
"""
```
