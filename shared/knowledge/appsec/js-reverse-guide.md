# JS 逆向配合接口挖掘指南

> 进站强制步骤见 `dig-scope` §4.1：**不只抽 `/api/` path**。盐、密文 id 公钥、hidden/admin 路由、写死的演示号有就进清单，没有写「无」。演示号当钥匙，不是登录框字典。
>
> 2026-11-14 整合自 `audit/js-reverse` + `utils/jsreverser-playbook`（jsreverser-mcp 已移除）。本文工具无关：浏览器侧用 DevTools 手动操作或 `playwright-cli attach` 接管本地浏览器，脚本侧用 curl + grep + Node。

## 使用场景 / 触发词

JS逆向 / 前端加密 / 加密参数 / sign参数 / signature / 签名算法 / 参数加密 / hook函数 / 反调试 / webpack逆向 / 混淆还原 / 补环境

- 页面接口有加密参数，无法直接用 curl 重放
- 需要从前端 JS 发现隐藏 API 接口
- 需要了解签名/token 生成逻辑以构造任意请求
- 路由表里 hidden/admin、webpack 异步 chunk、写死演示号/测试租户

---

## 方法论总纲

### 六原则

- **Observe-first**：先页面观察，再最小化采样，不要跳过取证直接猜环境
- **Hook-preferred**：优先函数 Hook / 日志采样，断点只做兜底（断点暂停期间页面不可交互，完成分析及时恢复）
- **Breakpoint-last**：Hook 无法解释关键上下文时才进断点路径
- **Rebuild-oriented**：一切取证为了本地 Node 复现跑通参数链路
- **Evidence-first**：每个结论都有运行时证据支撑，没有证据不下补丁
- **Task-driven**：先锁定目标（哪个请求、哪个字段、哪个函数），再动手

### 五阶段骨架（Observe → Capture → Rebuild → Patch → DeepDive）

1. **Observe 页面观察**：确认目标请求、相关脚本、候选函数。必须产出：目标请求、initiator/调用栈线索、可疑脚本 URL、记录文档。不猜环境。
2. **Capture 运行时采样**：对目标请求做最小侵入采样（fetch/XHR hook、Console 重放、断点一次），拿到参数样例、调用顺序、运行时证据。目标在首屏初始化/首个请求前生成时，优先在页面加载前挂采样（preload 思路：DevTools 的 Event Listener Breakpoints / playwright-cli inject init script）。
3. **Rebuild 本地复现**：把页面证据导出为本地 Node 工程（`env/entry.js` + `env/env.js` + `env/polyfills.js` + `env/capture.json`），本地补环境必须以页面观测证据为依据，不允许空想式补 `window/document/navigator/crypto/storage`。
4. **Patch 补环境迭代**：按代理日志 + `first divergence`（首个差异点）驱动补丁，直到本地稳定跑出目标参数（详见流程五）。
5. **DeepDive 深挖**：本地跑通后再做 AST 去混淆、VMP 插桩、逻辑提纯。只是出签名可降级此阶段；要长期复用算法链路则必做。

### 任务输入清单（开工前收集齐）

- 目标 URL、目标接口关键字、目标字段、目标函数名（若已知）
- 触发动作描述（点什么/输入什么会发出目标请求）
- 是否涉及首屏初始化 / 首次请求前逻辑
- 登录要求、成功判定标准、目标时间窗
- 超时与重试策略、是否允许补环境/断点

### 搜索关键词优先级表

| 优先级 | 搜索词 | 目标 |
|--------|--------|------|
| P0 | `sign`/`signature`/`encrypt`/`decode` | 签名/加密函数 |
| P0 | `token`/`nonce`/`timestamp` | 动态参数生成 |
| P1 | `XMLHttpRequest`/`fetch`/`axios` | 请求发送入口 |
| P1 | `JSON.stringify`/`JSON.parse` | 数据序列化 |
| P2 | `btoa`/`atob`/`Base64`/`MD5`/`SHA`/`AES`/`RSA` | 编码/加密算法 |
| P2 | `CryptoJS`/`JSEncrypt`/`forge` | 加密库 |
| P3 | `Object.defineProperty`/`Proxy` | 环境检测/反调试 |
| P3 | `debugger`/`setInterval`/`constructor` | 反调试手段 |

grep 默认串：`sign|token|nonce|encrypt|hmac|sha|md5|cookie|h5st`

---

## 流程一：接口发现

### 1. 查看网络请求

DevTools Network 面板（或 playwright-cli attach 后截图/取 HAR）：

```
筛选: Fetch/XHR
关注: 含用户数据的接口（/user/, /api/, /order/, /account/）
导出: Network 面板右键 Save all as HAR（含请求头/参数/时序，供后续分析）
```

### 2. 从 JS 源码批量提取接口

DevTools Console 提取页面脚本清单：

```javascript
Array.from(document.querySelectorAll('script[src]')).map(s => s.src)
```

```bash
# 下载所有 JS 文件，grep 接口路径
for url in $(cat js_files.txt); do
  curl -s "$url" | grep -oP '"(/api/[^"]+)"' | tr -d '"'
done | sort -u > discovered_apis.txt

# 关键词搜索
grep -E "(userId|uid|token|sign|order|payment)" discovered_apis.txt
```

### 3. 跨脚本搜索

```bash
# 下载全部脚本后本地全文检索（等价于跨源搜索）
mkdir js_dump && cd js_dump
while read url; do curl -s "$url" -o "$(basename "$url")"; done < ../js_files.txt
grep -rn "userId" .          # 找用户ID相关接口
grep -rn '"/api/' .          # 找所有 API 路径
grep -rn "Authorization" .   # 找 token 设置位置
grep -rn "signature" .       # 找签名参数
```

---

## 流程二：加密参数分析

适用于请求中有 `sign`/`_token`/`x-sign` 等加密参数。

### Step 1: XHR 断点定位（DevTools 手动路径）

```
1. DevTools → Sources → 右侧 XHR/fetch Breakpoints → Add breakpoint → 填接口路径子串（如 /api/target-endpoint）
2. 在页面触发对应操作，执行暂停
3. 右侧 Call Stack 面板查看调用栈，自上而下找设置加密参数的业务函数帧
4. 点击栈帧跳转源码；注意区分框架代码（axios/saga）与业务代码（utils.js/api.js）
```

### Step 2: 分析调用栈

```
Call Stack 示例:
  Frame 0: setRequestHeader (XMLHttpRequest)
  Frame 1: signRequest (utils.js:342)     ← 关注这里
  Frame 2: sendApiRequest (api.js:89)
  Frame 3: onClick (page.js:234)
```

定位到业务帧（如 Frame 1），在 Sources 面板读源码，必要时对该函数下普通断点重触发，看入参。

### Step 3: 提取签名逻辑

常见签名算法模式：

```javascript
// 模式 1: 参数排序 + MD5
function signRequest(params) {
  const sorted = Object.keys(params).sort().map(k => `${k}=${params[k]}`).join('&');
  return md5(sorted + SECRET_KEY);
}

// 模式 2: timestamp + nonce + HMAC
function sign(data) {
  const ts = Date.now();
  const nonce = Math.random().toString(36).substr(2);
  return hmacSha256(ts + nonce + JSON.stringify(data), APP_SECRET);
}

// 模式 3: 固定 salt 拼接
const sign = md5(userId + ':' + timestamp + ':' + SALT);
```

### Step 4: 在浏览器中执行签名函数

```javascript
// DevTools Console 直接调用页面内的签名函数
window.signRequest({userId: "victim_id", action: "getInfo"})

// 函数在模块作用域时：在断点暂停于该作用域内，Console 此时可访问局部变量直接调用
```

### Step 5: Python 复现签名

```python
import hashlib
import hmac
import time
import random
import string

# MD5 签名复现
def sign_request(params: dict, secret_key: str) -> str:
    sorted_str = '&'.join(f"{k}={params[k]}" for k in sorted(params.keys()))
    return hashlib.md5((sorted_str + secret_key).encode()).hexdigest()

# HMAC-SHA256 签名复现
def sign_hmac(data: str, app_secret: str) -> str:
    ts = str(int(time.time() * 1000))
    nonce = ''.join(random.choices(string.ascii_lowercase, k=8))
    msg = ts + nonce + data
    return hmac.new(app_secret.encode(), msg.encode(), hashlib.sha256).hexdigest()

# 验证：Python 结果应与浏览器 JS 执行结果一致
```

---

## 流程三：隐藏接口发现

### 从 Webpack chunk 中提取

```bash
# 找 chunk 文件
curl -s "https://target.com" | grep -oP 'chunk\.[a-z0-9]+\.js'

# 下载所有 chunk
for chunk in $(curl -s "https://target.com" | grep -oP '"/static/js/[^"]+\.js"' | tr -d '"'); do
  curl -s "https://target.com$chunk" >> all_js.txt
done

# 提取路径
grep -oP '"(/[a-z]+){1,5}"' all_js.txt | sort -u | grep -v node_modules
```

### 从路由配置提取

```bash
# Vue/React 路由配置
grep -oP 'path:\s*["\x27][^"'\'']+' all_js.txt
grep -oP '"route":\s*["\x27][^"'\'']+' all_js.txt

# Axios 基础 URL
grep -oP 'baseURL:\s*["\x27][^"'\'']+' all_js.txt
grep -oP 'BASE_API\s*=\s*["\x27][^"'\'']+' all_js.txt
```

---

## 流程四：API 参数枚举

发现接口后，枚举参数找越权/注入点：

```python
import requests

# 对发现的接口逐个测试
discovered_apis = [
    "/api/v1/user/info",
    "/api/v1/order/list",
    "/api/v2/account/profile",
]

session = requests.Session()
session.headers.update({"Authorization": "Bearer YOUR_TOKEN"})

for api in discovered_apis:
    r = session.get(f"https://target.com{api}")
    print(f"[{r.status_code}] {api} - {len(r.text)} bytes")
    if r.status_code == 200:
        # 记录响应中的 ID 字段，用于后续越权测试
        data = r.json()
        print(f"  响应字段: {list(data.keys()) if isinstance(data, dict) else 'array'}")
```

---

## 流程五：Node 补环境（签名/加密本地复现）

本地复现的默认目标**不是「完全模拟浏览器」，而是「先跑通目标参数链路」**。

### 扣包纪律

- 扣**最小函数依赖**，不整包搬运
- 每轮只补 **1 个缺失点**并重跑
- **超过 6 个补丁未收敛则停止**，回浏览器取证

### 补环境循环（first divergence 驱动）

```
1. 在页面里确认目标请求、脚本、函数（流程一/二）
2. 抠出入口函数与其依赖树，落成 env/entry.js
3. Node 运行 env/entry.js，优先读代理 env log（见下）
4. 记录当前 first divergence（首个与浏览器行为不一致的点）
5. 按「最小因果单元」做一个补丁决策
6. 复跑并确认 first divergence 是否前移
7. 补丁写回记录文档；循环 3-6 直到稳定跑出目标参数
```

### 最小因果单元

- 一次只做一个补丁决策；该决策对应一个最小因果单元：**值 / 函数壳 / 返回对象 / 最小对象契约**
- 静态 diff 工具/人工比对仅作辅助，不替代代理日志
- 每次补丁都要可回滚、可复测、可追溯到页面证据
- 没有代理日志或没有 first divergence 记录时，**不允许直接补宿主**

### 代理 env log（补环境的依据）

给 `entry.js` 里挂一层 Proxy 记录属性访问链：谁在读、何时读、读了什么——这是定位缺口的主证据，禁止凭空脑补。

```javascript
// env/env.js 骨架：代理日志 + 最小因果单元
function tracked(obj, name, log) {
  return new Proxy(obj, {
    get(t, k) { log.push(`${name}.${String(k)} <- read`); return t[k]; },
    has(t, k) { log.push(`${name}.${String(k)} <- has`); return k in t; }
  });
}
const envLog = [];
globalThis.window = tracked(globalThis, 'window', envLog);
// 首轮跑完打印 envLog，第一个未定义/行为不一致的访问就是 first divergence
```

### 优先补的宿主对象（按命中频率）

`window` → `document` → `navigator`（含 `webdriver`）→ `location` → `localStorage/sessionStorage` → `crypto` → `atob/btoa`/`TextEncoder` → `fetch/XMLHttpRequest`

### 产物结构（跨会话续做对齐用）

```
artifacts/<task>/
  entry.js        # 入口：从目标脚本抠出的调用链
  env.js          # 补环境：代理日志 + 补丁
  polyfills.js    # 纯函数填充（不碰业务逻辑）
  capture.json    # 页面侧采样的输入/输出基准
  notes.md        # 每轮补丁决策 + first divergence 轨迹
```

---

## 流程六：AST 去混淆

### 目标

- 把混淆代码拆成「可读语义块」，不追求一次性还原成最终源码
- 每一步静态改写都能在运行时对齐行为（输出可验证证据）

### 适用场景

- 字符串表 + 索引函数（`_0x***`）
- 平坦控制流（`while(true)+switch`）
- 花指令（永真/永假分支、死代码）
- IIFE 包裹 + 多层代理调用

### 流程（固定 pass 顺序：常量传播 → 字符串表替换 → 控制流还原 → 死代码清理）

1. **预扫描**：统计 AST 指标（节点数、函数数、字面量比例、`eval/new Function` 次数）；标记高风险节点（动态执行、反调试、环境探针）
2. **字符串层去混淆**：定位字符串表与解码函数；只做「可证明等价」的替换（仅静态可求值表达式）；记录替换统计（数量/失败数/失败样本）
3. **代理层折叠**：识别代理函数（简单转发、参数重排、常量包裹）；可内联的折叠为直接调用；不可判定的保留，避免误改业务逻辑
4. **控制流还原**：处理 `while-switch` 平坦化，按 dispatch 序列重建语句顺序；删除不可达分支前先跑一次覆盖验证
5. **死代码清理**：清理未引用声明、永假分支、无副作用表达式；每次清理后执行语义对比（最小样本）
6. **运行时回验**：对核心函数做输入输出回放（原始输出 vs 改写后输出），不一致则回滚最近变换

### 验证口径

- 结构指标下降：节点数↓、嵌套深度↓、动态执行点↓
- 语义指标稳定：关键函数 I/O 一致；涉及签名时关键请求参数一致

### 常见失败与回退

- 字符串解码依赖运行时状态 → 回退「运行时采样 + 局部替换」，不全量静态替换
- 控制流恢复后行为漂移 → 仅恢复目标函数，缩小改写面
- 清理死代码后崩溃 → 保留可疑副作用节点，分批删除

### 产物

`before.js` / `after.stepN.js`、`transform-log.json`（每步统计）、`verify-report.md`（I/O 对比）

---

## 流程七：window 蜜罐对抗（环境检测绕过）

识别页面对 `window`/`document`/`navigator` 的探针访问路径，在不破坏业务主流程的前提下做最小补丁通过检测。

### 常见蜜罐类型

- 存在性探针：`if (window.chrome && window.chrome.runtime)`
- 描述符探针：`Object.getOwnPropertyDescriptor(...)`
- 原型链探针：`instanceof`、`constructor.name`
- 一致性探针：`innerWidth/outerWidth/screen` 联动校验
- 行为探针：函数 `toString`、错误栈、调用时序

### 流程

1. **观测优先**：用 Proxy/getter hook 记录属性访问链（谁在读、何时读、读了什么）；先收集失败样本，再决定补丁点
2. **分组定位**：按探针类别分组（存在性/描述符/原型链/行为），每组只选最早触发点作为 first divergence
3. **单字段补丁**：每次只补一个字段或一个描述符；补丁后立刻复测确认影响面
4. **回归验证**：检测通过 + 目标业务请求未回归（参数与状态码正常）

### 补丁策略

- 优先「返回真实分布值」，避免硬编码魔法常量
- 优先「只读补丁」，尽量不改写业务函数
- 仅在必要时注入 preload 脚本（页面加载前），避免时序丢失

### 失败回退

- 补丁触发新探针 → 回滚最近补丁，改走更早触发点
- 行为不一致 → 检查 `toString`、`name`、`length` 描述符是否露馅

---

## 流程八：签名算法 Node 复现模板（站点无关）

> 两层能力模型：本模板是**通用能力层**（固定流程与输入契约）；站点字段映射、风险点、验签口径放**站点能力层**（单独 case 文件），不绑定特定域名。

### 输入契约（最小）

- `target.script_url`：目标签名脚本 URL
- `target.sign_entry`：入口函数或类名（如 `sign`、`ParamsSignMain`）
- `target.request_spec`：验签请求模板（URL、query/body、headers）
- `runtime.seed`：会话种子（cookie/localStorage/sessionStorage），可为空
- `runtime.clock`：固定时间戳策略（可选）

### 标准流程

1. **Observe**：确定签名字段、入口调用点、请求触发时机
2. **Capture**：采集最小种子——仅保留签名必要字段，严禁全量敏感导出
3. **Rebuild**：Node `vm` 补最小浏览器能力（`window/document/navigator/storage/canvas`）；先用代理 env log 定位缺口，再按 first divergence 约束补丁边界；**不暴露 `process` 等 Node 特征到 `vm`**
4. **Verify**：生成签名后立即发一次验签请求（闭环），以服务端响应为最终判据
5. **Harden**：按「最小因果单元补丁」迭代，记录 first divergence 轨迹

### 输出字段

`signature_parts_count`、`signature_key_part_len`（指纹段长度）、`verify_status`、`verify_body_preview`、`first_divergence_note`

---

## 失败回退速查

- Hook 无数据：确认动作执行 → 扩一档范围 → 仍失败则停，不要直接猜 local rebuild
- 错过首屏初始化：回到页面入口，在加载前挂采样（preload 思路）再重试
- 数据过多：先看汇总去噪，再单条下钻原始记录
- 补环境失败：先读代理 env log，确认当前 first divergence，再回看页面证据；静态比对仅辅助
- local rebuild 连续两轮无进展：回到页面观察，补采证据后再继续
- 断点不稳：回退 Hook 路径

## VMP 插桩原则

- Hook-first，Breakpoint-last
- VMP 首轮最小采样：opcode、ip/pc、栈顶摘要、关键寄存器摘要、输出摘要
- **禁止首轮全量状态采样**

---

## 输出契约与格式

逆向结论必须包含：

- 目标接口与字段
- 函数路径（脚本:行号）
- 运行时证据（采样记录 + 请求关联）
- 输入输出样例
- 补丁与回滚步骤
- 置信度与不确定性
- 本地补环境状态（已补/未补）

标准格式模板：

```
## 目标参数：{参数名}
生成位置：{脚本文件}:{行号}
调用链：{函数A} → {函数B} → {函数C}
算法类型：{HMAC-SHA256/AES-CBC/RSA/自定义}
输入依赖：{timestamp, cookie, body}
采样结果：
  - 输入：{...}
  - 输出：{...}
复现代码（可直接用于 replay.py / curl）：
  - Python: ...
```

与 Burp 联动（SRC 漏洞挖掘场景）：定位加密/签名逻辑 → 理解参数生成算法 → 构造绕过 Payload → 通过 Burp 代理发送验证。

## 安全红线

- 不在文档中写入可直接批量复用的站点特定 payload
- 不提交真实 cookie/token/storage 原文或包含真实凭证的样本输入
- 文档中只保留字段名、流程、阈值与判定标准
