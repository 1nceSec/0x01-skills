---
name: medium-reader
description: Medium 文章读取自动化全流程：URL 进 → 质量门禁（claps/出版物/作者/内容密度评估，不值得读的直接劝退）→ playwright attach 真 Chrome 读取（CF 质询自动决策）→ 结构化提取 → 清洗 → translate skill 精准翻译 → 按 RedTeamNotes 规范入库。用户给 Medium 等链接要求"读取/翻译/入库"时使用；不预设关键词找文，文章来源由用户或上层任务决定。
---

# Medium 文章读取自动化（读→译→入库一条龙）

## 触发与输入

- 单篇：一个文章 URL（medium.com 或出版物域名）+ 可选意图词（仅读/翻译/入库）
- 批量：URL 列表（建议 ≤6 篇/批，防风控）
- 全程授权阅读，仅读取公开/已登录可见内容

## 通道纪律（硬规则，违反即翻车）

1. **只走 playwright-cli attach 用户真 Chrome**：token 从凭证库读——先读 `E:\Agent\credentials.md` 拿 PLAYWRIGHT_MCP_EXTENSION_TOKEN，再 attach。token 失效时先确认 Chrome 开着，确认要轮换则**更新凭证库文件**（不问第二遍）
2. **禁止** jsreverser CDP 浏览器、browser-use 插件访问 Medium（污染 CF 风控评分）
3. webReader / WebFetch / curl 均不可用（服务端无登录态被 307 身份门禁弹回；curl 无代理网络层超时）——不要浪费时间重试
4. 需要任何凭证（token/cookie）一律先查 `E:\Agent\credentials.md`；用户给了新凭证也写回该文件

## 执行流程

### ⓪ 质量门禁（先判值不值得读，再花成本读）

文章来源不限（用户直接给、任意渠道发现的候选）——**不做关键词搜索，只做质量评估**。

硬信号（attach 后一并在页面上下文取，或从已加载页面 HTML 提取）：
```bash
# claps + 发布时间 + 作者，从页面 HTML 的 apollo state 里抓
playwright-cli -s=chrome --raw eval "(() => { const h = document.documentElement.outerHTML; return JSON.stringify({ claps: (h.match(/\"totalClapCount\":(\d+)/) || h.match(/\"clapCount\":(\d+)/) || ['?'])[1], pub: ((document.querySelector('meta[property=\"article:published_time\"]') || {}).content || '').slice(0,10), author: (document.querySelector('meta[name=\"author\"]') || {}).content || '', artLen: document.querySelector('article') ? document.querySelector('article').innerText.length : 0, codeBlocks: document.querySelectorAll('article pre, article code').length }); })()"
```

判定权重（综合评分，不是单指标门槛）：
| 信号 | 高质量特征 | 低质量特征 |
|---|---|---|
| claps | 老文 ≥500 强；**新文（当年）≥20 即有参考价值**——新文 claps 天然低，勿一刀切 | 挂 0 且发帖 >1 月 |
| 出版物 | InfoSec Write-ups 等头部出版物、知名博客（Very Lazy Tech 类） | 无出版物个人零散帖（需其他信号补强） |
| 作者 | H1/BC 研究员、知名猎人（如 Hakluke 2.7K claps 级）、方法论系列作者 | 无履历可查的营销号/AI 生成痕迹 |
| 内容密度 | artLen >8K + codeBlocks >5（方法论/工具链） | <3K 纯观点文（鸡汤/套路文直接劝退） |
| 原创性 | 自有方法论、实测数据、踩坑记录 | 转述工具文档、内容农场式罗列 |

**结论输出**：读（全流程）/ 跳过（说明哪项不合格）/ 存疑（列理由给用户定夺）。
质量不过关的文章明确告知用户并说明依据，不默默丢弃。

### ① 连接与打开

```bash
playwright-cli -s=chrome tab-new "<URL>"
sleep 8
```

**慢一页陷阱**：`goto`/`tab-new` 在 domcontentloaded 即返回，Medium 正文异步渲染——
紧随其后的 eval 拿到的可能是**上一页**。所以每页操作前必须先验 title：

```bash
playwright-cli -s=chrome --raw eval "document.title.slice(0,50)"
```

title 是文章标题才算就绪；批量循环中提取文件要按**实际 H1 内容**归位文件名，不信循环变量。

### ② CF 质询决策树（title 含"请稍候/Just a moment"时）

```
质询 → A. 文章在出版物自定义域名？（最快，优先）
        证据：goto 后最终 URL 的 host 不是 medium.com / 文章链接从 bugbountywriteup 重定向
        已知域名：osintteam.blog、infosecwriteups.com、meetcyber.net
        未知域名发现法：WebSearch 搜「文章标题 + site:」或直接打开 medium.com 链接观察重定向
        → 直读，零质询
   B. 等 15 秒再验 title（部分站自动过；出版物域名重启后也常直接过）
   C. 仍卡死 → 请用户重启 Chrome（风控标记随浏览器会话清零，实测 100% 恢复）→ 重新 attach
```

member-only 付费墙：登录态来自用户原生 Chrome 的 Google 账号 OAuth（httpOnly，document.cookie 看不见）。
侧边栏出现 Stories/Stats/Following 即已登录，正常提取即可；未登录则提示用户在原生 Chrome 里
重新用 Google 登录 Medium（不要走 cookie 注入；细节见 `E:\Agent\credentials.md` Medium 节）。
cf_clearance 注入无意义（指纹绑定），别试。

### ③ 提取（验证过的模板，直接用）

```bash
playwright-cli -s=chrome --raw eval "(() => { const a = document.querySelector('article'); if (!a) return 'NO'; const parts = []; for (const el of a.querySelectorAll('h1,h2,h3,h4,p,pre,li,blockquote,figcaption')) { const t = el.innerText.trim(); if (!t) continue; const tag = el.tagName.toLowerCase(); if (tag === 'p' && el.closest('li')) continue; if (tag === 'h1') parts.push('# ' + t); else if (tag === 'h2') parts.push('## ' + t); else if (tag === 'h3') parts.push('### ' + t); else if (tag === 'h4') parts.push('#### ' + t); else if (tag === 'pre') parts.push('\`\`\`\n' + t + '\n\`\`\`'); else if (tag === 'li') parts.push('- ' + t); else if (tag === 'blockquote') parts.push('> ' + t); else if (tag === 'figcaption') parts.push('*' + t + '*'); else parts.push(t); parts.push(''); } return parts.join('\n'); })()" > <名>-raw.md
```

完整性判据：结尾是作者签名/参考资料而非截断段落；无 "Upgrade to continue" 等付费墙文案。

### ④ 清洗（node 内联，处理 CLI 的 JSON 转义输出）

```bash
node -e "const fs=require('fs');let r=fs.readFileSync('<名>-raw.md','utf8').trim();let t=r.startsWith('\"')?JSON.parse(r):r;let prev=null;const o=[];for(let l of t.split('\n')){l=l.trim();const b=l.replace(/^[#>\-*\s]+/,'').trim();if(!b){o.push('');continue}if(['Listen','Share','More','Top highlight','Member-only story','--'].includes(l))continue;if(/^\d+(\.\d+)?K?$/.test(l))continue;if(b===prev)continue;o.push(l);prev=b}fs.writeFileSync('<名>.md',o.join('\n').replace(/\n{3,}/g,'\n\n').trim()+'\n')"
```

产物：工作区 `<名>.md`（英文源，留存备查，重跑翻译时直接喂它不再开浏览器）。

### ⑤ 翻译（translate skill 规则）

调用 `/translate`（或按其规则直译）：代码块/命令/路径/URL 逐字不动；安全术语（IDOR/SSRF/
subdomain takeover/recon 等）不译；不增不减；自然中文重构语序。

### ⑥ 入库（RedTeamNotes 规范）

目标库：`E:\RedTeamNotes\漏洞挖掘笔记\`，目录按主题（信息搜集系列/越权/工具相关…）。

笔记骨架（必须逐项对齐同系列已有笔记）：
```
# 中文全称标题（保留原文完整语义）

```url
详细文章可参考：
[原英文标题](原文URL)
```

**tags:** #主题标签 #副标签

---

<翻译正文>

---

### 补充：xxx（笔记补充，原文没有）   ← 可选，必须标注
```

硬性规则：
- **文件名 = H1 的概括版**（去修饰留核心概念；如 H1"一条脚本自动化整个 Bug Bounty 侦察流程"→ 文件"自动化侦察流水线.md"）
- **双链 [[...]] 只链真实存在的 .md**——入库前 `ls` 同目录核对文件名
- **国内外 SRC 分线标注**：信息收集类内容必须声明属国外线（bug bounty）还是国内线（企查查/备案/Quake 体系），对照时两列分清
- 信息搜集类放 `信息搜集系列/`

### ⑦ 收尾

- 关掉质询残留标签页，`playwright-cli -s=chrome detach`（不动用户其他标签）
- 交付：英文源文件路径 + 笔记绝对路径 + 建立的双链清单

## 环境生存法则（全部实测踩坑）

1. medium.com 主站风控按浏览器会话记，**重启 Chrome = 清零**；出版物自定义域名永远免质询
2. 批量读取每篇间隔 ≥8s；一批 ≤6 篇；连读失败即停（保护账号不被加重评分）
3. Chrome 开了自动翻译（标题会显示中文/乱码），无害，按内容 H1 判断即可
4. 会话可能中途断（Chrome 重启/扩展掉线）：报 "not open" 时重新 attach，不要重开浏览器
5. Excel/长任务落盘同理：提取一个存一个，别攒

## 完成后交付

英文源 + 中文笔记双路径、每篇的质询处理记录（走了决策树哪个分支）、
新增双链列表、失败篇目及原因（供下批重试）。
