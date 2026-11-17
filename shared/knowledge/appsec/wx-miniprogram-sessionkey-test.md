# 微信小程序三要素泄露测试（session_key / iv / encryptedData）

> **适用范围：仅国内**——微信小程序生态（国内 SRC/众测专属攻击面；国外 bug bounty 几乎无此资产形态）。手法本质（会话密钥泄露→凭证伪造）通用，但载体是微信特有。
>
> 进站特征：目标是微信小程序（抓包可见 `jscode2session`/`wx.login` 流程），或返回包/发送包里出现 `session_key` / `encryptedData` / `iv` 字样。配合 HaE 规则高亮，防漏抓——**返回 session_key 的接口域名常与业务接口域名无关**，所有接口的返回都要过一遍。

## 一、原理

微信小程序"手机号快捷登录"无需短信验证：小程序拿 `encryptedData`（密文，含手机号）+ `iv` 送服务端，服务端用 `session_key` 解密。**session_key 本应由服务端保管**；一旦泄露给前端，攻击者可自行构造密文 → 伪造任意手机号 → 任意用户登录。

三要素：
| 要素 | 来源 | 作用 |
|------|------|------|
| `session_key` | `jscode2session` 返回（每用户每次登录会话唯一） | AES 解密密钥 |
| `encryptedData` | 小程序端 `getPhoneNumber` 等 API 产生 | 含手机号的密文 |
| `iv` | 同上 | AES 偏移 |

## 二、泄露点识别

1. **返回包泄露**：登录/换取手机号接口的响应 JSON 直接带 `session_key`（服务端把 wx API 原样转发给了前端）。
2. **发送包泄露**：服务端直接拿 `session_key` 当用户 session 标识传回前端（自造会话 ID 懒得生成）。
3. **真伪鉴别**：多次放包看 `session_key` 是否变化——不变的多是假 key（写死），随登录变化且长度 24 位 base64 的才是真 key。

## 三、利用链

1. 抓快捷登录全程包 → 确认三要素泄露
2. 用泄露的 `session_key + iv + encryptedData` 本地解密，得到明文手机号结构（验证 key 有效）
3. 改明文里的手机号/`purePhoneNumber` 为受害者号码（管理员手机号可从页面"举报/联系方式"、公众号推文、抖音、谷歌语法收集）→ 重新 AES 加密
4. 替换 `encryptedData` 重放登录包 → 任意用户登录；管理员号 → 接管后台
5. 注意：session_key 有时效，重放前先重新走一遍快捷登录拿新 key（key 一定时间内不变，先重放记录）

解密工具：`github.com/mrknow001/wx_sessionkey_decrypt`（输入三要素直接出明文，也可反向加密）。

## 四、小程序其他高频点

| 测点 | 手法 |
|------|------|
| **app.json 路由绕过** | 默认页是登录页且无注册入口 → 反编译（wxappUnpacker/unveilr）读 `app.json` 的 pages 列表，AppID+页面路径直接跳登记页/内部页（听风吧 Tools 快速跳转） |
| **反编译喂给 AI** | 小程序包反编译后把路径给 AI 做接口提取与敏感信息分析（硬编码、隐藏接口、测试账号） |
| 端互换 | 小程序 URL 放 Web 端访问（可能自动跳转其他端）；`h5./app.` 子域逐个试——同系统多端=同洞多交 |
| `wxopen_id`/unionid | 特征识别参数，跨接口匹配做 IDOR/溯源（见 logic-test §十二） |

## 五、判定与上报

- **能证明**：解密脚本输出 + 替换手机号后成功登录受害者账号的完整请求/响应包。
- **只回显 session_key 但无法伪造**（服务端校验 watermark 时间戳/AppID 且 key 已失效）→ 降级为敏感信息泄露报告，注明未走通伪造链。
- 关联：见 `logic-test.md` §六（验证码族）、`idor-test.md`（登录后越权扩面）。
