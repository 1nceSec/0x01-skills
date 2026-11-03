# JavaScript/Node.js Security Audit Guide

> JavaScript/Node.js 代码安全审计模块
> 适用于: ES5/ES6+, Node.js, TypeScript, Deno

---

# 轨道B: 数据流分析法 (注入类漏洞)

> **核心公式**: Source → [无净化] → Sink = 注入类漏洞

## B1. Node.js Source

```javascript
// Express
req.query.name        // GET参数
req.body.name         // POST body
req.params.id         // 路径参数
req.headers['x-header']
req.cookies.session
req.files             // 文件上传
```

## B2. Node.js Sink

| Sink类型 | 漏洞 | CWE | 危险函数 |
|----------|------|-----|----------|
| 代码执行 | 代码注入 | 94 | eval, Function, vm.run |
| 命令执行 | 命令注入 | 78 | child_process.exec |
| SQL执行 | SQL注入 | 89 | connection.query |
| 文件操作 | 路径遍历 | 22 | fs.readFile, fs.writeFile |
| 原型污染 | 原型污染 | 1321 | Object.assign, _.merge |

## 核心危险面

JavaScript 的动态特性、原型链机制和异步编程模型带来独特的安全挑战。关键攻击面：代码注入、原型污染、ReDoS、路径遍历、不安全反序列化。

---

## 代码注入检测

```javascript
// 高危函数清单
eval(code)                           // 执行任意代码
Function(code)()                     // 动态函数构造
setTimeout(code_string, delay)       // 字符串形式超时回调
setInterval(code_string, delay)      // 字符串形式间隔回调
new Function('return ' + code)()     // 构造函数注入
vm.runInNewContext(code)             // VM模块执行
vm.runInThisContext(code)            // 当前上下文执行
require('child_process').exec(cmd)   // 命令执行

// 审计正则
\beval\s*\(|\bFunction\s*\(|setTimeout\s*\([^,)]*?[\+\`]|setInterval\s*\([^,)]*?[\+\`]
vm\.run|child_process|exec\s*\(|spawn\s*\(

// 漏洞示例
const userCode = req.query.code;
eval(userCode);  // ❌ Critical: 任意代码执行
```
---

## 原型污染检测

```javascript
// 原型污染向量
Object.assign(target, source)        // 递归合并对象
_.merge(target, source)              // Lodash合并
_.mergeWith(target, source)          // 自定义合并
$.extend(true, target, source)       // jQuery深拷贝
hoek.merge(target, source)           // Hoek合并

// 危险属性
__proto__
constructor.prototype
prototype

// 审计正则
(Object\.assign|_\.merge|_\.set|_\.defaults|\$\.extend)\s*\(
__proto__|constructor\.prototype

// 漏洞示例
function merge(target, source) {
    for (let key in source) {
        if (typeof source[key] === 'object') {
            target[key] = merge(target[key] || {}, source[key]);
        } else {
            target[key] = source[key];  // ❌ High: 原型污染
        }
    }
    return target;
}

// 攻击载荷
POST /api/merge
{
  "__proto__": {
    "isAdmin": true,
    "role": "admin"
  }
}
```

---

## 命令注入检测

```javascript
// 高危模块和函数
child_process.exec(cmd)              // Shell执行
child_process.execSync(cmd)          // 同步Shell执行
child_process.spawn(cmd, {shell:true}) // shell=true时危险
child_process.execFile(file, args)   // 文件执行
require('shelljs').exec(cmd)         // ShellJS

// 审计正则
child_process\.(exec|spawn|execSync|execFile|fork)
shelljs.*exec|sh\.exec

// 漏洞示例
const { exec } = require('child_process');
const filename = req.query.file;
exec(`cat ${filename}`, (err, stdout) => {  // ❌ Critical
    res.send(stdout);
});

// 攻击载荷
GET /api/file?file=test.txt;id;whoami
```
---

## 路径遍历检测

```javascript
// 危险操作
fs.readFile(userPath)                // 文件读取
fs.writeFile(userPath)               // 文件写入
fs.createReadStream(userPath)        // 流读取
require(userModule)                  // 动态加载模块
res.sendFile(userPath)               // Express发送文件
res.download(userPath)               // Express下载

// 审计正则
fs\.(readFile|writeFile|readFileSync|createReadStream|createWriteStream|unlink)
res\.(sendFile|download)\s*\(|require\s*\(.*?req\.(query|body|params)

// 漏洞示例
app.get('/download', (req, res) => {
    const file = req.query.file;
    res.sendFile(__dirname + '/files/' + file);  // ❌ High: 路径遍历
});

// 攻击载荷
GET /download?file=../../../etc/passwd
```

---

## 正则表达式拒绝服务 (ReDoS)

```javascript
// 危险正则模式
(a+)+                                // 嵌套量词
(a|a)*                               // 重复的选择
(a|ab)*                              // 重叠选择
(\w+\s?)*                            // 字符类+空格量词

// 审计正则
/\([^)]*[\+\*]\)\+/                  // 检测嵌套量词

// 漏洞示例
const emailRegex = /^([a-zA-Z0-9]+)+@[a-zA-Z0-9]+\.[a-zA-Z]{2,}$/;
if (emailRegex.test(userInput)) {    // ❌ Medium: ReDoS
    // ...
}

// 攻击载荷
"aaaaaaaaaaaaaaaaaaaaaaaaaaaa!"  // 不匹配但导致指数级回溯
```
---

## JSON 注入和反序列化

```javascript
// 不安全反序列化
JSON.parse(userInput)                // 通常安全，但注意原型污染
eval('(' + jsonString + ')')         // ❌ 极度危险
node-serialize.unserialize()         // 可执行代码
cryo.parse()                         // 可还原函数

// 审计正则
eval\s*\(.*JSON|serialize\.unserialize|cryo\.(parse|hydrate)

// 漏洞示例 - node-serialize
const serialize = require('node-serialize');
const userCookie = req.cookies.profile;
const obj = serialize.unserialize(userCookie);  // ❌ Critical

// 攻击载荷
{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('calc')}()"}
```

---

## XSS 检测 (服务端渲染)

```javascript
// 危险的模板引擎配置
// EJS: <%= userInput %> (不转义), <%- userInput %> (原始HTML)
// Pug/Jade: != userInput, div!= userInput (不转义)
// Handlebars: {{{ userInput }}} (三重大括号不转义)

// 审计关键字
res.send|res.write|innerHTML|dangerouslySetInnerHTML
<%=|<%-|!{|{{{

// 漏洞示例
app.get('/greet', (req, res) => {
    const name = req.query.name;
    res.send(`<h1>Hello ${name}</h1>`);  // ❌ High: XSS
});

// React/Vue
<div dangerouslySetInnerHTML={{__html: userInput}} />  // ❌ High
<div v-html="userInput"></div>                          // ❌ High
```

---

## SQL 注入检测 (Node.js ORM)

```javascript
// 危险操作
sequelize.literal(userInput)                              // ❌
sequelize.query(`SELECT * FROM users WHERE id=${id}`)     // ❌
knex.raw(`SELECT * FROM users WHERE name='${name}'`)      // ❌
manager.query(`SELECT * FROM users WHERE id=${id}`)       // ❌ TypeORM

// 审计正则
sequelize\.(literal|query)|knex\.raw|manager\.query.*\$\{

// 漏洞示例
const query = `SELECT * FROM users WHERE id = ${req.query.id}`;
const users = await sequelize.query(query);  // ❌ Critical
```

---

## NoSQL 注入检测 (MongoDB)

```javascript
// 危险操作
db.collection.find(JSON.parse(userInput))         // ❌
db.collection.find({ $where: userCondition })     // ❌
User.find(req.query)                              // ❌ Mongoose直接传递

// 审计正则
\$where|JSON\.parse.*req\.(query|body)|\.find\(req\.(query|body)\)

// 攻击载荷
GET /users?username[$ne]=null&password[$ne]=null  // 绕过认证
GET /users?$where=this.password.length<20         // $where注入
```

---

## SSRF 检测

```javascript
// 危险函数
http.get(url) | https.request(url) | axios.get(url)
fetch(url) | request(url) | got(url)

// 审计正则
(http|https|axios|fetch|request|got)\.(get|post|request)\s*\(.*?req\.(query|body|params)

// 漏洞示例
const url = req.query.url;
const response = await axios.get(url);  // ❌ High: SSRF

// 攻击载荷
GET /fetch?url=http://169.254.169.254/latest/meta-data/  // AWS元数据
GET /fetch?url=http://localhost:6379/                    // 内网Redis
GET /fetch?url=file:///etc/passwd                        // 文件读取
```

---

## JWT 安全检测

```javascript
// 常见漏洞
jwt.verify(token, secret, { algorithms: ['HS256', 'none'] })  // ❌ 允许none算法
jwt.decode(token)                                              // ❌ 不验证签名
jwt.sign(payload, null)                                        // ❌ 空密钥

// 审计正则
jwt\.decode\s*\((?!.*verify)|algorithms.*none|jwt\.sign.*null

// 漏洞示例
const decoded = jwt.decode(token);  // ❌ High: 未验证签名
if (decoded.role === 'admin') { ... }

// 攻击载荷 - none算法绕过
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJyb2xlIjoiYWRtaW4ifQ.

// 硬编码密钥检测
// ❌ const SECRET = 'my-secret-key-123';
```

---

## 开放重定向检测

```javascript
// 危险操作
res.redirect(req.query.url)          // ❌ 直接重定向
res.redirect(301, req.body.next)     // ❌ 用户控制的目标

// 审计正则
res\.redirect\s*\(.*?req\.(query|body|params)

// 攻击载荷
GET /logout?return=https://evil.com/phishing
```

---

## 竞态条件检测

```javascript
// TOCTOU (Time-of-check to Time-of-use)
if (await canWithdraw(user, amount)) {  // Check
    await withdraw(user, amount);        // Use - ❌ 竞态窗口
}

// 漏洞示例 - 余额检查
async function transfer(from, to, amount) {
    const balance = await getBalance(from);
    if (balance >= amount) {            // ❌ 竞态条件
        await deduct(from, amount);
        await credit(to, amount);
    }
}
// 攻击场景：同时发送多个转账请求
```

---

## 敏感信息泄露检测

```javascript
// 危险模式
console.log(req.body.password)       // 日志泄露密码
console.error(err.stack)             // 详细堆栈
res.send(err)                        // 错误对象直接返回
process.env                          // 环境变量泄露

// 审计正则
console\.(log|error|info).*password|res\.(send|json)\(err\)|JSON\.stringify\(process\.env\)
app\.use\(express\.errorHandler\(\)\)
```

---

## 环境变量和硬编码密钥

```javascript
// 审计正则
password\s*[:=]\s*['"][^'"]+['"]|api[_-]?key\s*[:=]\s*['"]
```

---

## package.json 依赖审计

```bash
npm audit
yarn audit

# 常见脆弱依赖
lodash < 4.17.21                     # 原型污染
minimist < 1.2.6                     # 原型污染
node-serialize                       # RCE
js-yaml < 3.13.1                     # 代码执行
handlebars < 4.7.7                   # RCE
express < 4.17.3                     # 开放重定向
jsonwebtoken < 9.0.0                 # 算法混淆

# 审计正则 (在package.json中)
"lodash":\s*"[<^~]?[0-3]\.|"^4\.(0|1[0-6])\."
"minimist":\s*"[<^~]?[01]\."
```

---

## TypeScript 特定安全

```typescript
// 类型断言绕过
const userInput = req.query.data as string;  // ❌ 不安全，可能不是string
executeQuery(userInput);

// any 类型滥用
function process(data: any) {  // ❌ 绕过类型检查
    eval(data.code);
}
```

---

## 搜索模式汇总

```regex
# 代码注入
\beval\s*\(|\bFunction\s*\(|vm\.run.*context|setTimeout.*[\+\`]

# 命令注入
child_process\.(exec|spawn).*shell.*true|exec\s*\(.*\$\{

# 原型污染
__proto__|constructor\.prototype|Object\.assign|_\.merge

# SQL注入
sequelize\.(literal|query).*\$\{|knex\.raw.*\$\{|\.query\(.*\+

# NoSQL注入
\$where|\.find\(req\.(query|body)\)|JSON\.parse.*req\.

# SSRF
(axios|fetch|http|https|request|got)\.(get|post).*req\.

# 路径遍历
res\.(sendFile|download).*req\.|fs\.read.*\+.*req\.|require\(.*req\.

# XSS
res\.send.*\$\{|dangerouslySetInnerHTML|v-html=|<%=.*req\.

# JWT
jwt\.decode\((?!.*verify)|algorithms.*none

# 敏感信息
console\.log.*password|res\.(send|json)\(err\)|\.stack

# 硬编码密钥
password\s*[:=]\s*['"]|api[_-]?key\s*[:=]\s*['"]|secret.*=.*['"][^'"]{8,}
```

---

## 快速审计检查清单

```markdown
[ ] 检查 package.json 已知CVE (npm audit)
[ ] 搜索 eval/Function/vm.run (代码注入)
[ ] 搜索 child_process.exec (命令注入)
[ ] 搜索 __proto__/Object.assign (原型污染)
[ ] 检查 JWT 验证逻辑 (算法、密钥)
[ ] 检查文件操作的路径拼接 (路径遍历)
[ ] 检查 HTTP 请求函数 (SSRF)
[ ] 检查数据库查询的字符串拼接 (注入)
[ ] 检查模板引擎的不转义输出 (XSS)
[ ] 检查重定向目标来源 (开放重定向)
[ ] 检查 .env 文件是否在 .gitignore
[ ] 检查错误处理是否泄露堆栈信息
[ ] 检查正则表达式是否存在 ReDoS
[ ] 检查竞态条件 (余额、库存等)
```

---

## 最小 PoC 示例

```bash
# Prototype Pollution
node -e "const a={}; const b=JSON.parse('{\"__proto__\":{\"polluted\":true}}'); Object.assign(a,b); console.log({}.polluted)"

# SSRF
curl "http://localhost:3000/fetch?url=http://169.254.169.254/latest/meta-data/"

# 路径遍历
curl "http://localhost:3000/download?file=../../etc/passwd"
```

---

## 授权漏洞检测 (Authorization Gap)

> 授权漏洞是"代码缺失"，grep 无法检测"应该有但没有"的代码
> 解决: 从"应该是什么"出发，枚举敏感操作 → 定义应有权限 → 对比实际代码

### Express 授权检测

```bash
# 步骤1: 找到所有敏感路由
grep -rn "\.delete\|\.put\|\.patch" --include="*.js" --include="*.ts"

# 步骤2: 检查路由是否有认证中间件
grep -rn "router\.delete" --include="*.js" -B 2 -A 2 | grep -E "isAuthenticated|requireAuth|passport\.authenticate|verifyToken"

# 步骤3: 检查handler中是否有权限检查
grep -rn "async.*delete\|function.*delete" --include="*.js" -A 20 | grep -E "userId|ownerId|req\.user\.\|checkPermission"
```

### 漏洞模式

```javascript
// ❌ 漏洞: delete 路由缺失认证中间件
router.delete('/files/:id', async (req, res) => {
    await File.findByIdAndDelete(req.params.id);
    res.json({ success: true });
});

// ❌ 漏洞: 有认证但无授权 (水平越权)
router.delete('/files/:id', isAuthenticated, async (req, res) => {
    await File.findByIdAndDelete(req.params.id);  // 可删除他人文件!
    res.json({ success: true });
});
```

### NestJS 授权检测

```bash
# 检查 Controller 的 Guard 配置
grep -rn "@Delete\|@Put\|@Patch" --include="*.ts" -B 5 | grep -E "@UseGuards|@Roles|AuthGuard"

# 检查全局 Guard 配置
grep -rn "APP_GUARD\|useGlobalGuards" --include="*.ts"
```

### 漏洞模式 (NestJS)

```typescript
// ❌ Controller 缺失 Guard
@Controller('files')
export class FileController {
    @Delete(':id')
    async delete(@Param('id') id: string) {
        return this.fileService.delete(id);
    }
}

// ❌ 有 AuthGuard 但无资源所有权验证
@Controller('files')
@UseGuards(AuthGuard('jwt'))
export class FileController {
    @Delete(':id')
    async delete(@Param('id') id: string, @Request() req) {
        return this.fileService.delete(id);  // 未验证所有者
    }
}
```

### Koa 授权检测

```bash
grep -rn "router\.delete\|router\.put\|router\.patch" --include="*.js"
grep -rn "router\.use\|app\.use" --include="*.js" -A 2 | grep -E "auth\|jwt\|session"
```

### 授权一致性检测脚本

```bash
#!/bin/bash
echo "=== JavaScript 授权一致性检测 ==="
ROUTE_FILES=$(find . -name "*.js" -o -name "*.ts" | xargs grep -l "router\.\|@Delete\|@Put" 2>/dev/null)
for routefile in $ROUTE_FILES; do
    echo "检查: $routefile"
    DELETE_ROUTES=$(grep -n "\.delete\s*(" "$routefile" 2>/dev/null)
    if [ -n "$DELETE_ROUTES" ]; then
        echo "$DELETE_ROUTES" | while read line; do
            line_num=$(echo "$line" | cut -d: -f1)
            route=$(echo "$line" | cut -d: -f2-)
            has_auth=$(echo "$route" | grep -c "isAuthenticated\|requireAuth\|verifyToken\|passport")
            if [ "$has_auth" -eq 0 ]; then
                echo "  !! 第${line_num}行: DELETE 路由可能缺少认证中间件"
            fi
        done
    fi
    NEST_DELETES=$(grep -n "@Delete" "$routefile" 2>/dev/null)
    if [ -n "$NEST_DELETES" ]; then
        echo "$NEST_DELETES" | while read line; do
            line_num=$(echo "$line" | cut -d: -f1)
            start=$((line_num - 10)); [ $start -lt 1 ] && start=1
            has_guard=$(sed -n "${start},${line_num}p" "$routefile" | grep -c "@UseGuards\|@Roles")
            if [ "$has_guard" -eq 0 ]; then
                echo "  !! 第${line_num}行: @Delete 可能缺少 @UseGuards"
            fi
        done
    fi
done
```

### 间接SSRF检测 (配置驱动)

```javascript
// ❌ 漏洞: 配置驱动的间接SSRF
const config = { apiBaseUrl: process.env.API_URL || 'http://internal-api' };
async function fetchData(endpoint) {
    const url = config.apiBaseUrl + endpoint;  // 间接SSRF
    return axios.get(url);
}

// 检测命令
grep -rn "process\.env\.\w*URL\|process\.env\.\w*HOST" --include="*.js" --include="*.ts"
grep -rn "config\.\w*[Uu]rl\|config\.\w*[Hh]ost" --include="*.js" --include="*.ts"
grep -rn "\`.*\${.*}.*http\|\`http.*\${" --include="*.js" --include="*.ts"
```

---

## CSRF 检测 (CWE-352)

```javascript
// 🔴 危险: Express 未启用 CSRF 保护
const app = express();
app.use(express.json());
// 缺少 csrf 中间件
app.post('/api/transfer', (req, res) => {
    transferMoney(req.body.to, req.body.amount);
});
```

```bash
# 查找 POST/PUT/DELETE 路由无 CSRF
rg -n "app\.(post|put|delete|patch)\(" --glob "*.{js,ts}" | grep -v "csrf\|CSRF"

# 查找敏感操作
rg -n "transfer|delete|update|create" --glob "*.{js,ts}" | grep "app\.\|router\."
```

---

## 文件上传检测 (CWE-434)

```javascript
// 🔴 无类型验证
const multer = require('multer');
const upload = multer({ dest: 'uploads/' });
app.post('/upload', upload.single('file'), (req, res) => {
    res.json({ filename: req.file.filename });  // 任意文件类型
});

// 🔴 仅前端验证: <input type="file" accept=".jpg,.png"> 可绕过
```

```bash
# 查找 multer 配置
rg -n "multer\(|upload\.(single|array|fields)" --glob "*.{js,ts}"

# 查找缺少 fileFilter 的配置
rg -A10 "multer\(" --glob "*.{js,ts}" | grep -v "fileFilter"
```

---

## 参考资源

- [OWASP NodeGoat](https://github.com/OWASP/NodeGoat)
- [Node.js Security Checklist](https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html)
- [Prototype Pollution Attack](https://portswigger.net/daily-swig/prototype-pollution)
