# Laravel Security Audit Guide

> Laravel Framework 安全审计模块
> 适用于: Laravel 8.x/9.x/10.x/11.x

## Mass Assignment 漏洞检测

```php
// 危险操作
User::create($request->all());              // High: 批量赋值攻击
$user->fill($request->input());             // High
$user->update($request->only(['name']));    // 如果未正确配置

// 审计正则
::create\s*\(\s*\$request->all\(\)|->fill\s*\(\s*\$request->|->update\s*\(\s*\$request->

// 漏洞示例
public function updateProfile(Request $request) {
    $user = Auth::user();
    $user->update($request->all());  // Critical: 可修改任意字段
    return redirect('/profile');
}

// 攻击载荷
POST /profile
{
  "name": "Attacker",
  "is_admin": true,       // 提权
  "role": "admin",
  "credits": 999999
}
```

---

## SQL 注入检测

```php
// 危险操作 - Raw Queries
DB::select("SELECT * FROM users WHERE id = " . $id);  // Critical
DB::statement("DELETE FROM users WHERE role = '$role'");

// 危险操作 - Query Builder
DB::table('users')->whereRaw("name = '$name'")->get();
User::whereRaw("email = '$email'")->first();

// 危险操作 - orderByRaw / groupByRaw
User::orderByRaw($request->input('sort'))->get();

// 审计正则
DB::(select|statement|raw|delete|update|insert)\s*\(.*\$|whereRaw.*\$|orderByRaw.*\$
havingRaw|groupByRaw

// 攻击载荷
GET /search?keyword=' OR '1'='1
GET /search?keyword='; DROP TABLE users--
```

---

## Laravel 反序列化 RCE

```php
// 危险操作
unserialize($request->cookie('user'));      // Critical: 反序列化用户输入
unserialize(base64_decode($data));          // Critical
unserialize(file_get_contents($path));      // 如果路径可控

// Laravel 特有的反序列化链
// APP_KEY 泄露 -> 伪造加密Cookie -> RCE

// 审计正则
unserialize\s*\(|APP_KEY\s*=|Illuminate\\.*__destruct

// 漏洞场景1: APP_KEY 泄露
// .env 文件泄露
APP_KEY=base64:YourSecretKeyHere  // 如果泄露可伪造签名

// 检查点
- .env 是否在 .gitignore
- 是否在公开仓库中
- debug 模式是否泄露
- /.env HTTP 访问是否被拦截

// Laravel POP链示例 (CVE-2021-3129)
- Illuminate\Broadcasting\PendingBroadcast::__destruct()
- Illuminate\Events\Dispatcher::dispatch()
- Illuminate\Bus\Dispatcher::dispatchNow()
- Illuminate\Foundation\Application::call()
```

---

## Blade 模板注入 (SSTI)

```php
// 危险操作
{!! $userInput !!}                           // High: 不转义输出HTML
@php echo $request->input('code'); @endphp   // Critical: 执行PHP代码
Blade::render($template)                     // 如果$template用户可控

// 审计正则
\{\!\!.*\$|@php\s+.*\$request|Blade::render.*\$request

// 漏洞示例: 动态模板
public function render(Request $request) {
    $template = $request->input('template');
    return Blade::render($template, ['user' => Auth::user()]);  // Critical: SSTI
}

// 攻击载荷
POST /render
template={{ system('id') }}
template=@php system($_GET['cmd']); @endphp
```

---

## 路径遍历和文件操作

```php
// 危险操作
Storage::get($request->input('file'));       // High: 路径遍历
file_get_contents($path);                    // 如果$path用户可控
File::delete($request->input('path'));       // Critical: 任意文件删除
include($request->input('page') . '.php');   // Critical: 文件包含

// 审计正则
Storage::(get|put|delete).*\$request|file_get_contents.*\$request
File::(get|put|delete).*\$request|include.*\$request|require.*\$request

// 攻击载荷
GET /download?file=../../.env
GET /download?file=../../../etc/passwd
```

---

## SSRF 检测

```php
// 危险操作
Http::get($request->input('url'));           // High: SSRF
file_get_contents($url);
Guzzle\Client->get($url);

// 审计正则
Http::(get|post|request).*\$request|file_get_contents.*\$request
Guzzle.*->get.*\$request

// 攻击载荷
GET /fetch?url=http://169.254.169.254/latest/meta-data/
GET /fetch?url=http://localhost:6379/
GET /fetch?url=file:///etc/passwd
```

---

## 认证和授权绕过

```php
// 未验证所有权
public function deletePost($id) {
    Post::find($id)->delete();  // High: IDOR
}

// 弱认证检查
if ($request->header('X-Admin') == 'true') {  // Critical
    // admin actions
}

// 基于客户端的授权
if ($request->input('role') == 'admin') {  // Critical
    // ...
}

// 审计正则
->delete\(\)|->update\(\)  # 检查是否有授权验证
\$request->(input|header).*==.*admin

// 漏洞示例: IDOR + 缺少中间件
Route::group(['prefix' => 'admin'], function () {
    Route::get('/users', [AdminController::class, 'users']);
});
// 缺少 middleware('auth') 或 can() 检查
```

---

## CSRF 保护检测

```php
// 危险配置
// app/Http/Middleware/VerifyCsrfToken.php
protected $except = [
    '*',                 // Critical: 全局禁用
    'api/*',             // API端点需其他保护
    '/webhook/*'         // 合理(外部回调)
];

// 审计正则
VerifyCsrfToken.*\$except|@csrf  # 检查是否正确使用
```

---

## XXE 漏洞检测

```php
// 危险操作
$xml = simplexml_load_string($request->input('xml'));  // High: XXE
$dom = new DOMDocument();
$dom->loadXML($xmlString);  // 默认不安全

// 审计正则
simplexml_load_(string|file)|DOMDocument.*loadXML|XMLReader

// 攻击载荷
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
```

---

## 命令注入检测

```php
// 危险操作
exec($request->input('cmd'));                // Critical
shell_exec("ping " . $host);
system("convert " . $file);
`whoami $user`;                              // 反引号执行

// 审计正则
exec\s*\(.*\$|shell_exec.*\$|system\s*\(.*\$|passthru.*\$|`.*\$

// 攻击载荷
GET /ping?host=google.com;whoami
GET /ping?host=`cat /etc/passwd`
```

---

## 敏感信息泄露

```php
// 危险配置
'debug' => true,                             // 生产环境启用debug
APP_DEBUG=true                               // 生产环境

// 代码泄露
return response()->json($exception);         // 异常对象泄露
dd($user);                                   // 调试输出忘记删除
Log::debug($request->all());                 // 密码记录到日志

// 审计正则
APP_DEBUG=true|dd\(|dump\(|var_dump\(|print_r\(
Log::.*password
```

---

## 开放重定向检测

```php
// 危险操作
return redirect($request->input('url'));     // Medium
return redirect()->intended($request->input('next'));

// 审计正则
redirect\s*\(\s*\$request|redirect\(\)->.*\$request

// 攻击载荷
GET /logout?redirect=https://evil.com/phishing
```

---

## 搜索模式汇总

```regex
# Mass Assignment
::create\s*\(\s*\$request->all|->fill\s*\(\s*\$request

# SQL注入
DB::(select|statement).*\$|whereRaw.*\$|orderByRaw.*\$request

# 反序列化
unserialize\s*\(|APP_KEY\s*=

# SSTI
\{\!\!.*\$|@php.*\$request|Blade::render.*\$request

# 路径遍历
Storage::(get|delete).*\$request|include.*\$request

# SSRF
Http::(get|post).*\$request|file_get_contents.*\$request

# 命令注入
exec\s*\(.*\$|shell_exec|system\s*\(|passthru|`

# 授权
->delete\(\)|->update\(\)  # 检查是否有authorize

# CSRF
VerifyCsrfToken.*\$except

# 敏感信息
APP_DEBUG=true|dd\(|var_dump\(

# 开放重定向
redirect\s*\(\s*\$request
```

---

## 快速审计检查清单

```markdown
[ ] 检查 composer.json 依赖版本
[ ] 检查 .env 是否在 .gitignore
[ ] 检查 APP_DEBUG 生产环境配置
[ ] 搜索 create/fill/update ($request->all)
[ ] 检查 Model 的 $fillable/$guarded
[ ] 搜索 whereRaw/orderByRaw (SQL注入)
[ ] 检查 unserialize 和 APP_KEY 泄露
[ ] 搜索 {!! (Blade不转义输出)
[ ] 检查文件操作的路径拼接
[ ] 检查 Http::get/file_get_contents (SSRF)
[ ] 检查 exec/shell_exec (命令注入)
[ ] 检查 Policy 和 authorize 使用
[ ] 检查 VerifyCsrfToken 的 $except
[ ] 检查 redirect 开放重定向
[ ] 检查登录/注册接口的速率限制
```

## 最小 PoC 示例
```bash
# Blade SSTI/未转义输出
curl "http://localhost/profile?name={{7*7}}"

# SQL 注入 (whereRaw)
curl "http://localhost/users?orderByRaw=id desc;select version()"

# SSRF
curl "http://localhost/fetch?url=http://169.254.169.254/latest/meta-data/"
```
