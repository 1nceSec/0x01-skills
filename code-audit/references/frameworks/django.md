# Django Security Audit

> Django 框架安全审计模块
> 适用于: Django, Django REST Framework

## Django特定漏洞

### 1. ORM注入

```python
# 危险: raw()拼接
User.objects.raw(f"SELECT * FROM auth_user WHERE id = {user_id}")
User.objects.raw('SELECT * FROM auth_user WHERE id = %s' % str(id))

# 危险: extra()拼接
User.objects.extra(where=[f"id = {user_id}"])

# 危险: RawSQL
from django.db.models.expressions import RawSQL
queryset.annotate(val=RawSQL(f"SELECT col FROM tbl WHERE id = {id}"))

# 危险: 参数名可控 (高危!)
data = json.loads(request.body.decode())
Student.objects.filter(**data).first()
# payload: {"passkey__contains":"a"} 利用 lookup 语法
# 可用 lookup: __contains, __startswith, __endswith, __regex 等

# 二次注入
filename = request.GET.get('url')
File.objects.create(filename=filename)  # 存入: ' or '1'='1
cur.execute("""select * from file where filename='%s'""" % filename)

# Django ORM Lookup 语法
# __exact, __contains, __startswith, __endswith, __regex, __iregex
```

### 2. 模板XSS

```python
# 危险: mark_safe
from django.utils.safestring import mark_safe
mark_safe(f"<div>{user_input}</div>")

# 危险: |safe过滤器
{{ user_input|safe }}

# 危险: autoescape off
{% autoescape off %}{{ user_input }}{% endautoescape %}

# 危险: 直接拼接 HTML
return HttpResponse("<p>name: %s</p>" % name)
```

### 2.5. SSTI / 格式化字符串注入

```python
# 危险: 双重格式化字符串
name = request.GET.get('name')
template = "<p>user:{user}, name:%s</p>" % name
return HttpResponse(template.format(user=request.user))
# payload: name = "{user.password}" -> 泄露用户密码

# 读取 SECRET_KEY 路径
{user.groups.model._meta.app_config.module.admin.settings.SECRET_KEY}
{user.groups.model._meta.apps.app_configs[auth].module.middleware.settings.SECRET_KEY}
{user.groups.model._meta.apps.app_configs[sessions].module.middleware.settings.SECRET_KEY}

# format() 限制: 只支持 . 和 [], 不支持括号调用, RCE困难, 主要信息泄露
```

### 3. CSRF配置

```python
# 危险: 全局禁用
MIDDLEWARE = [
    # 'django.middleware.csrf.CsrfViewMiddleware',  # 被注释
]

# 危险: 视图级别禁用
@csrf_exempt  # 搜索这个装饰器
def vulnerable_view(request): ...

# 危险: CSRF_TRUSTED_ORIGINS过宽
CSRF_TRUSTED_ORIGINS = ['https://*.example.com']
```

### 4. 文件处理

```python
# 危险: 不安全的文件路径
def download(request, filename):
    file_path = os.path.join(UPLOAD_DIR, filename)  # 路径遍历
    return FileResponse(open(file_path, 'rb'))

# 危险: 未验证的文件类型/大小
file = request.FILES['file']
with open(f'/uploads/{file.name}', 'wb') as f:  # 文件名未过滤
    f.write(file.read())  # 可能导致 DoS
```

### 5. 调试模式 / SECRET_KEY

```python
# settings.py
DEBUG = True  # 生产环境必须False
ALLOWED_HOSTS = ['*']  # 危险: 应指定具体域名
INSTALLED_APPS = ['debug_toolbar']  # 生产环境应移除

# 危险: 硬编码或弱密钥
SECRET_KEY = 'django-insecure-xxx'
```

### 6. 管理后台

```python
# 默认路径
path('admin/', admin.site.urls)  # 应更改为不可预测路径
```

---

## 审计正则

```regex
# ORM 注入
\.raw\s*\(f['"']|\.raw\s*\([^)]*%\s*str\(
\.extra\s*\([^)]*WHERE\s*=\s*\[|\.extra\s*\([^)]*where\s*=
RawSQL\s*\(f['"']
cursor\.execute\s*\([^)]*['"]\s*%|execute\s*\([^)]*\+
\.filter\s*\(\*\*|\.create\s*\(\*\*

# XSS
mark_safe\s*\(|\|safe\s*}}|autoescape\s+off
HttpResponse\s*\([^)]*%|HttpResponse\s*\(f['"']

# SSTI / 格式化字符串
['"]\s*%\s*[^'"]*\.format\s*\(

# CSRF
@csrf_exempt|csrf_exempt
CsrfViewMiddleware.*#

# 配置
DEBUG\s*=\s*True|ALLOWED_HOSTS\s*=\s*\[['"]?\*['"]?\]

# SECRET_KEY
SECRET_KEY\s*=\s*['"][^'"]{0,30}['"]

# 文件操作
request\.FILES\s*\[|FileResponse\s*\(open\s*\(

# URL 重定向
redirect\s*\([^)]*request\.|HttpResponseRedirect\s*\([^)]*request\.
```

## 审计清单

```
[ ] DEBUG=False (生产), SECRET_KEY强度, ALLOWED_HOSTS
[ ] SESSION_COOKIE_SECURE/HTTPONLY/SAMESITE, CSRF_COOKIE_SECURE
[ ] 搜索 .raw()/.extra()/RawSQL/cursor.execute() 拼接
[ ] 检查 .filter(**dict)/.create(**dict) 参数名可控
[ ] 搜索 mark_safe/|safe/autoescape off/HttpResponse拼接
[ ] 检查双重格式化 (% + format)
[ ] 搜索 @csrf_exempt, 检查中间件配置
[ ] 检查文件上传类型/大小/路径验证
[ ] 检查 admin 路径, debug_toolbar生产移除
[ ] 搜索 redirect() 用户输入
```

## 最小 PoC 示例
```bash
# SQL 注入 (.raw)
curl "http://localhost:8000/users?q=1' OR '1'='1"

# Open Redirect
curl "http://localhost:8000/redirect?next=http://evil.com"
```
