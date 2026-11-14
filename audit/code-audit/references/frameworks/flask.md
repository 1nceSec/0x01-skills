# Flask Security Audit

> Flask 框架安全审计模块
> 适用于: Flask, Flask-RESTful, Flask-Login, Flask-JWT-Extended

## Critical 漏洞

### 1. 调试模式 RCE

```python
# 危险: 生产环境开启调试
app.run(debug=True)  # Werkzeug debugger PIN 可被计算

# PIN 计算要素 (可用于爆破):
# - username, modname (flask.app), app.__name__, mod.__file__
# - uuid.getnode() -> MAC, get_machine_id() -> /etc/machine-id

# 检测
grep -rn "debug\s*=\s*True" --include="*.py"
grep -rn "FLASK_DEBUG\|DEBUG\s*=" --include="*.py" --include="*.env"
```

### 2. SECRET_KEY 泄露

```python
# 危险: 硬编码/弱密钥
app.secret_key = 'super_secret_key'
SECRET_KEY = 'development'

# 影响: Session伪造, Flask-Login令牌伪造, CSRF token伪造, itsdangerous签名伪造

# 检测
grep -rn "secret_key\s*=\|SECRET_KEY\s*=" --include="*.py"
```

### 3. SSTI (Server-Side Template Injection)

```python
# 危险: render_template_string 用户输入
from flask import render_template_string
@app.route('/hello')
def hello():
    name = request.args.get('name', 'World')
    template = f'<h1>Hello {name}!</h1>'
    return render_template_string(template)

# payload: {{config.items()}}
# payload: {{''.__class__.__mro__[1].__subclasses__()}}
# RCE: {{''.__class__.__mro__[1].__subclasses__()[X].__init__.__globals__['os'].popen('id').read()}}

# 危险: 用户控制模板名
@app.route('/page/<template>')
def page(template):
    return render_template(template)  # 可能加载任意模板

# 检测
grep -rn "render_template_string" --include="*.py"
grep -rn "render_template.*request\." --include="*.py"
```

### 4. Pickle Session 反序列化

```python
# Flask-Session 配置
SESSION_SERIALIZER = PickleSerializer  # 危险! SECRET_KEY泄露 + pickle = RCE

# 检测
grep -rn "SESSION_SERIALIZER\|PickleSerializer\|pickle" --include="*.py"
```

---

## High 漏洞

### 5. SQL 注入

```python
# 危险: 原始 SQL 拼接
sql = f"SELECT * FROM users WHERE id = {id}"
result = db.engine.execute(sql)

# 危险: text() 拼接
db.session.execute(text(f"SELECT * FROM users WHERE name = '{name}'"))

# 检测
grep -rn "execute\s*\(.*f[\"']" --include="*.py"
grep -rn "text\s*\(.*f[\"']" --include="*.py"
```

### 6. 命令注入

```python
# 危险: os.system / subprocess shell=True
os.system(f'ping -c 4 {host}')
subprocess.run(f'echo {user_input}', shell=True)
# payload: ?host=127.0.0.1;id

# 检测
grep -rn "os\.system\|subprocess\.\|popen" --include="*.py"
```

### 7. 任意文件读取/写入

```python
# 危险: 路径拼接
@app.route('/download')
def download():
    filename = request.args.get('file')
    return send_file(f'/uploads/{filename}')
# payload: ?file=../../../etc/passwd

# 危险: 文件上传未验证
file.save(f'/uploads/{file.filename}')  # 危险!

# 检测
grep -rn "send_file\|send_from_directory\|open\s*\(" --include="*.py"
```

### 8. SSRF

```python
# 危险: 未验证 URL
@app.route('/fetch')
def fetch():
    url = request.args.get('url')
    resp = requests.get(url)
    return resp.text
# payload: ?url=http://169.254.169.254/latest/meta-data/
```

---

## Medium 漏洞

### 9. XSS

```python
# 危险: Markup/safe 标记
return Markup(f'<p>{text}</p>')  # 不转义!

# 危险: |safe 过滤器
{{ user_input|safe }}

# 危险: 直接返回 HTML
return f'<h1>Hello {name}</h1>'  # 不经过模板

# 检测
grep -rn "Markup\s*\(" --include="*.py"
grep -rn "|safe" --include="*.html"
grep -rn "return.*f['\"].*<" --include="*.py"
```

### 10. CSRF / Open Redirect / Session

```python
# Open Redirect: 未验证重定向
return redirect(request.args.get('next'))
# payload: ?next=http://evil.com

# Session 危险配置
SESSION_COOKIE_SECURE = False
SESSION_COOKIE_HTTPONLY = False
```

---

## Flask 扩展安全

```python
# Flask-Login: remember_me 默认365天
login_user(user, remember=True)

# Flask-JWT: 弱密钥/永不过期
JWT_SECRET_KEY = 'weak_secret'
JWT_ACCESS_TOKEN_EXPIRES = False

# Flask-CORS: 允许所有+凭证
CORS(app, supports_credentials=True, origins='*')
```

---

## 检测命令汇总

```bash
grep -rn "debug\s*=\s*True" --include="*.py"
grep -rn "secret_key\s*=\|SECRET_KEY\s*=" --include="*.py"
grep -rn "render_template_string\|Markup\s*\(" --include="*.py"
grep -rn "execute\s*\(" --include="*.py" | grep -E "f['\"]|\+"
grep -rn "os\.system\|subprocess\.\|popen" --include="*.py"
grep -rn "send_file\|send_from_directory\|open\s*\(" --include="*.py"
bandit -r . -ll
```

## 审计清单

```
[ ] DEBUG模式生产环境禁用
[ ] SECRET_KEY硬编码或弱密钥
[ ] render_template_string使用
[ ] SQL查询参数化
[ ] 命令执行函数
[ ] 文件操作路径遍历
[ ] HTTP请求SSRF
[ ] CSRF保护启用
[ ] Session配置
[ ] CORS配置
[ ] Flask扩展配置
```

## 最小 PoC 示例
```bash
# Jinja2 SSTI
curl "http://localhost:5000/hello?name={{7*7}}"

# DEBUG 模式检查
curl -I http://localhost:5000/ | grep "Werkzeug"

# SSRF
curl "http://localhost:5000/fetch?url=http://169.254.169.254/latest/meta-data/"
```
