# Python Security Audit Guide

> Python 代码安全审计模块 | **双轨并行完整覆盖**
> 适用于: Python 2.x / 3.x, Flask, Django, FastAPI, Tornado 等

---

# 轨道B: 数据流分析法 (注入类漏洞)

> **核心公式**: Source → [无净化] → Sink = 注入类漏洞

## B1. Python Source

```python
# Flask
request.args.get('name')       # GET参数
request.form.get('name')       # POST表单
request.json                   # JSON body
request.headers.get('X-Header')
request.cookies.get('session')
request.files['file']

# Django
request.GET.get('name')
request.POST.get('name')
request.body
request.META.get('HTTP_X_HEADER')
```

## B2. Python Sink

| Sink类型 | 漏洞 | CWE | 危险函数 |
|----------|------|-----|----------|
| 命令执行 | 命令注入 | 78 | os.system, subprocess |
| 代码执行 | 代码注入 | 94 | eval, exec |
| SQL执行 | SQL注入 | 89 | cursor.execute, raw() |
| 文件操作 | 路径遍历 | 22 | open(), os.path.join |
| 反序列化 | RCE | 502 | pickle.load, yaml.load |
| 模板引擎 | SSTI | 97 | render_template_string |

## B3. Sink检测命令

## 核心危险面

Python因其动态特性和强大的内省能力，存在独特的安全挑战。关键攻击面包括：代码/命令注入、不安全反序列化、模板注入、格式化字符串漏洞。

---

## B4. Sink检测命令详细

### 命令注入检测

```python
# 高危函数清单
os.system(cmd)                    # 直接shell执行
os.popen(cmd)                     # 执行返回文件对象
os.spawn*(mode, path)             # 进程生成
subprocess.*(cmd, shell=True)     # shell=True时危险
subprocess.getoutput(cmd)         # 直接shell执行 (Python 3)
subprocess.getstatusoutput(cmd)   # 直接shell执行
commands.getoutput(cmd)           # Python 2
platform.popen(cmd)               # 间接执行向量
timeit.timeit(stmt)               # stmt可为代码字符串
pty.spawn(argv)                   # Linux 伪终端

# 危险示例
os.system('ping -n 4 %s' % ip)  # 拼接用户输入
s = subprocess.Popen('ping -n 4 ' + cmd, shell=True, stdout=subprocess.PIPE)

# subprocess 详解
# shell=False: 参数必须是列表，不经过 shell 解析
# shell=True:  调用 /bin/sh (Linux) 或 cmd.exe (Windows)，可命令注入

# 危险: shell=True
subprocess.Popen('ping -n 4 ' + cmd, shell=True)
subprocess.run('ping -n 4 ' + cmd, shell=True)
# payload: 127.0.0.1 && whoami

# 相对安全: shell=False (但仍需注意)
cmd = 'ping -n 4 %s' % shlex.quote(ip)
subprocess.run(cmd, shell=False)  # 字符串会报错，需列表
# 正确: subprocess.run(['ping', '-n', '4', ip], shell=False)

# shlex.quote() 注意事项
# shell=False 时，shlex.quote 会把参数当作单个字符串
# ping -n 4 '127.0.0.1&&whoami' → 当作单个参数
# 但如果命令本身拼接，仍有风险

os.system('rm %s' % filename)  # 文件名来自数据库，但仍需注意
# 注意: 如果文件名是 "aaa;whoami;.jsp"，仍有风险!

# 审计正则
os\.system\s*\(|os\.popen\s*\(|subprocess\.(call|Popen|run|getoutput)\s*\(
shell\s*=\s*True|platform\.popen\s*\(|timeit\.timeit\s*\(|pty\.spawn\s*\(
```

---

## 代码注入检测

```python
# 高危函数
eval(expression)           # 执行表达式
exec(code)                 # 执行任意代码
compile(source, ...)       # 编译代码对象
__import__(name)           # 动态导入
execfile(filename)         # Python 2

# 利用技术
__import__('os').system('id')
__builtins__.__dict__['__import__']('os')  # 绕过import过滤
chr(111)+chr(115)  # 绕过引号 = 'os'
base64.b64decode('payload')  # 编码绕过
__import__("pbzznaqf".decode('rot_13'))  # ROT13绕过
imp.reload(os)  # 模块重载绕过
sys.modules['os'] = __import__('os')  # sys.modules恢复

# 魔术方法链
"".__class__.__bases__[0].__subclasses__()  # 类遍历
func.__globals__  # 暴露模块级变量


---

## 反序列化检测

```python
# Pickle - 最危险
pickle.loads(data) / pickle.load(file)
pickle.Unpickler(file).load()
# Pickle操作码: R(调用), i(实例化), o(构建), c(导入)
# __reduce__()/__reduce_ex__() 魔术方法自动触发

# Pickle 利用
class Exploit:
    def __reduce__(self):
        return (os.system, ('whoami',))

e = Exploit()
payload = pickle.dumps(e)
# b'\x80\x03cnt\nsystem\nq\x00X\x06\x00\x00\x00whoamiq\x01\x85q\x02Rq\x03.'

# 反序列化触发
pickle.loads(payload)  # 执行 os.system('whoami')

# PyYAML - 高危
yaml.load(data)  # 危险! 默认不安全
# ≤5.1: !!python/object/apply 无限制执行
# >5.1: 需 Loader=yaml.Loader (仍不安全)
# yaml.FullLoader 仍有风险

# YAML payload
!!python/object/apply:os.system ['id']
!!python/object/new:os.system ['id']
!!python/object/apply:subprocess.check_output [['id']]

# 检测 payload
cp = "!!python/object/apply:subprocess.check_output [[ls]]"
yaml.load(cp)  # 执行命令

# jsonpickle - 使用 pickle 序列化
import jsonpickle

class Person:
    def __reduce__(self):
        return (__import__('os').system, ('whoami',))

admin = Person()
s = jsonpickle.encode(admin)
# '{"py/reduce": [{"py/function": "nt.system"}, {"py/tuple": ["whoami"]}]}'
jsonpickle.decode(s)  # 触发命令执行

# shelve - 基于 pickle
import shelve
file = shelve.open("test")
file['exp'] = Exploit()  # 存储时序列化
file.close()
# 读取时反序列化触发

# marshal - 序列化 code 对象
import marshal
import types

def malicious():
    import os
    os.system('whoami')

code_serialized = base64.b64encode(marshal.dumps(malicious.__code__))
code_unserialized = types.FunctionType(
    marshal.loads(base64.b64decode(code_serialized)),
    globals(),
    ''
)()  # 执行

---

## SSTI模板注入

### 各引擎特性对比

| 引擎    | 语法           | Python执行   | 风险         |
|---------|----------------|--------------|--------------|
| Jinja2  | {{ }}          | 受限         | 魔术方法链   |
| Mako    | ${} / <% %>    | 直接执行     | 无沙箱       |
| Tornado | ${} / {% %}    | %import支持  | 模块导入     |
| Django  | {{ }}          | 受限         | 标签注入     |

### Jinja2 检测与利用

```python
# 检测
{{7*7}} → 49
{{7*'7'}} → 7777777

# 利用payload
{{cycler.__init__.__globals__.os.popen('id').read()}}
{{lipsum.__globals__['os'].popen('id').read()}}
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}

# 审计正则
render_template_string\s*\(|Template\s*\([^)]*\)\.render
```

### Mako - 直接执行Python

```python
# 语法: ${} 表达式, <% %> 代码块
<%import os; os.system('id')%>
${__import__('os').popen('id').read()}
<%! import subprocess %>${subprocess.check_output(['id'])}

# 审计正则
mako\.template\.Template\s*\(
```

### Tornado - 支持模块导入

```python
# 语法: ${} 表达式, {% %} 语句
{% import os %}${os.popen('id').read()}
${__import__('os').system('id')}

# 审计正则
tornado\.template\.Template\s*\(
```

### Django - 格式化字符串信息泄露

```python
# 危险: 格式化字符串 + format
template = "<p>user:{user}, name:%s</p>" % name  # name 可控
return HttpResponse(template.format(user=request.user))
# payload: name = "{user.password}" → 泄露密码

# 危险: 双重格式化导致信息泄露
name = request.GET.get('name')
template = "<p>user:{user}, name:%s</p>" % name
return HttpResponse(template.format(user=request.user))
# {user.password} → 读取用户密码
# {user.__init__.__globals__[__builtins__][eval]} → 获取 eval 函数

# Django 读取 SECRET_KEY 路径
{user.groups.model._meta.app_config.module.admin.settings.SECRET_KEY}
{user.user_permissions.model._meta.app_config.module.admin.settings.SECRET_KEY}
{user.groups.model._meta.apps.app_configs[auth].module.middleware.settings.SECRET_KEY}
{user.groups.model._meta.apps.app_configs[sessions].module.middleware.settings.SECRET_KEY}
{user.groups.model._meta.apps.app_configs[staticfiles].module.utils.settings.SECRET_KEY}

# format 限制
# 只支持点 (.) 和中括号 ([])，不支持括号调用
# 因此 RCE 受限，主要用于信息泄露

```

---

## 文件操作漏洞

```python
# 危险模式 - 文件读取
open(user_path)
file(user_path)              # Python 2
codecs.open(user_path)
io.open(user_path)
pathlib.Path(path).read_text()
pathlib.Path(path).read_bytes()
send_file(user_path)  # Flask
send_from_directory(directory, filename)  # Flask
FileResponse(open(file_path, 'rb'))  # Django

# 危险模式 - 文件删除
os.remove(user_path)
shutil.rmtree(user_path)

# 危险模式 - 文件上传
file = request.FILES.get('filename')
with open(file.name, 'wb') as f:  # 文件名未过滤
    f.write(file.read())

# 文件上传 - 缺少类型验证
file = request.files.get('filename')
upload_dir = os.path.join(os.path.dirname(__file__), 'uploadfile')
dir = os.path.join(upload_dir, file.filename)  # 未验证后缀
file.save(dir)

# Zip 解压路径遍历 (高危!)
with zipfile.ZipFile(zip_file, "r") as z:
    for fileinfo in z.infolist():
        filename = fileinfo.filename  # 可能是 ../../../etc/passwd
        outfile = os.path.join(UPLOAD_FOLDER, filename)  # 路径遍历!
        with open(outfile, 'wb') as f:
            f.write(z.read(filename))

# 构造恶意 zip
z_info = zipfile.ZipInfo(r"../__init__.py")  # 覆盖关键文件
z_file = zipfile.ZipFile("bad.zip", mode="w")
z_file.writestr(z_info, "malicious code")

# 路径遍历 payload
../../../etc/passwd
....//....//....//etc/passwd  # 绕过../过滤
..%2F..%2F..%2Fetc%2Fpasswd  # URL编码
%2e%2e%2f  # URL编码
%252e%252e%252f  # 双重编码
..\/..\/..\/etc/passwd  # 混合斜杠
local_file:///etc/passwd  # urllib绕过

---

## SSRF检测

```python
# 危险函数
requests.get/post(user_url)  # 仅支持 http/https (默认)
urllib.request.urlopen(user_url)  # 支持 file:// 等协议
httpx.get(user_url)
aiohttp.ClientSession().get(url)

# pycurl - 功能强大但危险
curl = pycurl.Curl()
curl.setopt(curl.URL, user_url)  # 支持多协议
curl.setopt(curl.FOLLOWLOCATION, True)  # 自动跳转
curl.perform()

# requests 扩展协议支持
from requests_file import FileAdapter
s = requests.Session()
s.mount('file://', FileAdapter())  # 添加 file:// 支持后变危险
req = s.get(user_url)

# 协议风险
file://   → 本地文件读取
gopher:// → Redis/Memcached攻击
dict://   → 端口探测
ftp://    → 内网FTP访问
ldap://   → 目录服务访问

# IP绕过技巧
2130706433           # 十进制 = 127.0.0.1
0x7f000001           # 十六进制
0177.0.0.1           # 八进制 (注意: Python socket 不支持)
127.0.0.1.xip.io     # DNS重绑定
localhost            # 绕过 IP 黑名单
0.0.0.0              # 绕过检测
[::]                 # IPv6 loopback

# urllib 文件协议陷阱
# Windows: file://C:/Windows/win.ini  (错误: C 被当作 host)
# 正确:    file:///C:/Windows/win.ini (三个斜杠)
# Linux:   file:///etc/passwd

# 302 跳转绕过
# 外部URL → 302 → 内网IP (需检测每次跳转)

# Python socket.getaddrinfo() 不支持非标准格式
# 0x7F.0.0.1, 0177.0.0.1 会报错 socket.gaierror
# 但浏览器解析可能支持 (django HttpResponseRedirect 跳转时)

# 审计正则
requests\.(get|post|put|delete)\s*\([^)]*request\.
urllib\.request\.urlopen\s*\([^)]*request\.
pycurl\.Curl\s*\(|curl\.setopt\s*\(.*URL
```

---

## XXE检测

### 默认不安全行为

| 库              | resolve_entities | 风险            |
|-----------------|------------------|-----------------|
| lxml            | True             | 默认解析实体    |
| xml.dom.minidom | True             | 需显式禁用      |
| xml.sax         | 依配置           | 需显式禁用      |
| defusedxml      | False            | 推荐使用        |

```python
# 危险用法
etree.parse(source)
etree.fromstring(xml_string)
minidom.parse(source)
xml.sax.parse(source, handler)


# 审计正则
etree\.(parse|fromstring|XML)\s*\(|(?<!defusedxml\.)ElementTree
```

---

## SQL注入检测

```python
# 危险模式
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
cursor.execute("SELECT * FROM users WHERE name = '%s'" % name)
cursor.execute("SELECT * FROM users WHERE id = " + user_id)
cursor.execute('SELECT username FROM auth_user WHERE id = %s;' %str(id))  # 字符串拼接

# Django ORM 拼接注入
User.objects.raw(f"SELECT * FROM users WHERE id = {id}")
User.objects.extra(where=[f"name = '{name}'"])
User.objects.extra(WHERE=['id='+str(id)])  # 错误: 拼接

# Django ORM 参数名可控注入 (高危!)
data = json.loads(request.body.decode())
Student.objects.filter(**data).first()  # data = {"passkey__contains":"a"}
# 利用 lookup 语法: passkey__contains, passkey__startswith 等

# Django 字典注入
dict = {'username':"admin' OR '1'='1", 'age':18}
User.objects.create(**dict)  # 字典键可控时危险

# Django 二次注入
filename = request.GET.get('url')
File.objects.create(filename=filename)  # 存入: ' or '1'='1
cur.execute("""select * from file where filename='%s'""" %(filename))  # 拼接导致注入

# SQLAlchemy 拼接
sql = "SELECT name, email from users WHERE id = %s" %str(id)
data = session.execute(sql).fetchone()

# 安全参数化
cursor.execute("SELECT * FROM users WHERE id = ?", [user_id])  # SQLite
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))  # MySQL/PostgreSQL
cursor.executemany('insert into userinfo(user,pwd) values(%s,%s);', data)  # 批量插入

# Django ORM 安全
User.objects.filter(id=user_id)  # 使用标准 API
User.objects.get(id=str(id))  # 安全的 ORM
User.objects.raw("SELECT * FROM users WHERE id = %s", [user_id])  # 参数化
User.objects.extra(WHERE=['id=%s'], params=[str(id)])  # 正确的 extra 用法

# SQLAlchemy 安全
user = User.query.filter(User.id == id).first()
session.execute(text("SELECT * FROM users WHERE id = :id"), {"id": user_id})

# 审计正则
execute\s*\([^)]*['"]\s*\+|execute\s*\(f['"']|execute\s*\([^)]*%s['"]\s*%
\.raw\s*\(f['"']|\.extra\s*\([^)]*where\s*=\s*\[|\.filter\s*\(\*\*
```

### ORM/Query Builder高级注入模式

```python
# ===== Django ORM 高危模式 =====

# 1. extra() 方法注入 (Critical)
# ❌ 危险: where子句字符串拼接
User.objects.extra(where=[f"status = '{status}'"])
User.objects.extra(where=["id=" + user_id])
User.objects.extra(select={'is_recent': f"created_at > '{date}'"})

# ✓ 安全: 使用参数化
User.objects.extra(where=["status = %s"], params=[status])
User.objects.extra(select={'is_recent': "created_at > %s"}, select_params=[date])

# 2. raw() 查询注入 (Critical)
# ❌ 危险: SQL拼接
User.objects.raw(f"SELECT * FROM users WHERE name = '{name}'")
User.objects.raw("SELECT * FROM users WHERE id = " + str(user_id))

# ✓ 安全: 参数化
User.objects.raw("SELECT * FROM users WHERE name = %s", [name])

# 3. RawSQL 注入 (Critical)
from django.db.models import RawSQL
# ❌ 危险
User.objects.annotate(
    val=RawSQL(f"SELECT COUNT(*) FROM orders WHERE user_id = {user.id}", ())
)

# ✓ 安全
User.objects.annotate(
    val=RawSQL("SELECT COUNT(*) FROM orders WHERE user_id = %s", (user.id,))
)

# 4. 字段名注入 (High)
# ❌ 危险: 用户控制字段名
field_name = request.GET.get('sort_by')  # 用户输入: "id); DROP TABLE users; --"
User.objects.order_by(field_name)  # 危险!

# ❌ 危险: 动态lookup
lookup = request.GET.get('lookup')  # 用户输入可能包含 "__" 构造复杂查询
User.objects.filter(**{lookup: value})

# ✓ 安全: 白名单验证
ALLOWED_SORT_FIELDS = ['id', 'created_at', 'username']
if field_name in ALLOWED_SORT_FIELDS:
    User.objects.order_by(field_name)

# 5. Q对象注入 (Medium)
from django.db.models import Q
# ❌ 潜在危险: 动态构造Q对象
filter_dict = json.loads(request.body)  # {"name__contains": "admin"}
User.objects.filter(Q(**filter_dict))

# ✓ 安全: 验证键名
ALLOWED_LOOKUPS = {'name__exact', 'email__exact', 'id'}
safe_dict = {k: v for k, v in filter_dict.items() if k in ALLOWED_LOOKUPS}
User.objects.filter(Q(**safe_dict))

# 6. aggregate() / annotate() 注入
from django.db.models import Count, Sum
# ❌ 危险: 动态聚合字段
agg_field = request.GET.get('field')
User.objects.aggregate(Count(agg_field))  # 字段名可控

# ✓ 安全: 白名单
ALLOWED_AGG_FIELDS = ['orders', 'comments', 'likes']
if agg_field in ALLOWED_AGG_FIELDS:
    User.objects.aggregate(Count(agg_field))

# ===== SQLAlchemy 高危模式 =====

# 1. text() 拼接注入 (Critical)
from sqlalchemy import text
# ❌ 危险
query = text(f"SELECT * FROM users WHERE name = '{name}'")
session.execute(query)

# ❌ 危险: format拼接
query = text("SELECT * FROM users WHERE id = {}".format(user_id))
session.execute(query)

# ✓ 安全: 绑定参数
query = text("SELECT * FROM users WHERE name = :name")
session.execute(query, {"name": name})

# 2. filter() 字符串表达式注入 (High)
# ❌ 危险: 字符串WHERE子句
session.query(User).filter(f"name = '{name}'").all()

# ✓ 安全: 使用ORM表达式
session.query(User).filter(User.name == name).all()

# 3. order_by() 字符串注入 (High)
# ❌ 危险: 动态ORDER BY
sort_field = request.args.get('sort')
session.query(User).order_by(text(sort_field)).all()

# ✓ 安全: 白名单 + getattr
SORT_FIELDS = {'id': User.id, 'name': User.name}
if sort_field in SORT_FIELDS:
    session.query(User).order_by(SORT_FIELDS[sort_field]).all()

# 4. Column name injection (High)
# ❌ 危险: 动态列名
column_name = request.args.get('column')
session.query(getattr(User, column_name)).all()  # AttributeError可能,但仍危险

# ✓ 安全: 白名单映射
ALLOWED_COLUMNS = {'id': User.id, 'email': User.email}
if column_name in ALLOWED_COLUMNS:
    session.query(ALLOWED_COLUMNS[column_name]).all()

# 5. join() 字符串注入 (Medium)
# ❌ 危险
table_name = request.args.get('join_table')
session.query(User).join(table_name).all()

# ✓ 安全: 预定义join
session.query(User).join(User.profile).all()

# 6. from_statement() 注入 (Critical)
# ❌ 危险
sql = f"SELECT * FROM users WHERE created_at > '{date}'"
session.query(User).from_statement(text(sql)).all()

# ✓ 安全
sql = "SELECT * FROM users WHERE created_at > :date"
session.query(User).from_statement(text(sql)).params(date=date).all()

# ===== Peewee ORM =====
from peewee import *

# ❌ 危险: SQL拼接
query = User.raw(f"SELECT * FROM users WHERE name = '{name}'")

# ❌ 危险: 字段名注入
field = request.GET.get('field')
User.select().where(SQL(f"{field} = 'value'"))

# ✓ 安全
User.select().where(User.name == name)
User.raw("SELECT * FROM users WHERE name = ?", name)

# ===== Tortoise ORM (异步) =====
# ❌ 危险
await User.raw(f"SELECT * FROM users WHERE id = {user_id}")

# ✓ 安全
await User.filter(id=user_id)
await User.raw("SELECT * FROM users WHERE id = $1", [user_id])

# ===== Pony ORM =====
from pony.orm import *

# ❌ 危险: select拼接
select(u for u in User if f"u.name == '{name}'")  # eval()内部危险

# ✓ 安全
select(u for u in User if u.name == name)

# ===== 高级注入技术 =====

# 1. JSON字段注入 (PostgreSQL)
# ❌ 危险: JSON操作符注入
json_key = request.GET.get('key')  # 用户输入: "data'->>'password"
User.objects.filter(**{f"metadata__{json_key}": value})

# 2. 数组字段注入 (PostgreSQL)
from django.contrib.postgres.fields import ArrayField
# ❌ 危险
User.objects.filter(tags__contains=[user_input])  # 需验证user_input

# 3. 全文搜索注入 (PostgreSQL)
from django.contrib.postgres.search import SearchQuery
# ❌ 潜在危险: 搜索语法注入
SearchQuery(user_input, search_type='raw')  # 用户可注入特殊字符

# ✓ 安全: 使用plain类型
SearchQuery(user_input, search_type='plain')

# 4. 窗口函数注入
from django.db.models import Window, F
from django.db.models.functions import RowNumber
# 检查partition_by和order_by是否使用用户输入

# ===== 检测正则表达式 =====

# Django ORM危险模式
\.extra\s*\(\s*where\s*=\s*\[.*f["']|\.extra\s*\(.*\+
\.raw\s*\(\s*f["']|\.raw\s*\(.*\+|\.raw\s*\(.*%
RawSQL\s*\(\s*f["']|RawSQL\s*\(.*\+
\.order_by\s*\(.*request\.|\.filter\s*\(\*\*.*request\.

# SQLAlchemy危险模式
text\s*\(\s*f["']|text\s*\(.*\.format|text\s*\(.*\+
\.filter\s*\(\s*f["']|\.filter\s*\(.*\+
\.order_by\s*\(\s*text\(|\.from_statement\s*\(.*\+
getattr\s*\(\s*\w+\s*,\s*request\.|getattr\s*\(.*user_input

# 通用ORM注入
\.execute\s*\(\s*f["']|\.execute\s*\(.*%s["']\s*%
Column\s*\(.*request\.|Table\s*\(.*request\.
```

### ORM注入检测命令

```bash
# Django ORM高危检测
grep -rn "\.extra\s*(" --include="*.py" -A 3 | grep -E "where.*\+|where.*f['\"]|where.*%"
grep -rn "\.raw\s*(" --include="*.py" -A 2 | grep -E "f['\"]|%s['\"].*%|\+"
grep -rn "RawSQL\s*(" --include="*.py" -A 2 | grep -E "f['\"]|\+"
grep -rn "\.order_by\s*\(" --include="*.py" | grep -E "request\.|GET\.|POST\.|params"
grep -rn "\.filter\s*\(\*\*" --include="*.py" -A 1 | grep -E "request\.|json\.loads"

# SQLAlchemy高危检测
grep -rn "text\s*\(" --include="*.py" -A 2 | grep -E "f['\"]|\.format|\+|%s['\"].*%"
grep -rn "\.filter\s*\(" --include="*.py" -A 1 | grep -E "f['\"]|\+"
grep -rn "getattr\s*\(.*User" --include="*.py" | grep -E "request\.|args\.|form\."
grep -rn "from_statement" --include="*.py" -A 2 | grep -E "text.*\+|text.*f['\"]"

# 字段名/表名注入检测
grep -rn "order_by.*request\|order_by.*GET\|order_by.*args" --include="*.py"
grep -rn "annotate.*request\|aggregate.*request" --include="*.py"

# JSON/Array字段检测(PostgreSQL特有)
grep -rn "ArrayField\|JSONField\|HStoreField" --include="*.py" -A 5 | grep "request\."
```

### 安全修复检查清单

**Critical修复:**
- [ ] 所有`.raw()`和`text()`使用参数化查询
- [ ] 移除`.extra(where=[])`中的字符串拼接
- [ ] `RawSQL()`第一个参数不包含f-string或+拼接
- [ ] `.execute()`调用全部参数化

**High修复:**
- [ ] 动态字段名使用白名单验证
- [ ] ORDER BY子句字段名白名单
- [ ] `.filter(**dict)`的dict键名验证
- [ ] JSON/Array操作的用户输入验证

**Medium审查:**
- [ ] Q对象动态构造的lookup验证
- [ ] aggregate/annotate字段名验证
- [ ] 自定义Manager方法的SQL安全性
- [ ] 信号(signals)中的查询安全
```

---

## 格式化字符串漏洞

```python
# 用户控制模板时可泄露信息
template = "{name.__class__.__init__.__globals__}"
template.format(name=user_object)

# Flask读取配置
"{user.__class__.__init__.__globals__[config]}".format(user=obj)

# Django读取密码
"{user.password}".format(user=request.user)

# 审计正则
\.format\s*\([^)]*request\.|\.format_map\s*\(
```

---

## XSS 跨站脚本

```python
# 危险: 直接输出用户输入
# Flask
name = request.args.get('name')
return Response("<p>name: %s</p>" % name)

# Django
name = request.GET.get('name')
return HttpResponse("<p>name: %s</p>" % name)

# 危险: render_template_string 拼接
template = "<p>%s</p>" % name
return render_template_string(template)  # 可能导致 XSS 和 SSTI

# 危险: mark_safe (Django)
from django.utils.safestring import mark_safe
return HttpResponse(mark_safe(f"<div>{user_input}</div>"))

# 危险: |safe 过滤器
{{ user_input|safe }}  # 模板中标记为安全

# 动态 URL 属性风险
<a href="{{ url }}">link</a>  # url 可能是 javascript:alert(1)
# 需验证 URL scheme

# 审计正则
Response\s*\([^)]*%|HttpResponse\s*\([^)]*%
render_template_string\s*\(|mark_safe\s*\(|\|safe\s*}}
```

---

## URL Bypass / Open Redirect

```python
# 危险: 未验证的重定向
# Flask
url = request.values.get('url')
return redirect(url)  # 任意 URL 跳转

# Django
from django.shortcuts import redirect
url = request.GET.get('url')
return redirect(url)

# 危险: 弱验证
if url.endswith('baidu.com'):
    return redirect(url)
# 绕过: evil.com?baidu.com, evil.com/baidu.com, evil.com#baidu.com

# Django is_safe_url (注意 CVE-2017-7233)
from django.utils.http import is_safe_url
if is_safe_url(url, allowed_hosts={'example.com'}):
    return redirect(url)
# 旧版本可利用: https:12345678 绕过

# 审计正则
redirect\s*\([^)]*request\.|HttpResponseRedirect\s*\(
```

---

## 弱随机数

```python
# 不安全 - 可预测 (基于 Mersenne Twister)
import random
random.random()
random.randint(a, b)
random.choice(seq)
random.seed(time.time())  # 可预测种子

# 危险场景
token = ''.join(random.choices(string.ascii_letters, k=32))  # 不安全!
session_id = random.randint(1000000, 9999999)  # 可预测
password_reset_code = random.randint(100000, 999999)  # 可暴力破解


## 自动化工具

```bash
# Bandit - Python静态分析
bandit -r /path/to/project -f json
bandit -r /path/to/project --exclude tests/

# Semgrep - 多语言SAST
semgrep --config=p/python /path/to/project
semgrep --config=p/security-audit /path/to/project

# Safety - 依赖漏洞检查
safety check -r requirements.txt

# 快速grep扫描
grep -rn "os\.system\|subprocess.*shell=True" --include="*.py" .
grep -rn "eval\s*(\|exec\s*(" --include="*.py" .
grep -rn "pickle\.load\|yaml\.load" --include="*.py" .
grep -rn "render_template_string" --include="*.py" .
grep -rn "execute.*f['\"]SELECT" --include="*.py" .
```

---

## 最小 PoC 示例
```bash
# SSTI
curl "http://localhost:5000/hello?name={{7*7}}"

# Pickle 反序列化
python -c "import pickle,os; print(pickle.dumps(os.system))"

# YAML unsafe load
python - <<'PY'
import yaml
print(yaml.load("!!python/object/apply:os.system ['id']", Loader=yaml.UnsafeLoader))
PY
```

---

---

## 授权漏洞检测 (Authorization Gap) - v1.7.1

> **核心问题**: 授权漏洞是"代码缺失"，grep 无法检测"应该有但没有"的代码
> **解决方案**: 授权矩阵方法 - 从"应该是什么"出发，而非"存在什么"

### 方法论

```
❌ 旧思路 (被动检测 - 局限性大):
   搜索 @login_required 装饰器 → 检查是否存在
   问题: 存在装饰器不等于正确，可能配置错误或遗漏

✅ 新思路 (主动建模 - 系统性):
   1. 枚举所有敏感操作 (delete/update/export/download)
   2. 定义应有的权限 (谁可以操作什么)
   3. 对比实际代码，检测缺失或不一致
```

### Django 授权检测

```bash
# 步骤1: 找到所有视图的敏感操作
grep -rn "def\s\+\(delete\|update\|edit\|destroy\|export\|download\)" --include="views.py"
grep -rn "class.*\(Delete\|Update\|Destroy\)View" --include="views.py"

# 步骤2: 检查权限装饰器/Mixin存在性
for file in $(find . -name "views.py"); do
    echo "=== $file ==="
    # 检查敏感方法是否有权限检查
    grep -B 5 "def delete\|def update\|def destroy" "$file" | \
    grep -E "@permission_required|@login_required|PermissionRequiredMixin|LoginRequiredMixin"
done

# 步骤3: 对比同模块方法的权限一致性
echo "=== 权限一致性检查 ==="
grep -B 3 "def create" views.py | head -5
grep -B 3 "def delete" views.py | head -5
```

### 漏洞模式

```python
# ❌ 漏洞: delete方法缺失权限检查
class FileView(View):
    def get(self, request, file_id):
        # 有权限检查
        if not request.user.has_perm('file.view'):
            return HttpResponseForbidden()
        return serve_file(file_id)

    def delete(self, request, file_id):
        # 缺失权限检查! 任何用户都可删除
        File.objects.filter(id=file_id).delete()
        return JsonResponse({'success': True})

# ❌ 漏洞: 水平越权 - 未验证资源所有权
@login_required
def delete_document(request, doc_id):
    # 只检查登录，未验证是否是文档所有者
    Document.objects.filter(id=doc_id).delete()  # 可删除他人文档
    return redirect('documents')

### Flask 授权检测

```bash
# 找到所有路由的敏感操作
grep -rn "@.*\.route.*methods.*\['DELETE'\|'PUT'\|'POST'\]" --include="*.py"
grep -rn "def\s\+\(delete\|update\|remove\|export\)" --include="*.py"

# 检查 login_required 装饰器
grep -B 3 "def delete\|def update" --include="*.py" | grep -c "@login_required"
```

### 漏洞模式 (Flask)

```python
# ❌ 漏洞: 缺失认证检查
@app.route('/api/file/<int:file_id>', methods=['DELETE'])
def delete_file(file_id):
    # 未检查登录状态
    File.query.filter_by(id=file_id).delete()
    return jsonify({'success': True})

# ❌ 漏洞: 有认证但无授权 (水平越权)
@app.route('/api/file/<int:file_id>', methods=['DELETE'])
@login_required
def delete_file(file_id):
    # 只检查登录，未验证是否是文件所有者
    File.query.filter_by(id=file_id).delete()
    return jsonify({'success': True})

### Django REST Framework 授权检测

```bash
# 检查 ViewSet 的权限配置
grep -rn "class.*ViewSet" --include="*.py" -A 10 | grep -E "permission_classes|IsAuthenticated|IsAdminUser"

# 检查自定义动作的权限
grep -rn "@action.*detail=True" --include="*.py" -A 5 | grep "permission_classes"
```

### 漏洞模式 (DRF)

```python
# ❌ 漏洞: ViewSet 全局权限但自定义动作缺失
class FileViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]  # 全局要求登录

    @action(detail=True, methods=['post'])
    def share(self, request, pk=None):
        # 应该额外检查是否是文件所有者
        file = self.get_object()
        file.shared_with.add(request.data['user_id'])
        return Response({'status': 'shared'})

### 授权一致性检测脚本

```bash
#!/bin/bash
# check_auth_consistency_python.sh

echo "=== Python 授权一致性检测 ==="

# Django 项目
if [ -f "manage.py" ]; then
    echo "[Django 项目]"

    # 检查所有视图文件
    for views in $(find . -name "views.py" -type f); do
        echo ""
        echo "检查: $views"

        # 提取敏感方法
        grep -n "def\s\+\(delete\|update\|destroy\|remove\|export\)" "$views" | while read line; do
            line_num=$(echo "$line" | cut -d: -f1)
            method=$(echo "$line" | cut -d: -f2-)

            # 检查前5行是否有权限装饰器
            start=$((line_num - 5))
            [ $start -lt 1 ] && start=1

            auth_check=$(sed -n "${start},${line_num}p" "$views" | \
                grep -c "@permission_required\|@login_required\|PermissionRequiredMixin")

            if [ "$auth_check" -eq 0 ]; then
                echo "  ⚠️  第${line_num}行: $method - 缺少权限装饰器"
            else
                echo "  ✅ 第${line_num}行: $method - 有权限检查"
            fi
        done
    done
fi

# Flask 项目
if [ -f "app.py" ] || ls *.py 2>/dev/null | xargs grep -l "from flask import" >/dev/null 2>&1; then
    echo ""
    echo "[Flask 项目]"

    for pyfile in $(find . -name "*.py" -type f); do
        # 检查 DELETE/PUT 路由
        grep -n "methods=.*DELETE\|methods=.*PUT" "$pyfile" | while read line; do
            line_num=$(echo "$line" | cut -d: -f1)

            # 检查是否有 @login_required
            start=$((line_num - 3))
            [ $start -lt 1 ] && start=1

            auth_check=$(sed -n "${start},${line_num}p" "$pyfile" | grep -c "@login_required")

            if [ "$auth_check" -eq 0 ]; then
                echo "  ⚠️  $pyfile:$line_num - DELETE/PUT 路由缺少 @login_required"
            fi
        done
    done
fi
```

### 间接SSRF检测 (配置驱动)

```python
# ❌ 漏洞: 配置驱动的间接SSRF
# settings.py
API_BASE_URL = os.environ.get('API_URL', 'http://internal-api')

# views.py
def fetch_data(endpoint):
    url = settings.API_BASE_URL + endpoint  # 间接SSRF
    return requests.get(url).json()

# 检测命令
grep -rn "settings\.\w*URL\|settings\.\w*HOST\|config\.\w*url" --include="*.py"
grep -rn "os\.environ.*url\|os\.environ.*host" --include="*.py"
grep -rn "f['\"].*{.*}.*http\|\.format.*http" --include="*.py"
```

### 审计清单 (授权专项)

```
授权矩阵建模:
- [ ] 列出所有敏感操作 (CRUD + export/download)
- [ ] 定义每个操作的预期权限
- [ ] 检查实际装饰器/Mixin是否匹配预期

Django 专项:
- [ ] 检查 View 类的 permission_required
- [ ] 检查 ViewSet 的 permission_classes
- [ ] 验证 get_queryset() 是否过滤用户数据
- [ ] 检查 @action 自定义动作的权限

Flask 专项:
- [ ] 检查 DELETE/PUT 路由的 @login_required
- [ ] 验证资源所有权检查 (current_user.id)
- [ ] 检查 API Blueprint 的权限配置

水平越权防护:
- [ ] 验证所有资源操作都检查 owner/user_id
- [ ] 检查 get_object_or_404 是否包含用户过滤
- [ ] 验证批量操作的权限检查

间接注入:
- [ ] 检查 settings/config 中的 URL 配置
- [ ] 追踪环境变量中的可控值
- [ ] 验证格式化字符串构造的URL
```

---

## CSRF 安全 (CWE-352)

### 危险模式

```python
# 🔴 Django - 禁用 CSRF
from django.views.decorators.csrf import csrf_exempt

@csrf_exempt  # 🔴 状态变更接口禁用 CSRF
def transfer(request):
    if request.method == 'POST':
        # 转账操作
        pass

# 🔴 Flask - 无 CSRF 保护
@app.route('/api/transfer', methods=['POST'])
def transfer():
    # 状态变更操作无 CSRF 保护
    pass

# 🔴 FastAPI - 仅依赖 CORS (不够)
@app.post("/api/transfer")
async def transfer(request: TransferRequest):
    # CORS 不能防止所有 CSRF 攻击
    pass
```


## 硬编码凭据 (CWE-798)

### 危险模式

```python
# 🔴 硬编码密钥
SECRET_KEY = 'my-secret-key-12345'  # 🔴

# 🔴 数据库密码
DATABASES = {
    'default': {
        'PASSWORD': 'admin123',  # 🔴
    }
}

# 🔴 API 密钥
class PaymentService:
    API_KEY = 'sk_live_xxxxxxxxxxxx'  # 🔴

    def charge(self, amount):
        requests.post(url, headers={'Authorization': f'Bearer {self.API_KEY}'})

# 🔴 AWS 凭据
import boto3
client = boto3.client(
    's3',
    aws_access_key_id='AKIA...',  # 🔴
    aws_secret_access_key='xxx',  # 🔴
)
```

## 文件上传安全 (CWE-434)

### 危险模式

```python
# 🔴 Django - 无验证
def upload(request):
    file = request.FILES['file']
    with open(f'/uploads/{file.name}', 'wb') as f:  # 🔴 路径遍历
        for chunk in file.chunks():
            f.write(chunk)

# 🔴 Flask - 无验证
@app.route('/upload', methods=['POST'])
def upload():
    file = request.files['file']
    file.save(f'/uploads/{file.filename}')  # 🔴 任意文件名
```

## 竞态条件 (CWE-362)

### 危险模式

```python
# 1. Check-Then-Act (TOCTOU) - 文件操作
import os

# 危险: 检查与操作之间存在竞态窗口
def vulnerable_file_write(filename, data):
    if not os.path.exists(filename):  # 检查
        # 竞态窗口: 攻击者可以在此创建符号链接
        with open(filename, 'w') as f:   # 操作
            f.write(data)

# 2. 共享状态竞态 (多线程)
# 危险: 共享计数器
class VulnerableCounter:
    def __init__(self):
        self.count = 0

    def increment(self):
        # 非原子操作: read-modify-write
        self.count += 1  # 等同于 temp = self.count; self.count = temp + 1

# 3. Django ORM 竞态
# 危险: 应用层检查
def vulnerable_create_user(username):
    if not User.objects.filter(username=username).exists():
        # 竞态窗口
        User.objects.create(username=username)

# 4. Flask 全局状态竞态
from flask import Flask, g

app = Flask(__name__)

# 危险: 模块级可变状态
request_count = 0  # 多worker共享会出问题

@app.route('/count')
def count():
    global request_count
    request_count += 1  # 非原子，且进程间不共享
    return str(request_count)

# 5. asyncio 竞态
import asyncio

# 危险: 异步check-then-act
cache = {}

async def vulnerable_cache_get(key, compute_fn):
    if key not in cache:
        # 竞态窗口: 多个协程同时执行compute_fn
        cache[key] = await compute_fn()
    return cache[key]

### 检测命令

```bash
# 查找 check-then-act 模式
grep -rn "if.*exists.*:\|if.*is None.*:" --include="*.py" -A 2

# 查找全局可变状态
grep -rn "^[a-z_].*= \[\]$\|^[a-z_].*= \{\}$\|^[a-z_].*= 0$" --include="*.py"

# 查找非原子递增
grep -rn "+= 1\|-= 1" --include="*.py"

# 查找文件存在检查
grep -rn "os\.path\.exists\|os\.path\.isfile" --include="*.py"
```

---
