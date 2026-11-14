# Go Security Audit

> Go 代码安全审计模块
> 适用于: Go, Gin, Echo, Fiber, net/http, fasthttp, iris, mux, httprouter

---

## 识别特征

```go
// Go项目识别
package main

import (
    "net/http"
    "github.com/gin-gonic/gin"
)

// 文件结构
├── go.mod
├── go.sum
├── main.go
├── cmd/
├── internal/
│   ├── handler/
│   ├── service/
│   └── repository/
├── pkg/
└── config/
```

---

## 轨道B: 数据流分析法 (注入类漏洞)

> **核心公式**: Source → [无净化] → Sink = 注入类漏洞
> **工具**: gosec 静态扫描

### B1. Go Source

```go
// net/http
r.URL.Query().Get("name")
r.FormValue("name")
r.Header.Get("X-Header")
r.Cookie("session")

// Gin
c.Query("name")
c.PostForm("name")
c.Param("id")
c.GetHeader("X-Header")
```

### B2. Go Sink

| Sink类型 | 漏洞 | Gosec规则 | 危险函数 |
|----------|------|-----------|----------|
| SQL执行 | SQL注入 | G201/G202 | db.Query(sql), fmt.Sprintf |
| 命令执行 | 命令注入 | G204 | exec.Command("sh", "-c", cmd) |
| 文件操作 | 路径遍历 | G304 | os.Open(userPath) |
| HTTP请求 | SSRF | G107 | http.Get(userURL) |
---

## Gosec 规则参考

> gosec 通过扫描 Go AST 检测安全问题，规则与 CWE 映射

### G1xx - 凭据与敏感信息

| 规则 | 描述 | CWE |
|------|------|-----|
| G101 | 硬编码凭据 (password, secret, token) | CWE-798 |
| G102 | 绑定到所有接口 (0.0.0.0) | CWE-200 |
| G103 | unsafe 包使用审计 | CWE-242 |
| G104 | 未检查的错误返回值 | CWE-703 |
| G106 | ssh.InsecureIgnoreHostKey 使用 | CWE-322 |
| G107 | HTTP请求中的污点URL输入 | CWE-88 |
| G108 | pprof端点自动暴露 (/debug/pprof) | CWE-200 |
| G109 | strconv.Atoi 转 int16/32 整数溢出 | CWE-190 |
| G110 | 解压缩炸弹 DoS | CWE-409 |

### G2xx - 注入类

| 规则 | 描述 | CWE |
|------|------|-----|
| G201 | fmt.Sprintf 构造SQL | CWE-89 |
| G202 | 字符串拼接构造SQL | CWE-89 |
| G203 | HTML模板未转义数据 | CWE-79 |
| G204 | 命令执行审计 | CWE-78 |

### G3xx - 文件与路径

| 规则 | 描述 | CWE |
|------|------|-----|
| G301 | 创建目录权限过大 (>0750) | CWE-276 |
| G302 | chmod权限过大 | CWE-276 |
| G303 | 可预测路径创建临时文件 | CWE-377 |
| G304 | 文件路径污点输入 | CWE-22 |
| G305 | Zip解压路径遍历 (Zip Slip) | CWE-22 |
| G306 | 写文件权限过大 | CWE-276 |

### G4xx - 加密相关

| 规则 | 描述 | CWE |
|------|------|-----|
| G401 | 使用 DES/RC4/MD5 | CWE-326 |
| G402 | 不安全的TLS配置 | CWE-295 |
| G403 | RSA密钥 < 2048位 | CWE-326 |
| G404 | 使用 math/rand (弱随机) | CWE-338 |

### G5xx - 导入黑名单

| 规则 | 描述 |
|------|------|
| G501 | 导入 crypto/md5 |
| G502 | 导入 crypto/des |
| G503 | 导入 crypto/rc4 |
| G504 | 导入 net/http/cgi |
---

## 并发安全 (Race Conditions)

### 1. Data Race

```go
// 危险: 并发读写 map
var cache = make(map[string]string)

func GetCache(key string) string {
    return cache[key]  // 并发读
}

func SetCache(key, value string) {
    cache[key] = value  // 并发写 - DATA RACE!
}
```

### 2. Channel 竞态

```go
// 危险: channel 关闭后发送
func worker(ch chan int) {
    for i := 0; i < 10; i++ {
        ch <- i
    }
    close(ch)
}

func main() {
    ch := make(chan int)
    go worker(ch)
    go func() {
        ch <- 100  // panic: send on closed channel
    }()
}
```

### 3. Read-Modify-Write 竞态

```go
// 危险: 非原子计数
var counter int

func increment() {
    counter++  // 非原子操作: 读取 → 加1 → 写入
}
```

### 4. 检查-使用竞态 (TOCTOU)

```go
// 危险: 检查后使用
func processFile(path string) error {
    if _, err := os.Stat(path); os.IsNotExist(err) {
        return err
    }
    // 竞态窗口: 文件可能在检查后被删除或替换
    return os.Remove(path)
}
```

### 5. Race Detector

```bash
go build -race ./...
go test -race ./...
go run -race main.go
```
---

## Go特定漏洞

### 1. 命令执行 (G204)

```go
// 危险: 用户输入拼接到shell
cmd := exec.Command("sh", "-c", userInput)  // RCE!
cmd.Run()

// 危险: 动态命令名
cmd := exec.Command(userCmd, userArgs...)  // RCE!

// 危险: 从cookie/header获取命令参数
cookie, _ := r.Cookie("cmd")
exec.Command("sh", "-c", cookie.Value)  // RCE!

// 搜索模式
exec\.Command|exec\.CommandContext|syscall\.Exec
syscall\.Exec|syscall\.ForkExec
```

### 2. SQL注入 (G201/G202)

```go
// 危险: fmt.Sprintf拼接 (G201)
query := fmt.Sprintf("SELECT * FROM users WHERE id = %s", userID)
db.Query(query)  // SQLi!

// 危险: 字符串拼接 (G202)
db.Query("SELECT * FROM users WHERE name = '" + name + "'")

// 危险: ORDER BY/LIMIT动态拼接
query := fmt.Sprintf("SELECT * FROM users ORDER BY %s", sortColumn)

// GORM原生SQL
db.Raw("SELECT * FROM users WHERE id = " + id)  // 危险!

// Sqlx命名查询
db.NamedQuery("SELECT * FROM users WHERE name = " + name)  // 危险!

// 搜索模式
fmt\.Sprintf.*SELECT|fmt\.Sprintf.*INSERT|fmt\.Sprintf.*UPDATE|fmt\.Sprintf.*DELETE
db\.Query.*\+|db\.Exec.*\+|db\.Raw\(.*\+
```

#### GORM 特定危险模式

```go
// 危险: Raw 拼接
db.Raw("SELECT * FROM users WHERE name = '" + name + "'").Scan(&users)

// 危险: Where 字符串拼接
db.Where("name = '" + name + "'").Find(&users)

// 检测规则
\.Raw\s*\([^?]*\+
\.Where\s*\("[^"]*'\s*\+
\.Order\s*\([^)]*\+
```
### 3. 模板注入 (G203)

```go
// 危险: 用户输入作为模板内容
tmpl := template.New("test")
tmpl, _ = tmpl.Parse(userInput)  // SSTI!
tmpl.Execute(w, data)

// 危险: text/template (无自动转义)
import "text/template"  // 比html/template更危险

// 危险: html/template禁用转义
template.HTML(userInput)  // XSS!
template.JS(userInput)    // XSS!
template.CSS(userInput)   // XSS!

// 搜索模式
template\.New.*Parse\(|text/template
template\.HTML\(|template\.JS\(|template\.CSS\(
```

### 4. SSRF (G107)

```go
// 危险: 用户可控URL
url := req.FormValue("url")
resp, _ := http.Get(url)  // SSRF!

// 危险: 未验证的重定向跟随
client := &http.Client{}  // 默认跟随重定向
resp, _ := client.Get(userURL)

// 危险: net.Dial可控
conn, _ := net.Dial("tcp", userHost+":"+userPort)

// 需要防护的协议: file://, gopher://, dict://, ftp://

// 搜索模式
http\.Get\(|http\.Post\(|http\.Do\(|http\.NewRequest
net\.Dial|net\.DialTimeout|net\.DialTCP
```

### 5. 路径遍历 (G304/G305)

```go
// 危险: filepath.Join不能防止路径遍历!
filePath := filepath.Join("/uploads", userFilename)
// filepath.Join("/uploads", "../../etc/passwd") = "/etc/passwd"

// 危险: Zip解压路径遍历 (Zip Slip) (G305)
func extractZip(zipPath, destDir string) {
    r, _ := zip.OpenReader(zipPath)
    for _, f := range r.File {
        path := filepath.Join(destDir, f.Name)  // 可能逃逸!
        // f.Name 可能是 "../../../etc/cron.d/malicious"
    }
}

// 搜索模式
filepath\.Join|os\.Open|ioutil\.ReadFile|os\.ReadFile|os\.Create
zip\.OpenReader|archive/zip|archive/tar
```
### 6. 整数溢出 (G109)

```go
// 危险: strconv.Atoi结果转小类型
input := req.FormValue("size")
size, _ := strconv.Atoi(input)
smallSize := int16(size)  // 溢出! 65536 -> 0

// 危险: 乘法溢出导致小分配
count, _ := strconv.Atoi(userInput)
buf := make([]byte, count*elementSize)  // count很大时溢出

// 搜索模式
strconv\.Atoi.*int16|strconv\.Atoi.*int32
```

### 7. 弱随机数 (G404)

```go
// 危险: math/rand用于安全场景
import "math/rand"
token := rand.Int()  // 可预测!
rand.Seed(time.Now().UnixNano())  // 种子可猜测

// 搜索模式
"math/rand"|rand\.Int|rand\.Intn|rand\.Seed
```

### 8. unsafe 包滥用 (G103)

```go
// 危险: unsafe.Pointer转换
ptr := unsafe.Pointer(&data)
uptr := uintptr(ptr)  // GC可能在此期间移动对象
newPtr := unsafe.Pointer(uptr)  // 可能指向无效内存!

// 危险: 与syscall配合
syscall.Syscall(SYS_XXX, uintptr(unsafe.Pointer(&buf)), ...)

// 危险: 任意内存访问
func readMemory(addr uintptr, size int) []byte {
    return (*[1 << 30]byte)(unsafe.Pointer(addr))[:size]
}

// 危险: 类型转换绕过
func bypassTypeSystem(i int) *string {
    return (*string)(unsafe.Pointer(&i))
}

// 危险: 修改不可变数据
func modifyString(s string) {
    sh := (*reflect.StringHeader)(unsafe.Pointer(&s))
    data := (*[1 << 30]byte)(unsafe.Pointer(sh.Data))[:sh.Len]
    data[0] = 'X'  // 危险!
}

// 搜索模式
unsafe\.Pointer|uintptr\(unsafe
import\s+"unsafe"
unsafe\.Sizeof|unsafe\.Offsetof|unsafe\.Alignof
```
### 9. cgo 安全

```go
/*
#include <stdlib.h>
#include <string.h>

void vulnerable_copy(char* dst, char* src, int len) {
    memcpy(dst, src, len);  // 可能越界
}
*/
import "C"
import "unsafe"

// 危险: 缓冲区溢出
func copyData(dst, src []byte) {
    C.vulnerable_copy(
        (*C.char)(unsafe.Pointer(&dst[0])),
        (*C.char)(unsafe.Pointer(&src[0])),
        C.int(len(src)),  // 如果 src > dst，溢出
    )
}

// 危险: 悬挂指针
func dangling() *C.char {
    s := "hello"
    cs := C.CString(s)
    // 忘记 C.free(unsafe.Pointer(cs))
    return cs  // 返回后 Go 字符串可能被回收
}

// 检测规则
import\s+"C"
/\*.*#include.*\*/
C\.[A-Za-z]+\(
C\.CString\([^)]+\)(?!.*C\.free)
C\.malloc\(
unsafe\.Pointer.*C\.
```

### 10. Goroutine泄漏

```go
// 危险: 无缓冲channel阻塞
func leak() {
    ch := make(chan int)
    go func() {
        result := doWork()
        ch <- result  // 如果没人接收，永久阻塞!
    }()

    select {
    case <-time.After(time.Second):
        return  // 超时返回，goroutine泄漏
    case r := <-ch:
        return r
    }
}

// 搜索模式
make\(chan.*\)|go func\(
```
### 11. pprof暴露 (G108)

```go
// 危险: 导入pprof自动注册路由
import _ "net/http/pprof"  // 自动暴露 /debug/pprof

// 可能泄露:
// /debug/pprof/heap     - 内存信息
// /debug/pprof/goroutine - 协程栈
// /debug/pprof/cmdline  - 命令行参数

// 搜索模式
net/http/pprof|/debug/pprof
```

### 12. SSH不安全配置 (G106)

```go
// 危险: 忽略主机密钥验证
config := &ssh.ClientConfig{
    HostKeyCallback: ssh.InsecureIgnoreHostKey(),  // 中间人攻击!
}

// 搜索模式
InsecureIgnoreHostKey
```

### 13. 解压缩炸弹 (G110)

```go
// 危险: 未限制解压大小
gzReader, _ := gzip.NewReader(r.Body)
io.Copy(w, gzReader)  // 1KB压缩 -> 1GB解压 = DoS

// 搜索模式
gzip\.NewReader|zlib\.NewReader|flate\.NewReader
```

### 14. IPv6地址处理

```go
// 危险: IPv6地址端口拼接
addr := fmt.Sprintf("%s:%s", host, port)  // IPv6错误!
// "::1:8080" 解析错误

// 搜索模式
fmt\.Sprintf.*%s:%s.*host|fmt\.Sprintf.*%s:%d.*host
```

### 15. 控制字符注入

```go
// 危险: 日志注入
log.Printf("User: %s", userInput)  // 可能注入\r\n伪造日志

// 搜索模式
log\.Printf.*%s|fmt\.Printf.*%s
```

### 16. JWT/认证

```go
// 危险: 弱密钥
var jwtKey = []byte("secret")  // 弱!

// 危险: 不验证签名算法
token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
    return jwtKey, nil  // 未验证alg，可能被none算法绕过
})

// 搜索模式
jwt\.Parse|jwt\.ParseWithClaims
jwtKey|secretKey|signingKey
```
### 17. CORS配置

```go
// Gin框架 - 危险配置
r.Use(cors.New(cors.Config{
    AllowOrigins:     []string{"*"},  // 允许所有来源
    AllowCredentials: true,           // 与*同时使用危险!
}))

// 危险: 反射Origin
r.Use(cors.New(cors.Config{
    AllowOriginFunc: func(origin string) bool {
        return true  // 反射任意来源
    },
    AllowCredentials: true,
}))

// 搜索模式
AllowOrigins|AllowAllOrigins|AllowCredentials|AllowOriginFunc
Access-Control-Allow-Origin
```

### 18. CSRF (CWE-352)

```go
// 危险: Gin - 无 CSRF 保护
r := gin.Default()
r.POST("/api/transfer", func(c *gin.Context) {
    var req TransferRequest
    c.BindJSON(&req)
    transfer(req.To, req.Amount)  // 状态变更操作无 CSRF 保护
})

// 检测命令
rg -n '\.(POST|PUT|DELETE|PATCH)\(' --glob "*.go"
rg -n "csrf|CSRF" --glob "*.go" || echo "No CSRF protection found"
```

### 19. 文件上传 (CWE-434)

```go
// 危险: 无验证的文件上传
func uploadHandler(c *gin.Context) {
    file, _ := c.FormFile("file")
    c.SaveUploadedFile(file, "/uploads/"+file.Filename)  // 路径遍历 + 任意类型
}

// 检测命令
rg -n "FormFile|SaveUploadedFile|MultipartForm" --glob "*.go"
rg -A10 "FormFile" --glob "*.go" | grep -v "filetype\|MIME\|extension"
```

---

## Web 框架特定漏洞

### Gin

```go
// 危险: 信任代理头
r := gin.Default()
// 默认信任所有代理头，可能导致 IP 欺骗

// 危险: 模板注入
r.GET("/hello", func(c *gin.Context) {
    name := c.Query("name")
    c.HTML(http.StatusOK, "index.tmpl", gin.H{
        "content": template.HTML(name),  // 未转义
    })
})
```

### Echo

```go
// 危险: 绑定攻击 (Mass Assignment)
type User struct {
    Name  string `json:"name"`
    Admin bool   `json:"admin"`
}

e.POST("/user", func(c echo.Context) error {
    u := new(User)
    c.Bind(u)  // 用户可设置 Admin=true
})
```
---

## 授权漏洞检测 (Authorization Gap)

> 授权漏洞是"代码缺失"，grep 无法检测"应该有但没有"的代码
> 授权矩阵方法 - 从"应该是什么"出发，而非"存在什么"

### Gin 框架授权检测

```bash
# 步骤1: 找到所有敏感路由
grep -rn "\.DELETE\|\.PUT\|\.PATCH" --include="*.go"
grep -rn "func.*Delete\|func.*Update\|func.*Remove" --include="*.go"

# 步骤2: 检查路由组是否有认证中间件
grep -rn "\.Group" --include="*.go" -A 5 | grep -E "AuthMiddleware|JWTAuth|RequireAuth"

# 步骤3: 检查具体handler是否有权限检查
grep -rn "func.*Delete" --include="*.go" -A 20 | grep -E "userID|ownerID|CheckPermission|Authorize"
```

### 漏洞模式

```go
// 漏洞: delete handler 缺失权限检查
func DeleteFile(c *gin.Context) {
    fileID := c.Param("id")
    db.Delete(&File{}, fileID)  // 未检查用户是否有权删除
    c.JSON(200, gin.H{"status": "deleted"})
}

// 漏洞: 有认证但无授权 (水平越权)
func DeleteFile(c *gin.Context) {
    fileID := c.Param("id")
    userID := c.GetInt("userID")
    // 只验证登录，未验证是否是文件所有者
    db.Delete(&File{}, fileID)  // 可删除他人文件!
}
```

### Echo 框架授权检测

```bash
grep -rn "\.DELETE\|\.PUT\|\.PATCH" --include="*.go"
grep -rn "e\.Use\|g\.Use" --include="*.go" -A 2 | grep -E "middleware\.|JWT|Auth"
```

### 漏洞模式 (Echo)

```go
// 漏洞: 路由组有认证但无细粒度授权
api := e.Group("/api", middleware.JWT([]byte("secret")))
api.DELETE("/users/:id", deleteUser)  // 任何登录用户都可删除任何用户!
```

### Fiber 框架授权检测

```bash
grep -rn "\.Delete\|\.Put\|\.Patch" --include="*.go"
grep -rn "app\.Use\|group\.Use" --include="*.go" -A 2
```
### 授权一致性检测脚本

```bash
#!/bin/bash
echo "=== Go 授权一致性检测 ==="
GO_FILES=$(find . -name "*.go" -type f)

for gofile in $GO_FILES; do
    DELETE_ROUTES=$(grep -n "\.DELETE\|\.Delete" "$gofile" 2>/dev/null)
    PUT_ROUTES=$(grep -n "\.PUT\|\.Put" "$gofile" 2>/dev/null)

    if [ -n "$DELETE_ROUTES" ] || [ -n "$PUT_ROUTES" ]; then
        echo ""
        echo "检查: $gofile"
        AUTH_MIDDLEWARE=$(grep -c "AuthMiddleware\|JWTMiddleware\|RequireAuth\|middleware\.JWT" "$gofile")
        if [ "$AUTH_MIDDLEWARE" -eq 0 ]; then
            echo "  WARNING: 文件中有敏感路由但未发现认证中间件"
        fi
        echo "$DELETE_ROUTES" | while read line; do
            if [ -n "$line" ]; then
                handler=$(echo "$line" | grep -o "[A-Za-z]*Delete[A-Za-z]*\|delete[A-Za-z]*")
                if [ -n "$handler" ]; then
                    has_owner_check=$(grep -A 30 "func.*$handler" "$gofile" | grep -c "owner_id\|OwnerID\|user_id.*=\|UserID.*=")
                    if [ "$has_owner_check" -eq 0 ]; then
                        echo "  WARNING: $handler: 可能缺少资源所有权验证"
                    fi
                fi
            fi
        done
    fi
done
```

### 间接SSRF检测 (配置驱动)

```go
// 漏洞: 配置驱动的间接SSRF
type Config struct {
    APIBaseURL string `yaml:"api_base_url"`
}

func FetchData(cfg *Config, endpoint string) ([]byte, error) {
    url := cfg.APIBaseURL + endpoint  // 间接SSRF
    resp, err := http.Get(url)
}

// 检测命令
grep -rn "viper\.Get.*URL\|viper\.Get.*Host\|config\.\w*URL" --include="*.go"
grep -rn "os\.Getenv.*URL\|os\.Getenv.*HOST" --include="*.go"
grep -rn "fmt\.Sprintf.*%s.*http\|fmt\.Sprintf.*http.*%s" --include="*.go"
```
---

## 审计正则

```regex
# 命令执行 (G204)
exec\.Command|exec\.CommandContext|syscall\.Exec|syscall\.ForkExec

# SQL注入 (G201/G202)
fmt\.Sprintf.*(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)
db\.(Query|Exec|Raw)\s*\([^)]*\+
NamedQuery\s*\([^)]*\+
\.Raw\s*\([^?]*\+
\.Where\s*\("[^"]*'\s*\+
\.Order\s*\([^)]*\+

# 模板注入 (G203)
template\.New.*Parse\(|text/template
template\.(HTML|JS|CSS)\s*\(

# SSRF (G107)
http\.(Get|Post|Do|NewRequest)\s*\(
net\.(Dial|DialTimeout|DialTCP)\s*\(

# 路径遍历 (G304/G305)
filepath\.Join|os\.(Open|Create|ReadFile)|ioutil\.ReadFile
zip\.OpenReader|archive/(zip|tar)

# 整数溢出 (G109)
strconv\.Atoi.*int(8|16|32)

# 弱随机 (G404)
"math/rand"|rand\.(Int|Intn|Seed)

# 硬编码凭据 (G101)
(password|passwd|secret|token|apikey|api_key)\s*[:=]\s*["'][^"']+["']

# pprof暴露 (G108)
net/http/pprof|/debug/pprof

# SSH不安全 (G106)
InsecureIgnoreHostKey

# unsafe使用 (G103)
unsafe\.Pointer|uintptr\(unsafe
import\s+"unsafe"

# cgo使用
import\s+"C"
C\.CString\([^)]+\)(?!.*C\.free)
C\.malloc\(

# 解压缩 (G110)
gzip\.NewReader|zlib\.NewReader|flate\.NewReader

# 并发竞态
make\(chan|go func\(
```

---

## 审计工具

```bash
# Gosec
gosec ./...
gosec -severity medium ./...
gosec -include=G101,G201,G204 ./...
gosec -fmt=json -out=results.json ./...

# 其他工具
go vet ./...
staticcheck ./...
golangci-lint run

# 竞态检测
go build -race ./...
go test -race ./...

# CodeQL
codeql database create ./codeql_database -s /path/to/go/project --language=go
codeql database analyze ./codeql_database codeql/go-queries --format=sarif-latest --output=results.sarif
```

---

## 最小 PoC 示例

```bash
# SSRF
curl "http://localhost:8080/fetch?url=http://169.254.169.254/latest/meta-data/"

# 路径遍历
curl "http://localhost:8080/download?file=../../etc/passwd"

# 命令注入
curl "http://localhost:8080/ping?host=google.com;id"

# -race 并发检测
go test -race ./...
```

---

- [gosec GitHub](https://github.com/securego/gosec)
- [Go安全最佳实践](https://go.dev/doc/security)
- [OWASP Go安全指南](https://owasp.org/www-project-web-security-testing-guide/)
