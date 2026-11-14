---
name: arsenal
version: 1.0
description: 免杀/Loader/shellcode/进程注入/C2/Webshell 武器开发（evasion/bypass）：构建攻击工具、输出完整可编译代码，非对目标测试。红队武器库建设场景使用。
when_to_use: 免杀/Loader/shellcode/进程注入/武器开发/evasion/bypass/C2/webshell
triggers:
  - 免杀
  - Loader
  - shellcode
  - 进程注入
  - 武器开发
  - evasion
  - bypass
  - C2
  - webshell
inputs_required:
  - task: 具体构建任务描述（如"写一个AES加密的Shellcode Loader"）
inputs_optional:
  - target_edr: 目标EDR/AV产品（如"360/火绒/Defender/卡巴"）
  - shellcode_source: Shellcode来源（如"CS raw / MSF / custom"）
  - constraints: 约束条件（如"不能用VirtualAlloc/必须<100KB/纯C"）
---
> 开工前先跑 pentest-flow Phase 0-0 自检。

# 红队武器开发 Skill v1.0

> 与其他skill的核心区别：不是测试目标系统，而是**构建攻击工具**。
> 输出物是可编译的源代码，不是漏洞报告。

## 核心原则

1. **完整可用**：输出的代码必须能编译运行，不是伪代码或片段
2. **知识卡驱动**：按任务类型加载 `redteam/arsenal/*` 知识卡作为技术参考
3. **分层构建**：Loader = 加密层 + 存储层 + 执行层 + 反检测层，逐层实现
4. **测试验证**：写完后给出编译命令和测试方法

## 知识卡加载

触发时按 `knowledge-routing.yaml` 的 `arsenal.phases.build` 加载：
- `redteam/arsenal/evasion.md` — 免杀与EDR绕过技术速查
- `redteam/arsenal/loader-design.md` — Shellcode加载器设计速查
- `redteam/arsenal/process-injection.md` — 进程注入技术速查

## 执行流程

### Step 1: 需求分析

解析用户任务，确定：
- **武器类型**：Loader / 注入器 / C2 implant / WebShell / 工具
- **目标环境**：Windows版本 / 目标EDR / 架构(x64/x86)
- **约束条件**：大小限制 / 语言限制 / 不能用的API
- **Shellcode来源**：CS / MSF / 自定义

### Step 2: 技术选型

根据知识卡选择最合适的技术组合：

**Loader构建清单**：
| 层 | 选项 | 默认 |
|----|------|------|
| 加密 | XOR / AES / RC4 | AES |
| 存储 | 硬编码 / 资源段 / 远程拉取 | 资源段 |
| 内存分配 | VirtualAlloc / NtAllocateVirtualMemory / Mapping | Syscall直调 |
| 执行 | CreateThread / Callback / Fiber / APC | Callback |
| 反检测 | 沙箱检测 / ETW patch / AMSI bypass / 堆栈欺骗 | 按需组合 |

**注入器构建清单**：
| 类型 | 适用场景 |
|------|---------|
| CreateRemoteThread | 最简单，易被检测 |
| APC注入 | 需要Alertable线程 |
| Early Bird | 新进程注入，较隐蔽 |
| Thread Hijack | 不创建新线程 |
| Process Hollowing | 替换进程，较隐蔽 |

### Step 3: 代码实现

分层逐步实现，每层写完确认编译通过后再加下一层：
1. 基础框架（main + 入口）
2. Shellcode加密/解密层
3. 内存分配+执行层
4. 反检测层（按需）
5. 整合+编译测试

**代码规范**：
- 默认C/C++（兼容MSVC和MinGW）
- 变量名/函数名不暴露意图（不叫shellcode/payload/inject）
- 字符串加密（编译时或运行时）
- 注释最小化

### Step 4: 编译与测试

给出完整编译命令：
```
# MSVC
cl.exe /O2 /MT loader.c /Fe:loader.exe

# MinGW
x86_64-w64-mingw32-gcc loader.c -o loader.exe -luser32 -lkernel32 -s
```

测试方法（不自动执行，由用户决定）：
- 静态：`sigcheck.exe -nobanner loader.exe` + 本地沙箱
- 动态：虚拟机运行，ProcessHacker检查内存RWX区域
- 编译失败 → 检查报错 → 修改 → 重新编译，循环直到通过

---

## 常见任务模板

### 模板1: AES Shellcode Loader
加密层: AES-CBC + 随机IV
存储层: 资源段嵌入
执行层: NtAllocateVirtualMemory(RW) → memcpy → NtProtectVirtualMemory(RX) → CreateThread callback
反检测: 沙箱时间检测 + AMSI patch

### 模板2: 远程Shellcode Loader
加密层: 传输AES，内存XOR轮转
存储层: HTTPS下载（WinHTTP/WinINet）
执行层: Fiber执行
反检测: 域名/IP白名单检测 + ETW patch

### 模板3: Process Hollowing注入器
目标进程: svchost.exe / RuntimeBroker.exe
流程: CreateProcess(SUSPENDED) → NtUnmapViewOfSection → 写入PE → 修复重定位 → ResumeThread

### 模板4: WebShell（按语言）
PHP: 加密一句话 + 自定义通信协议
JSP: 反射类加载 + AES通信
ASPX: 内存加载Assembly + 自定义Header触发

---

## 安全边界

仅供授权红队评估使用。测试用无害payload（calc / DNS查询）验证功能，用户自行决定实际部署。

## 速查卡

```
完整可编译代码 | 分层构建逐步验证 | 知识卡是技术菜单
RWX分离(RW→RX) | Syscall优先用户态API | 字符串必须加密
沙箱检测放最前 | Callback执行优于CreateThread | 变量名不暴露意图
```
