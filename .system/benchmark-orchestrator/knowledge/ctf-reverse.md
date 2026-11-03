---
name: ctf-reverse
description: 逆向工程通用流程：文件识别、反编译、动态调试、脱壳、VM逆向、约束求解
category: reverse
---

## 特征识别
- 给了ELF/PE/Mach-O二进制文件，或.pyc/.class/.apk/.wasm
- 题目关键词：reverse, crackme, keygen, 输入密码/序列号

## 工具
`file` `strings` `objdump` `readelf` `ghidra`(headless) `gdb` `ltrace/strace` `uncompyle6` `jadx` `upx -d` `checksec` `angr` `z3` `pwntools`

## 第一步：快速信息收集（必做，30秒内）
```bash
file <binary>
checksec --file=<binary>
strings -n 8 <binary> | grep -iE "flag|key|pass|correct|win|success|right|wrong"
strings -n 8 <binary> | grep -iE "http|\.php|\.py|base64|AES|RSA|xor"
readelf -h <binary> 2>/dev/null   # ELF: entry/架构/class
readelf -S <binary> 2>/dev/null | grep -i debug  # 有调试段=未strip
```

## 壳识别与脱壳
| 特征 | 壳类型 | 脱壳方法 |
|------|--------|---------|
| strings含"UPX!" | UPX | `upx -d <binary>` |
| entry在.text外(.UPX0/.UPX1) | UPX变种 | 修复magic后`upx -d`，或手动dump |
| 极少strings+高熵.text | 自定义壳 | gdb断OEP：`catch syscall mprotect` → dump |
| PE: IAT极少/TLS callback | 商业壳 | x64dbg断VirtualAlloc → 追踪写入→找OEP |

手动脱壳：
```bash
gdb ./packed -ex "catch syscall mprotect" -ex "r"
# 断在mprotect时检查参数，PROT_EXEC=代码段解密完成
# info proc mappings → dump可执行段
```

## 静态分析：关键函数定位策略
1. **从main开始**：`objdump -d <binary> | grep -A5 '<main>'`
2. **交叉引用法**：从strings中"Correct"/"Wrong"等提示反查引用函数
3. **ghidra headless反编译**：
```bash
analyzeHeadless /tmp/ghidra_proj proj -import <binary> \
  -postScript ExportDecompilation.java -scriptPath /path/to/scripts
```
4. **符号表恢复**：stripped用`nm -D`查动态符号；Go查`.gopclntab`
5. **导入表分析**：`objdump -T <binary> | grep -iE "strcmp|memcmp|crypt|rand"`

## 动态调试断点策略
```bash
# 断在比较函数
gdb -ex "b strcmp" -ex "b memcmp" -ex "b strncmp" -ex "r" --args ./binary AAAA
# 断下: x/s $rdi  x/s $rsi  查看比较双方

# 断在关键地址
gdb -ex "b *0x401234" -ex "r" --args ./binary AAAA
# 断下: info registers

# 条件断点
gdb -ex "b *0x401234 if $rax==1" -ex "r" --args ./binary AAAA

# 内存写入断点（自修改代码/解密场景）
gdb -ex "watch *0x603000" -ex "r" --args ./binary
```

## 常见算法识别与逆推
| 模式 | 算法 | 逆推方法 |
|------|------|---------|
| `input[i] ^ key[i%len]` | XOR加密 | 已知明文XOR密文得key |
| 逐字符线性变换 | 仿射/凯撒 | `(c - b) * inv(a) mod 256` |
| S-box查表 | AES/DES/自定义 | 提取S-box，识别标准常量(AES: 0x63) |
| 矩阵乘法 | Hill密码 | numpy求逆矩阵 |
| 大数modpow | RSA | 提取n,e → 分解n → 求d |
| 递归+memo | DP约束 | z3求解 |
| `rol`/`ror`+xor链 | 自定义hash | 逆序还原每一步 |

## 约束求解（Z3/angr）
适用：多条件分支校验、复杂数学变换、路径爆炸

```python
# Z3 模板
from z3 import *
inp = [BitVec(f'x{i}', 8) for i in range(32)]
s = Solver()
for i in range(32):
    s.add(inp[i] >= 0x20, inp[i] <= 0x7e)  # 可打印ASCII
# 加入反编译代码提取的约束
if s.check() == sat:
    m = s.model()
    print(''.join(chr(m[inp[i]].as_long()) for i in range(32)))
```

```python
# angr 自动求解模板
import angr
proj = angr.Project('./binary', auto_load_libs=False)
state = proj.factory.entry_state()
simgr = proj.factory.simulation_manager(state)
simgr.explore(find=0x401234, avoid=0x401300)  # find=success, avoid=fail
if simgr.found:
    print(simgr.found[0].posix.dumps(0))
```

## VM/虚拟机题专项流程
1. **识别dispatch loop**：`while(1){ switch(bytecode[pc]){ case 0: ... }}`
2. **提取opcode表**：每个case→虚拟指令，记录opcode值→操作→操作数个数
3. **dump字节码**：通常在.rodata或全局变量，`hexdump`提取
4. **写反汇编器**：
```python
opcodes = {0:"push",1:"pop",2:"add",3:"sub",4:"xor",5:"cmp",6:"jmp",7:"jnz",8:"read",9:"print"}
pc = 0
while pc < len(bytecode):
    op = bytecode[pc]
    print(f"{pc:04x}: {opcodes.get(op, f'unk_{op:02x}')}", end=" ")
    # 根据指令解析操作数...
```
5. **逆执行**：从比较结果倒推输入值

## 特殊语言逆向
| 语言 | 工具 | 命令 |
|------|------|------|
| Python .pyc | uncompyle6/pycdc | `uncompyle6 x.pyc > src.py` (≤3.8) / `pycdc x.pyc` (3.9+) |
| Java .class/.jar | jadx/javap | `jadx -d out x.jar` / `javap -c -p X.class` |
| Android .apk | jadx/apktool | `jadx -d out x.apk`，关注onCreate校验逻辑 |
| Go | strings+ghidra | `strings <bin> \| grep "main\."` 恢复函数名 |
| .NET | dnSpy/ILSpy | 直接反编译到C#；混淆先用de4dot |
| Rust | rustfilt | `rustfilt`还原mangled符号名 |

## Anti-Debug绕过（CTF场景）
```bash
# ptrace反调试：LD_PRELOAD hook
echo 'int ptrace(int a,int b,int c,int d){return 0;}' > fake.c
gcc -shared -o fake.so fake.c
LD_PRELOAD=./fake.so gdb ./binary

# 时间检测rdtsc：gdb中 set $rax=0
# /proc/self/status TracerPid：patch cmp为nop
```

## Flag位置
- 程序输出"Correct!"时的输入即为flag
- 硬编码在binary的.rodata/.data段
- 动态计算：断点在比较处从内存/寄存器读取
- 解密后的内存区域（需要在正确时机dump）
- 环境变量或命令行参数中
