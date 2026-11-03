---
name: ctf-misc
description: 杂项：隐写术、流量分析、取证、编码识别
category: misc
---

## 特征识别
- 给了图片/音频/pcap/磁盘镜像/压缩包/奇怪编码文本

## 工具
`binwalk` `foremost` `steghide` `zsteg` `stegsolve` `tshark` `volatility` `CyberChef` `exiftool`

## 解题步骤

### 隐写术（图片/音频）
1. `file <img>` — 确认真实格式（扩展名可能骗人）
2. `exiftool <img>` — 元数据中找Comment/Description/Author
3. `strings <img> | grep -iE "flag|ctf"` — 速查尾部追加
4. `binwalk -e <img>` — 提取嵌入文件
5. PNG：`zsteg <img> -a` 检测LSB隐写 | CRC校验修复宽高
6. JPG：`steghide extract -sf <img> -p ""` 空密码 → 常见密码爆破
7. GIF：`convert <gif> -coalesce frame_%d.png` 逐帧分离对比
8. 音频：`sox <wav> -n spectrogram -o spec.png` 频谱图 / DTMF / SSTV

### 流量分析
9. `tshark -r <pcap> -T fields -e http.request.uri` — 提取HTTP请求
10. `tshark -r <pcap> -z follow,tcp,ascii,0` — 追踪TCP流
11. DNS隧道：`tshark -r <pcap> -T fields -e dns.qry.name | sort -u` → 拼子域名
12. ICMP隧道：`tshark -r <pcap> -Y icmp -T fields -e data` → hex解码
13. USB键盘：提取HID数据→映射键码→还原输入
14. 导出文件：`tshark -r <pcap> --export-objects http,./exported/`

### 取证
15. 磁盘：`foremost -i image.dd -o output/` | `autopsy`
16. 内存：`volatility -f mem.dmp imageinfo` → `pslist/filescan/dumpfiles/hashdump`
17. Windows注册表：`volatility printkey -K "Software\...\Run"` 自启动
18. 浏览器：`volatility chromehistory` | sqlite3查History/Login Data

### 编码识别
19. Base64(`=`结尾)/Base32(`====`)/Base16(纯hex) → `base64 -d`
20. 摩尔斯(`.-`)/培根(AB)/栅栏/凯撒 → CyberChef Magic自动识别
21. 二进制/八进制/hex → `python3 -c "print(bytes.fromhex('...'))"`
22. 多层套娃：逐层解Base64→Hex→ROT13→Base32
23. 零宽字符隐写(U+200B等)：专用Unicode隐写解码器

### 压缩包
24. 加密zip：`fcrackzip -u -D -p wordlist.txt file.zip` / `john --format=PKZIP hash`
25. 伪加密：zip文件头flag位 → `deFlags` 09→00（全局+本地都改）
26. 已知明文攻击：`bkcrack -C enc.zip -c known.txt -P plain.zip -p known.txt`
27. 嵌套压缩：`while file *.zip | grep -q Zip; do unzip -o *.zip; done`

### QR码/条形码
28. 破损QR码：补全定位图案（三个角的finder pattern）→ 在线解码
29. 多个QR碎片：拼接后扫描
30. 二维码版本信息：纠错等级/掩码模式逆向

### 文件格式修复
31. PNG：文件头 `89 50 4E 47 0D 0A 1A 0A` → CRC校验 → 修复IHDR宽高
32. ZIP：文件头 `50 4B 03 04` → 若缺失则补全
33. BMP/GIF：对比标准文件头，修复被篡改的magic bytes

## Flag位置
- 隐写提取物内容 / 流量中传输的明文 / 取证恢复的文件
- 压缩包内隐藏文件 / QR码内容 / 修复后文件的strings输出
