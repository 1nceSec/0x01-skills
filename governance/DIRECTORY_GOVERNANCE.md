# 目录编号治理规则 v1.1（2026-11-10 DSH 修订稿，编号段与地面执行对齐）

> **修订记录**
> - v1.0（2026-11-09）：初版，经用户批准。
> - v1.1（2026-11-10）：编号分配段与 2026-11-10 双库命名终版 DECISION 及磁盘地面实况对齐；规则条款零改动；映射表路径随 0x0A→0x07 重编号同步修正。待 ZCode 会签后生效。
> - 会签状态：DSH ✅（本修订稿产出方）/ ZCode ⏳（会签中）

1. **每库（E:\Agent / E:\PenTest）顶层编号唯一**，格式 `0xNN_类型_名称`
2. **保留段**：`0x0F` = 归档（Historical）；`0xF8–0xFE` = 运行时常驻区（活进程回写地盘，明示非规划区，如 0xFE_RT_Document）
3. **运行区纪律**：程序一律不从数据树启动；发现回写壳→迁入 F 段或整改启动路径
4. **一切目录改动走映射表**（`E:\Agent\0x07_Documentation\MAPPING_*.csv`，含回滚命令）
5. **功能目录编号冻结**（0x09_Runtime 等被引用者不改号，宁留空位不破引用）

## 当前编号分配（2026-11-11 第四次实况同步——命名冻结前最后手工同步）

### E:\Agent（实况枚举）
0x00_Governance / 0x01_Skills / 0x02_Plugins / 0x03_Scripts / 0x04_Documentation / 0x05_Archive / 0x06_Runtime / 0x09_Runtime

### E:\PenTest（实况枚举）
0x00_Tmp / 0x01_Projects / 0x02_Tools / 0x03_Dicts / 0x04_RedTeam_Phishing / 0x05_Exploits / 0x06_Software / 0x07_Knowledge / 0x08_VulnEnv / 0x09_Templates
