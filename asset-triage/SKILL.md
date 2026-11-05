---
name: asset-triage
version: 1.0
description: 薄弱资产识别/资产精判/资产筛选/打点清单（asset triage）：输入资产表（SRC⑥大表/指纹表/URL清单），指纹识别→信号粗筛→主动验证→AI精判，输出 P0–P3 打点清单；漏洞挖掘与红队评估的公共前置阶段。
when_to_use: 薄弱资产/资产精判/资产筛选/asset triage/打点
triggers:
  - 薄弱资产
  - 资产精判
  - 资产筛选
  - asset triage
  - 打点
inputs_required:
  - asset_file: 资产表路径（xlsx/csv/txt，含URL列）
inputs_optional:
  - name: 项目名称（用于输出文件命名，默认'目标'）
---
> 开工前先跑 pentest-ai-driven Phase 0-0 自检。

# 薄弱资产识别 Skill v1.0

> 输入一张资产表，输出一份可直接用于渗透/红队的打点清单。

## 工具链

- **脚本目录**：`E:\Agent\Claude\AI驱动的薄弱资产识别\`
- **共享模块**：`common.py`（REG_KW/CLOSED_RX/LISTING_RX/load_reg_paths/check_hit，单源维护）
- **知识库**：`knowledge\weak_signals.yml` + `knowledge\register_paths.txt`
- **TscanPlus**：指纹识别（SRC⑤步已跑过则跳过）

## 管道流程

```
资产表(URL清单)
  ↓ 有指纹表则跳过
L1  run.py → tscan分块指纹识别 → triage.py离线粗筛
  ↓ 产出：指纹表.csv + 嫌疑资产初筛.csv + AI精判输入.json
L2  主动验证（五脚本，按场景选用）
    verify.py: 嫌疑资产验证（登录面注册+目录遍历，快速，先跑此脚本）
    scan.py: 统一扫描引擎（--mode basic=18条未授权+注册+遍历，--mode deep=43条全量，推荐替代sweep/sweep2）
    sweep.py: 全量扫描（遗留，scan.py --mode basic替代）
    sweep2.py: 深度补扫（遗留，scan.py --mode deep替代）
    regcheck.py: 注册专项（全字典49路径，嫌疑优先+金丝雀，可独立跑也可与scan并行）
  ↓ 产出：各验证结果.csv
L3  build_final.py → 三路合并 → 薄弱资产打点清单
  ↓ 产出：打点清单.csv/.md + 已验证URL.txt
L4  AI精判（Claude原生，基于ai_prompt.md逻辑）
    对P0-P1逐条核验：WebFetch验证+JS挖掘+组合研判
  ↓ 最终产出：薄弱资产打点清单.md（六类分类+P0-P3定级+渗透方向）
```

## 启动流程

### Step 0: 确认输入

```
AskUserQuestion({
  questions: [{
    header: "资产输入",
    question: "请确认输入资产的类型？",
    multiSelect: false,
    options: [
      { label: "SRC大表", description: "SRC资产收集工具包的⑥大表或⑤指纹表" },
      { label: "URL清单", description: "任意URL列表（xlsx/csv/txt）" }
    ]
  }]
})
```

- SRC大表且有⑤步指纹：`run.py --skip-tscan` 跳过tscan，直接triage
- 其他：从L1开始跑
- xlsx/txt输入：Step 0自动转csv（脚本只接受csv），xlsx用openpyxl读取首sheet
- `--skip-tscan` 是Skill流程控制参数（传给run.py），非验证脚本参数

### Step 1: L1 指纹+粗筛

```bash
cd "E:\Agent\Claude\AI驱动的薄弱资产识别"
# 完整流程（tscan + triage）
py -X utf8 run.py "{asset_file}"
# 有SRC⑤步已跑tscan的块JSON → 跳过tscan，直接解析+粗筛
py -X utf8 run.py "{asset_file}" --skip-tscan --json-dir "{json目录}"
```

可调参数：`--block 10`(每块URL数) `--pause 20`(块间暂停秒) `--workers 1`(并行数) `--proc-timeout 15`(单块超时分钟)

产出（输出目录下）：`{name}_指纹表.csv` + `{name}_嫌疑资产初筛.csv` + `{name}_AI精判输入.json`

### Step 2: L2 主动验证（后台并行）

```bash
# 基础验证（登录面注册扫描+目录遍历实测）
py -X utf8 verify.py "输出\{name}_指纹表.csv"
# 统一扫描（替代sweep+sweep2，--mode basic=18条未授权，--mode deep=43条全量）
py -X utf8 scan.py "输出\{name}_指纹表.csv" --mode basic
py -X utf8 scan.py "输出\{name}_指纹表.csv" --mode deep
# 遗留脚本（sweep.py/sweep2.py仍可用，scan.py为推荐替代）
# 注册专项（嫌疑优先+金丝雀防护）
py -X utf8 regcheck.py "输出\{name}_指纹表.csv"
# 405端点复核（等scan完成后跑）
py -X utf8 rescan405.py "输出\{name}_指纹表.csv"
```

各脚本通用参数：`--threads 12`(线程数) `--timeout 8`(超时秒)；verify/sweep/sweep2另有`--limit N`(调试用，只测前N行)。
verify + sweep + sweep2 + regcheck 可并行（后台运行），rescan405 等 sweep 完成后跑。
每个脚本有断点续跑机制（done.txt），中断后重跑自动跳过已完成项。

### Step 3: L3 合并

```bash
py -X utf8 build_final.py {name}
```

产出：`输出\{name}_薄弱资产打点清单.csv` + `输出\{name}_已验证URL.txt`

### Step 4: L4 AI精判（Claude原生执行）

读取 `输出\{name}_AI精判输入.json`，按 `ai_prompt.md` 的六类分类体系逐条精判：
1. **证据核验**：WebFetch验证指纹真实性
2. **可注册性判定**：②a明面/②b隐藏(JS路由挖掘)/②c侧信道
3. **未授权核验**：druid/actuator/nacos等路径实测
4. **定级**：P0(已确认暴露/RCE) → P1(有POC/可注册/测试环境) → P2(信息泄露) → P3(观察)
5. **渗透方向+首个验证动作**

输出写入 `输出\{name}_薄弱资产打点清单.md`

## 与下游Skill联动

### → vuln-hunting
打点清单按P0→P1排序，逐个作为 vuln-hunting 的 target URL 输入。
P0/P1的渗透方向直接转化为 vuln-hunting 的初始 Intent。

### → red-team
P0目标作为 red-team Stage 2 的候选突破口。
打点清单中的技术栈/版本信息传递为先验知识。

## 硬规则

- **只做识别与GET级验证**：不利用漏洞、不注册账号、不发POST（除非用户指示）
- **每条判定必须引用证据**：无证据只能标【待确认】
- **403不丢弃**：标注"绕过候选"；**403但有favicon图标** → 大概率存在Web系统（纯拒绝页无图标），优先级提升为打点候选，首个验证动作=目录字典扫描找登录页
- **单批≤50条**：AI精判超50条分批处理
- 遵守 CLAUDE.md §3 上下文控制规范

## 输出格式

最终交付（4种格式同时生成）：
- `输出\{name}_薄弱资产打点清单.md` — 人读报告
- `输出\{name}_薄弱资产打点清单.csv` — 机器可读
- `输出\{name}_薄弱资产打点清单.xlsx` — P0红/P1橙/P2黄色标，带自动筛选
- `输出\{name}_薄弱资产打点清单.txt` — 纯URL列表（已验证可达）

报告结构：
- 一、逐条判定表（URL/产品/类别/优先级/证据/渗透方向/首个验证动作）
- 二、P0/P1清单（按战果预期排序）
- 三、Top5立即验证动作
- 四、知识库修正建议

对话回报：文件路径 + 各优先级条数 + P0/P1摘要。
