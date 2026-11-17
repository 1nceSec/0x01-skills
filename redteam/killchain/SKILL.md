---
name: killchain
version: 2.2
description: 红队评估/红队/攻防演练/red team/红蓝对抗：Kill Chain 三路径（外网Web RCE+内网AD域控+云原生K8s）；Web按RCE向量优先级表驱动、含悬空桶接管；K8s：管理面暴露→偷token→Pod立足→特权逃逸→横向；主Agent战术决策+Worker执行。
when_to_use: 红队评估/红队/攻防演练/red team/红蓝对抗
triggers:
  - 红队评估
  - 红队
  - 攻防演练
  - red team
  - 红蓝对抗
inputs_required:
  - target: 目标范围描述（IP段/域名/组织名）
inputs_optional:
  - scope_file: 授权范围文件路径
  - initial_access: 已有的初始立足点（如webshell/VPN凭证）
  - credentials: 已获取的凭证列表
  - rules_of_engagement: 行动规则（禁止操作/时间窗口/告警阈值）
---
> 开工前先跑 pentest-flow Phase 0-0 自检。

# 红队评估 Skill v2.2 — Kill Chain 阶段制编排器

> 与渗透测试的核心区别：红队是**目标导向**（拿到域控/核心数据/业务控制权），
> 不是覆盖导向（OWASP每项都测）。路径最短化，非必要不横向扩面。

## Phase 0-0: 输入路由

| 输入类型 | 判断依据 | 执行路径 |
|---|---|---|
| **SRC链接/组织名** | URL含SRC/安全应急特征，或纯文本组织名 | → `recon/src-asset/SKILL.md`（Read） → `recon/asset-triage/SKILL.md`（Read） → P0目标作为Stage 2突破口 → Phase 0-A |
| **原始资产表** | 用户提供域名/IP/指纹表等未经精判的资产列表 | → `recon/asset-triage/SKILL.md`（Read） → P0目标作为Stage 2突破口 → Phase 0-A |
| **脆弱资产表/打点清单** | 用户说"从打点清单继续"或提供asset-triage产出/已标注P0-P3的资产 | → P0目标作为Stage 2突破口 → Phase 0-A |
| **指定目标** | IP/CIDR/域名/已有立足点 | → 直接 Phase 0-A |

## Phase 0-A: 工具确认（必须首先执行，不得跳过）

```
AskUserQuestion({
  questions: [
    {
      header: "Burp代理",
      question: "是否使用 Burp 代理？",
      multiSelect: false,
      options: [
        { label: "不使用 (Default)", description: "默认不调用Burp，curl直连发包；任务中途需要时明确说启用即可切换" },
        { label: "使用 Burp", description: "replay.py主力 + curl -x proxy辅助，流量过Burp HTTP History" }
      ]
    },
    {
      header: "Playwright",
      question: "是否使用 Playwright 浏览器？",
      multiSelect: false,
      options: [
        { label: "不使用 (Default)", description: "默认纯命令行测试，不启动浏览器；任务中途需要时明确说启用即可切换" },
        { label: "使用 Playwright", description: "playwright-ext自动化浏览、功能遍历、JS审计" }
      ]
    },
    {
      header: "测试账号",
      question: "是否有登录测试账号？",
      multiSelect: false,
      options: [
        { label: "无测试账号 (Default)", description: "默认未授权视角测试，优先未授权方向；账号后续提供" },
        { label: "有测试账号", description: "有登录凭证，需要提供Cookie或账号密码" }
      ]
    }
  ]
})
```

结果写入 redteam-blackboard.json `meta.tools`。**默认不调用**：选"不使用"的工具默认全程不调用（含Worker），但**不是硬禁用**——任务中途用户明确要求启用时，更新 `meta.tools` 后即可调用；hook 检测到"标记不使用+实际调用"时中断向用户确认，不静默放行也不静默拒绝。
**测试账号默认无**：优先未授权方向；任务中途用户提供账号/凭证时，写入黑板 `credentials` 并继续凭据链测试。

## 核心原则

1. **目标驱动**：一切行动服务于objectives[]中的目标，靶标=最高优先级，非必要不做额外覆盖
2. **得分驱动**：攻防演练的本质是拿分。按目标体系权重排序：critical > high > medium > bonus。高权重优先，累加分不放过
3. **源码先行**：W1识别技术栈后，立即评估源码获取可能性。有源码审计产出(Tier 0)优先于黑盒测试(Tier 1-3)
4. **阶段推进**：严格按Kill Chain阶段执行，每阶段有明确推进门
5. **OPSEC优先**：每个操作评估暴露风险；能用LotL就不上传工具，能内存执行就不落盘
6. **知识卡自动加载**：按当前阶段从 `knowledge-routing.yaml` 的 `killchain.phases` 加载
7. **黑板持久化**：`redteam-blackboard.json` 记录全局状态，跨阶段传递情报
8. **状态脚本**：`node shared/state/redteam-state.mjs <cmd>` 管理目标+资产+凭证+攻击路径+traces+摘要

## 阶段路由表

> **路径基准**：本表及全文所有 `shared/...` 相对路径均指 **skills 根目录**下的 `shared/`（位于 skills 根目录，即本 skill 目录**上两级** `../../shared/...`），不在本 skill 目录内。若按本 skill 目录内解析失败，必须改试 `../../shared/...`；仍找不到时明确报告，**禁止静默降级**为手写黑板或旧格式流程。

| 阶段 | 加载文件 | 触发条件 |
|------|----------|----------|
| 资产收集 | `recon/src-asset/SKILL.md`（Read） | Phase 0-0输入为SRC链接/组织名时触发 |
| 薄弱资产精判 | `recon/asset-triage/SKILL.md`（Read） | 资产收集完成后触发 |
| Bootstrap | `shared/playbooks/bootstrap.md` | 任务启动，Read一次（黑板用redteam-blackboard.json） |
| Kill Chain循环 | `playbooks/stages.md` | 每轮循环Read（三路径：Web W1-W4 / AD A1-A5 / K8s K1-K4 + 目标体系 + Reason-Act + OPSEC + 方向切换） |
| 源码审计委托 | `audit/code-audit/SKILL.md`（Read） | W1识别到可获取源码的框架/CMS/商业系统时触发，产出进findings作为W2 Tier 0 |
| Web突破委托 | `core/pentest-flow/SKILL.md`（Read） | W2止损后或 `redteam-state.mjs path next` 返回 `delegate_pentest` 时触发，pentest只找入口（RCE/权限/数据），产出进findings |
| 桶接管向量 | `shared/knowledge/appsec/bucket-takeover-test.md` §9 | W1侦察发现OSS/COS/S3等云存储引用时按悬空桶检查（初始访问/供应链向量） |
| Web打点扩面 | `shared/knowledge/appsec/param-asymmetry-fuzz.md` | W1/W2 遇登录面/接口面时：隐藏参数+ORDER BY注入+鉴权绕过变体（分号矩阵/改方法/白名单路由）+actuator与框架字典——**国内外通用手法**，红队仅取利用面，不取SRC定级 |
| 初始凭据获取 | `shared/knowledge/appsec/logic-test.md` §六 + `wx-miniprogram-sessionkey-test.md` | W2 无弱口令突破口时：验证码族绕过/小程序三要素伪造=拿合法账号进内部系统（凭证链起点）；仅取手法，平台定级/一洞多交等SRC规则**不适用红队** |
| K8s知识卡 | `shared/knowledge/redteam/cloud/k8s-attack.md` | K1-K4各阶段加载（入口向量/逃逸检查表/收割清单/横向） |
| 攻击链管理 | `shared/playbooks/chain.md` | 发现可串联漏洞 / `chain next`返回非空 |
| 状态管理 | `shared/state/redteam-state.mjs` | CLI: `init` / `obj <add\|update\|list>` / `asset <add\|update\|list>` / `cred <add\|test\|list>` / `net <add\|list>` / `path <add\|show\|next>` / `persist add` / `stage <check\|advance>` / `score` / `summary` / `bb <merge\|observe\|plan\|log>` / `trace <write\|list\|search>` / `gate` |
| 阶段收口门禁 | `shared/state/redteam-state.mjs gate` | Stage切换前/Merge后/写报告前必跑：PASS才进下一Stage（含治理五项preflight硬阻断） |
| 公共表 | `shared/common-tables.md` | Bootstrap时加载（工具表+进站短表+打穿短表） |
| Worker模板 | `shared/worker-prompt-template.md` | Spawn Worker时填充变量注入 |
| 安全红线 | `shared/references/safety-boundaries.md` | 按需引用 |

## 黑板 Schema（精简）

`redteam-blackboard.json` 十一分区：
- `meta`：target_scope / roe / current_stage / tools / total_rounds / no_progress_streak / branch(web|ad|chained)
- `objectives`：目标树（category/weight/completion_criteria/evidence_required/status）—— 靶标=critical，集权系统=critical/high，按目标体系初始化
- `assets`：已控主机（hostname/ip/os/role/access_level/domain_joined）
- `credentials`：已获凭证（type/username/domain/value/source_asset/valid/tested_on）—— 过程资产，不计分但必须追踪
- `network`：已知网段（cidr/scanned/alive_hosts）—— 过程资产
- `attack_path`：攻击路径图（from→to，method，stage）
- `intents`：待执行任务（stage/description/status/priority/evidence_refs必填引用facts）
- `findings`：发现的漏洞/配置问题（加 `confidence: "confirmed"|"suspected"`）
- `scoreboard`：得分记录（每项含 objective_ref/category/weight/evidence/submitted）—— 每个成果立即写入，关联对应objective
- `source_intel`：源码情报（target_system/tech_stack/source_type/audit_status/findings_ref）—— 追踪靶标源码获取和审计状态
- `failure_records` + `persistence_points` + `decision_log`（decision_log加 `evidence_refs` 因果引用）

## 输出协议

每次输出末尾附状态标记（独占一行）：
```
STAGE: <w1-recon|w2-exploit|w3-deepen|w4-objective|a1-recon|a2-privesc|a3-lateral|a4-persist|a5-objective|k1-entry|k2-pod|k3-escape|k4-lateral>
STATUS: <running|stage_complete|blocked|need_input|objective_reached>
ASSET: <new_host|new_cred|new_path|new_data>|<detail>
```

## 安全红线

- 严格遵守 Rules of Engagement
- 不对未授权目标发起攻击
- 不实际破坏/删除数据
- 持久化操作需用户确认
- DCSync/域操作需用户确认
- 凭证记录在黑板，不在输出中裸露
> 详见 shared/references/safety-boundaries.md

## 终止条件

目标达成 | 所有路径穷尽 | 行动规则时间窗口结束 | 用户终止

## 报告 & 清理

用户说"写报告" → 触发 report-generator skill，基于 attack_path 生成攻击链报告
用户说"清理" → 按 persistence_points 逐项清除后门 → 确认完成

## 速查卡（每轮必读）

```
目标驱动不是覆盖驱动 | 靶标=最高优先级 | RCE/数据/权限优先 | XSS等低产出类型跳过
目标体系：靶标(critical) > 集权系统(critical/high) > 服务器/后台/数据库(high) > 内网主机(medium累加) > 加分项(bonus)
三路径：Web(W1-W4) / AD(A1-A5) / K8s(K1-K4) | 按目标环境自动路由 | Web打穿可切AD/K8s
Web分支：源码获取→审计(Tier 0) > RCE向量优先级表(Tier 1-3) | 悬空桶引用=初始访问向量(见bucket-takeover §9)
K8s分支：面板/API/kubelet暴露 → 偷token → exec业务Pod → 特权挂盘逃逸 → 宿主收割 → SSH横向
挂宿主盘必 -o ro | exec只选业务Pod不动系统组件 | Secret API可列举=凭据池
凭证+网络=过程资产，不计分但必须追踪，是路径推进的燃料
得分驱动：critical先拿，累加分不放过 | 每个成果立即采证入scoreboard关联objective
OPSEC优先 | 凭证立即入库 | 高危操作先确认
单向量≤5种bypass无突破→parked | 3轮无进展→方向切换
Worker发现一律pending | findings只有主Agent能写
每轮评估：阶段/目标达成/凭证/得分/下一步ROI/OPSEC风险
L3被拦×3→升级L5请求协助 | 跨session用auto-handoff
```

## 安全边界
遵循 E:/Agent/0x00_Governance/AGENTS.md（权威规则）+ shared/references/safety-boundaries.md。Worker prompt 必须逐条写入安全约束。
