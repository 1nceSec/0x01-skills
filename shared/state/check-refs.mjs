#!/usr/bin/env node
// check-refs.mjs — 技能库文档链接审计：扫描所有 .md 中的本地文件引用，报告无法解析的断链
// 用法：node shared/state/check-refs.mjs [--fix-report <file>]    （只读，不修改任何文件）
// 动机：shared/playbooks/loop.md 曾被 4 处引用而文件不存在，静默断链导致测试遗漏。
// 解析规则：引用依次尝试①相对引用所在文件目录 ②技能库根 ③<引用文件目录>/../../（域文件夹向上两级到根）④外部仓库根（EXTERNAL_BASES）⑤全库按 basename 兜底。
// 过滤：跳过 URL、代码围栏（```）内示例、模板占位符（含 { }）、已知运行时产物名单。
// ⚠️ 已知盲区（2026-11-15，使用时知悉）：
//   1. CLAUDE.md 等在 RUNTIME_NAMES 跳过名单中的文件名不会被校验（CLAUDE.md §x.x 章节号失效曾漏报，需人工核对）
//   2. ⑤basename 全库兜底会掩盖路径基准错误——文件存在但写错了目录也能通过（arsenal 知识卡前缀错误曾因此漏报）；修路径基准类 bug 时勿依赖本脚本通过与否
//   3. 示例数据/外部工具名（smuggler.py 等）按忽略名单跳过，若忽略名单过期需人工维护

import { readFileSync, readdirSync, statSync, existsSync } from 'fs';
import { join, dirname, basename, resolve } from 'path';
import { fileURLToPath } from 'url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const EXT_RE = /\.(md|mjs|py|yaml|yml|json)$/i;
const REF_RE = /[A-Za-z0-9_.\-/\\]+\.(?:md|mjs|py|yaml|yml|json)\b/gi;

// 已知运行时产物/示例文件名：出现即视为数据产物而非文档引用
const RUNTIME_NAMES = new Set([
  'blackboard.json', 'redteam-blackboard.json', 'worker-{id}.json', 'package.json', 'package-lock.json',
  'tsconfig.json', 'app.json', 'config.json', 'settings.py', 'manage.py', 'app.py', 'views.py',
  'finding.json', 'finding', 'permission-diff.md', 'subapp-params.sh', 'notes.md', 'results.md',
  '_audit_context.md', '_findings.md', '_verify_checklist.md', 'findings-confirmed.md',
  'handoff-20260930-1423.md', 'pentest_memory.json', 'memory.json', 'route_map.json', 'param_candidates.json',
  'param_samples.json', 'params_merged.json', 'wooyun_vulnerabilities.json', 'userRouteAuth.json',
  'xxx-test.md', 'test.md', 'xxx.md', 'CLAUDE.md', 'refusal-audit.md',
  'site_map.json', 'permissions_tree.json', 'permissions_all_stub.json', 'role_permissions_stub.json',
  'runtime_api.json', 'scan_raw.json', 'api_detail.json', 'CHANGES.md', 'extract_apis.py',
  'MSDKConfig.json', 'AGENT.md', 'IDENTITY.md', 'SOUL.md', '_scope.json', 'composer.json',
  'llm-security-test.md', 'cors-test.md', 'crlf-injection-test.md', 'vuln-report-format.md',
  'smuggler.py', 'php_filter_chain_generator.py', 'ConvertToShellcode.py', 'ajpShooter.py', 'fofa.py',
  'getKnowledgeList.json', 'getKnowledgeInfo.json', 'transform-log.json', 'verify-report.md',
  'hunt-iter.md', 'scripts.json', 'client.py', 'downstream.py', 'upstream.py', 'cordis.patch.yml',
  '.plan.md', '.auth-state.json',
]);

// 外部仓库/治理文件/工具包根：解析到对应外部绝对路径
const EXTERNAL_BASES = [
  'E:/Agent/Claude',
  'E:/Agent/0x00_Governance',
  'E:/PenTest',
  'E:/PenTest/0x02_Tools/S_Src/A_AssetCollect/AI驱动的薄弱资产识别',
  'E:/PenTest/0x02_Tools/S_Src/A_AssetCollect/SRC资产收集工具包',
  'E:/Agent/DSH-NEXT/.dsh/profiles/desktop',
];

function walk(dir, out = []) {
  for (const name of readdirSync(dir)) {
    if (name === 'node_modules' || name === '.git' || name.startsWith('.')) continue;
    const p = join(dir, name);
    const st = statSync(p);
    if (st.isDirectory()) walk(p, out);
    else if (name.endsWith('.md')) out.push(p);
  }
  return out;
}

function stripFences(text) {
  return text.replace(/```[\s\S]*?(?:```|$)/g, (m) => ' '.repeat(m.length));
}

// 全库 basename 索引（兜底解析用）
const allFiles = [];
(function index(dir) {
  for (const name of readdirSync(dir)) {
    if (name === 'node_modules' || name === '.git' || name.startsWith('.')) continue;
    const p = join(dir, name);
    const st = statSync(p);
    if (st.isDirectory()) index(p);
    else allFiles.push(p);
  }
})(ROOT);

const broken = [];
const docs = walk(ROOT);
for (const doc of docs) {
  const raw = readFileSync(doc, 'utf8');
  const text = stripFences(raw);
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.trim().startsWith('>')) { /* 引用块仍可能是真引用，不跳过 */ }
    for (const m of line.matchAll(REF_RE)) {
      let ref = m[0].replace(/[.,;:：）)）]+$/, '').replace(/\\/g, '/');
      if (!ref || ref.includes('{') || ref.includes('*')) continue;
      const base = basename(ref);
      if (RUNTIME_NAMES.has(base) || RUNTIME_NAMES.has(ref)) continue;
      if (/^(x+|xxx|test|r1?|res|resp|output|results?|data|payload|request|response|capture|collect|auth|schema|state)\.json$/i.test(base)) continue; // 示例数据名
      if (/stub\.json$|plan\.md$/i.test(base)) continue; // 模板/产物通配（*_stub.json、*.plan.md）
      if (ref.startsWith('/')) continue; // 目标 URL 路径（/config/online.yml、/openapi.json 等）
      // 解析：①相对所在文件 ②技能库根 ③所在目录向上两级 ④外部仓库根 ⑤basename 兜底
      const docDir = dirname(doc);
      const candidates = [
        resolve(docDir, ref),
        resolve(ROOT, ref),
        resolve(docDir, '..', '..', ref),
        resolve(docDir, '..', ref),
        ...EXTERNAL_BASES.map((b) => resolve(b, ref)),
      ];
      let ok = candidates.some((c) => existsSync(c));
      if (!ok) ok = allFiles.some((f) => basename(f) === base);
      if (!ok) broken.push({ file: doc, line: i + 1, ref, text: line.trim().slice(0, 120) });
    }
  }
}

if (broken.length === 0) {
  console.log('check-refs: 全部引用可解析，无断链');
  process.exit(0);
}
console.log(`check-refs: 发现 ${broken.length} 处断链\n`);
for (const b of broken) {
  console.log(`${b.file.replace(ROOT + '\\', '').replace(ROOT + '/', '')}:${b.line}  →  ${b.ref}`);
  console.log(`    ${b.text}`);
}
process.exit(1);
