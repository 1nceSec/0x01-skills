#!/usr/bin/env node
// redteam-state.mjs — 红队评估状态管理 v1.0
// 目标驱动 + Kill Chain 阶段制。与 pentest-state.mjs 互不干扰。
// 用法：node redteam-state.mjs <command> [subcommand] [args...]

import { readFileSync, writeFileSync, appendFileSync, existsSync, mkdirSync, readdirSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const WORK_DIR = process.env.REDTEAM_WORKDIR || 'E:\\Agent\\Claude';
const BLACKBOARD = join(WORK_DIR, 'blackboard.json');
const CHANGELOG = join(WORK_DIR, 'blackboard-changelog.jsonl');
const TRACES_DIR = join(WORK_DIR, 'worker-traces');

// ─── 工具函数 ───

function loadBB() {
  if (!existsSync(BLACKBOARD)) { console.error('blackboard.json不存在，先执行 init'); process.exit(1); }
  return JSON.parse(readFileSync(BLACKBOARD, 'utf8'));
}
function saveBB(bb) { writeFileSync(BLACKBOARD, JSON.stringify(bb, null, 2), 'utf8'); }
function logChange(source, changes) {
  appendFileSync(CHANGELOG, JSON.stringify({ ts: new Date().toISOString(), source, changes }) + '\n', 'utf8');
}
function nextId(arr, prefix) { return `${prefix}-${arr.length + 1}`; }
function traceDir() { if (!existsSync(TRACES_DIR)) mkdirSync(TRACES_DIR, { recursive: true }); }

// ─── Init: 初始化黑板 ───

function init(targetScope, roe, branch) {
  const schema = JSON.parse(readFileSync(join(__dirname, '..', '..', 'red-team', 'redteam-blackboard-schema.json'), 'utf8'));
  const bb = JSON.parse(JSON.stringify(schema.init_template));
  bb.meta.target_scope = targetScope || '';
  bb.meta.roe = roe || '';
  bb.meta.branch = branch || 'web';
  bb.meta.start_time = new Date().toISOString();
  saveBB(bb);
  traceDir();
  console.log(`红队黑板已初始化 — scope: ${targetScope || '(空)'}, branch: ${branch || 'web'}`);
}

// ─── Objective: 目标管理 ───

const VALID_OBJ_CATEGORIES = ['target','server_control','admin_panel','db_access','sensitive_data','centralised_system','intranet_host','intranet_data','attack_chain','zero_day','supply_chain'];
const VALID_WEIGHTS = ['critical','high','medium','bonus'];
const VALID_OBJ_STATUS = ['pending','in_progress','achieved','blocked'];

function objAdd(jsonStr) {
  const bb = loadBB();
  const obj = JSON.parse(jsonStr);
  if (!obj.category || !VALID_OBJ_CATEGORIES.includes(obj.category)) {
    console.error(`category必须是: ${VALID_OBJ_CATEGORIES.join('|')}`); process.exit(1);
  }
  obj.id = obj.id || nextId(bb.objectives, 'obj');
  obj.weight = obj.weight || 'medium';
  obj.status = 'pending';
  obj.branch = obj.branch || bb.meta.branch || 'web';
  obj.achieved_round = null;
  obj.evidence_ref = null;
  bb.objectives.push(obj);
  saveBB(bb);
  logChange('obj-add', [`+objective: ${obj.id} (${obj.category})`]);
  console.log(`目标已添加: ${obj.id} — ${obj.description || obj.category}`);
}

function objUpdate(objId, field, value) {
  const bb = loadBB();
  const obj = bb.objectives.find(o => o.id === objId);
  if (!obj) { console.error(`目标 ${objId} 不存在`); process.exit(1); }
  if (field === 'status' && !VALID_OBJ_STATUS.includes(value)) {
    console.error(`status必须是: ${VALID_OBJ_STATUS.join('|')}`); process.exit(1);
  }
  const old = obj[field];
  obj[field] = value;
  if (field === 'status' && value === 'achieved') {
    obj.achieved_round = bb.meta.total_rounds;
  }
  saveBB(bb);
  logChange('obj-update', [`~${objId}.${field}: ${old} → ${value}`]);
  console.log(`${objId}.${field}: ${old} → ${value}`);
}

function objList() {
  const bb = loadBB();
  if (bb.objectives.length === 0) { console.log('无目标'); return; }
  for (const o of bb.objectives) {
    const flag = o.status === 'achieved' ? '[DONE]' : o.status === 'blocked' ? '[BLOCK]' : o.status === 'in_progress' ? '[WIP]' : '[TODO]';
    console.log(`${flag} ${o.id} [${o.weight}] ${o.category}: ${o.description || '-'}`);
  }
}

// ─── Asset: 资产管理 ───

const VALID_ROLES = ['web','workstation','server','dc','firewall','unknown'];
const VALID_ACCESS = ['none','user','admin','system','domain_admin'];

function assetAdd(jsonStr) {
  const bb = loadBB();
  const a = JSON.parse(jsonStr);
  if (!a.ip && !a.hostname) { console.error('asset必须有ip或hostname'); process.exit(1); }
  a.id = a.id || nextId(bb.assets, 'a');
  a.access_level = a.access_level || 'none';
  a.role = a.role || 'unknown';
  a.domain_joined = a.domain_joined || false;
  a.discovered_round = bb.meta.total_rounds;
  bb.assets.push(a);
  saveBB(bb);
  logChange('asset-add', [`+asset: ${a.id} (${a.ip || a.hostname})`]);
  console.log(`资产已添加: ${a.id} — ${a.ip || a.hostname} [${a.access_level}]`);
}

function assetUpdate(assetId, field, value) {
  const bb = loadBB();
  const a = bb.assets.find(x => x.id === assetId);
  if (!a) { console.error(`资产 ${assetId} 不存在`); process.exit(1); }
  if (field === 'access_level' && !VALID_ACCESS.includes(value)) {
    console.error(`access_level必须是: ${VALID_ACCESS.join('|')}`); process.exit(1);
  }
  const old = a[field];
  a[field] = value;
  saveBB(bb);
  logChange('asset-update', [`~${assetId}.${field}: ${old} → ${value}`]);
  console.log(`${assetId}.${field}: ${old} → ${value}`);
}

function assetList() {
  const bb = loadBB();
  if (bb.assets.length === 0) { console.log('无已知资产'); return; }
  for (const a of bb.assets) {
    const domain = a.domain_joined ? ` (${a.domain_name || 'domain'})` : '';
    console.log(`${a.id}: ${a.ip || '-'}/${a.hostname || '-'} [${a.role}] ${a.access_level}${domain}`);
  }
}

// ─── Credential: 凭证管理 ───

function credAdd(jsonStr) {
  const bb = loadBB();
  const c = JSON.parse(jsonStr);
  if (!c.username || !c.type) { console.error('credential必须有username和type'); process.exit(1); }
  c.id = c.id || nextId(bb.credentials, 'c');
  c.valid = c.valid !== false;
  c.tested_on = c.tested_on || [];
  c.admin_on = c.admin_on || [];
  bb.credentials.push(c);
  saveBB(bb);
  logChange('cred-add', [`+cred: ${c.id} (${c.type}:${c.username})`]);
  console.log(`凭证已添加: ${c.id} — ${c.type}:${c.username}${c.domain ? '@' + c.domain : ''}`);
}

function credTest(credId, assetId, isAdmin) {
  const bb = loadBB();
  const c = bb.credentials.find(x => x.id === credId);
  if (!c) { console.error(`凭证 ${credId} 不存在`); process.exit(1); }
  if (!c.tested_on.includes(assetId)) c.tested_on.push(assetId);
  if (isAdmin === 'true' && !c.admin_on.includes(assetId)) c.admin_on.push(assetId);
  saveBB(bb);
  logChange('cred-test', [`~${credId} tested on ${assetId}${isAdmin === 'true' ? ' (admin)' : ''}`]);
  console.log(`${credId} → ${assetId}: ${isAdmin === 'true' ? 'admin' : 'user'}`);
}

function credList() {
  const bb = loadBB();
  if (bb.credentials.length === 0) { console.log('无凭证'); return; }
  for (const c of bb.credentials) {
    const scope = c.admin_on.length > 0 ? ` admin@[${c.admin_on.join(',')}]` : '';
    console.log(`${c.id}: ${c.type}:${c.username}${c.domain ? '@' + c.domain : ''} valid=${c.valid}${scope}`);
  }
}

// ─── Network: 网段管理 ───

function netAdd(jsonStr) {
  const bb = loadBB();
  const n = JSON.parse(jsonStr);
  if (!n.cidr) { console.error('network必须有cidr'); process.exit(1); }
  n.id = n.id || nextId(bb.network, 'n');
  n.scanned = false;
  n.alive_hosts = null;
  bb.network.push(n);
  saveBB(bb);
  logChange('net-add', [`+network: ${n.id} (${n.cidr})`]);
  console.log(`网段已添加: ${n.id} — ${n.cidr}`);
}

function netList() {
  const bb = loadBB();
  if (bb.network.length === 0) { console.log('无已知网段'); return; }
  for (const n of bb.network) {
    const status = n.scanned ? `scanned, ${n.alive_hosts ?? '?'} alive` : 'not scanned';
    console.log(`${n.id}: ${n.cidr} [${status}]`);
  }
}

// ─── Attack Path: 攻击路径记录 ───

function pathAdd(jsonStr) {
  const bb = loadBB();
  const p = JSON.parse(jsonStr);
  if (!p.from || !p.to || !p.method) { console.error('attack_path必须有from/to/method'); process.exit(1); }
  p.stage = p.stage || bb.meta.current_stage;
  p.round = bb.meta.total_rounds;
  bb.attack_path.push(p);
  saveBB(bb);
  logChange('path-add', [`+path: ${p.from} → ${p.to} via ${p.method}`]);
  console.log(`路径已记录: ${p.from} → ${p.to} [${p.method}]`);
}

function pathShow() {
  const bb = loadBB();
  if (bb.attack_path.length === 0) { console.log('无攻击路径'); return; }
  for (const p of bb.attack_path) {
    const cred = p.credential_used ? ` cred=${p.credential_used}` : '';
    console.log(`R${p.round} [${p.stage}] ${p.from} → ${p.to} via ${p.method}${cred}`);
  }
}

// ─── Persistence: 持久化点管理 ───

function persistAdd(jsonStr) {
  const bb = loadBB();
  const p = JSON.parse(jsonStr);
  if (!p.asset || !p.method) { console.error('persistence必须有asset和method'); process.exit(1); }
  p.id = p.id || nextId(bb.persistence_points, 'p');
  p.verified = false;
  bb.persistence_points.push(p);
  saveBB(bb);
  logChange('persist-add', [`+persist: ${p.id} on ${p.asset} via ${p.method}`]);
  console.log(`持久化已添加: ${p.id} — ${p.asset} [${p.method}]`);
}

// ─── Stage: Kill Chain 阶段推进 ───

const STAGES = ['recon', 'entry', 'privesc', 'lateral', 'persist', 'objective'];
const STAGE_GATES = {
  entry:     bb => bb.assets.some(a => a.access_level !== 'none'),
  privesc:   bb => bb.assets.some(a => ['admin','system','domain_admin'].includes(a.access_level)),
  lateral:   bb => bb.credentials.some(c => c.tested_on.length > 0),
  persist:   bb => bb.assets.filter(a => ['admin','system','domain_admin'].includes(a.access_level)).length >= 2,
  objective: bb => bb.objectives.some(o => o.status === 'achieved'),
};

function stageCheck() {
  const bb = loadBB();
  const current = bb.meta.current_stage;
  const idx = STAGES.indexOf(current);
  console.log(`当前阶段: ${current} (${idx + 1}/${STAGES.length})`);

  // 检查是否满足下一阶段推进门
  for (let i = idx + 1; i < STAGES.length; i++) {
    const gate = STAGE_GATES[STAGES[i]];
    if (gate && gate(bb)) {
      console.log(`✓ 可推进到 ${STAGES[i]}`);
    } else if (gate) {
      console.log(`✗ ${STAGES[i]} 门未满足`);
      break;
    }
  }

  // 统计
  const controlled = bb.assets.filter(a => a.access_level !== 'none').length;
  const creds = bb.credentials.filter(c => c.valid).length;
  const achieved = bb.objectives.filter(o => o.status === 'achieved').length;
  console.log(`\n资产: ${controlled}/${bb.assets.length} 已控 | 凭证: ${creds} 有效 | 目标: ${achieved}/${bb.objectives.length} 达成`);
}

function stageAdvance(targetStage) {
  const bb = loadBB();
  if (!STAGES.includes(targetStage)) {
    console.error(`无效阶段，可选: ${STAGES.join('|')}`); process.exit(1);
  }
  const gate = STAGE_GATES[targetStage];
  if (gate && !gate(bb)) {
    console.error(`推进门未满足，不能进入 ${targetStage}`); process.exit(1);
  }
  const old = bb.meta.current_stage;
  bb.meta.current_stage = targetStage;
  saveBB(bb);
  logChange('stage-advance', [`stage: ${old} → ${targetStage}`]);
  console.log(`阶段推进: ${old} → ${targetStage}`);
}

// ─── Path Next: 确定性计算下一步候选 ───

function pathNext() {
  const bb = loadBB();
  const stage = bb.meta.current_stage;
  const candidates = [];

  // 根据阶段产生候选动作
  if (stage === 'recon' || stage === 'entry') {
    // 未突破的Web资产 → 委托pentest
    const noAccess = bb.assets.filter(a => a.access_level === 'none' && a.role === 'web');
    for (const a of noAccess) {
      candidates.push({ action: 'delegate_pentest', target: a.id, desc: `Web突破: ${a.ip || a.hostname}`, priority: 1 });
    }
    // 无资产时提示需要先侦察
    if (bb.assets.length === 0) {
      candidates.push({ action: 'recon_target', target: bb.meta.target_scope, desc: '侦察目标范围', priority: 0 });
    }
  }

  if (stage === 'privesc' || stage === 'entry') {
    // 低权限资产 → 提权
    const lowPriv = bb.assets.filter(a => a.access_level === 'user');
    for (const a of lowPriv) {
      candidates.push({ action: 'privesc', target: a.id, desc: `提权: ${a.ip || a.hostname}`, priority: 2 });
    }
  }

  if (stage === 'lateral' || stage === 'privesc') {
    // 未测试凭证 × 未控资产 → 横向
    const untested = [];
    for (const c of bb.credentials.filter(cr => cr.valid)) {
      const controlled = new Set(bb.assets.filter(a => a.access_level !== 'none').map(a => a.id));
      const notTested = bb.assets.filter(a => !controlled.has(a.id) && !c.tested_on.includes(a.id));
      for (const a of notTested) {
        untested.push({ action: 'lateral_move', target: a.id, cred: c.id, desc: `横向: ${c.username}→${a.ip || a.hostname}`, priority: 3 });
      }
    }
    candidates.push(...untested.slice(0, 10));

    // 未扫描网段 → 扫描发现
    for (const n of bb.network.filter(x => !x.scanned)) {
      candidates.push({ action: 'scan_network', target: n.id, desc: `扫描网段: ${n.cidr}`, priority: 4 });
    }
  }

  if (stage === 'persist') {
    // 高权限但无持久化 → 建立持久化
    const highPriv = bb.assets.filter(a => ['admin','system','domain_admin'].includes(a.access_level));
    const persisted = new Set(bb.persistence_points.map(p => p.asset));
    for (const a of highPriv.filter(a => !persisted.has(a.id))) {
      candidates.push({ action: 'persist', target: a.id, desc: `持久化: ${a.ip || a.hostname}`, priority: 5 });
    }
  }

  // 始终检查：未达成目标的直接路径
  for (const o of bb.objectives.filter(x => x.status !== 'achieved')) {
    candidates.push({ action: 'pursue_objective', target: o.id, desc: `目标: ${o.description || o.category}`, priority: o.weight === 'critical' ? 0 : 3 });
  }

  candidates.sort((a, b) => a.priority - b.priority);

  if (candidates.length === 0) {
    console.log(JSON.stringify({ candidates: [], message: '无候选动作' }));
  } else {
    console.log(JSON.stringify({ stage, candidates: candidates.slice(0, 8) }));
  }
}

// ─── Score: 得分计算 ───

const WEIGHT_POINTS = { critical: 100, high: 50, medium: 20, bonus: 10 };

function score() {
  const bb = loadBB();
  let total = 0;
  const breakdown = [];

  for (const o of bb.objectives) {
    const pts = WEIGHT_POINTS[o.weight] || 0;
    if (o.status === 'achieved') {
      total += pts;
      breakdown.push(`✓ ${o.id} [${o.category}] +${pts}`);
    } else {
      breakdown.push(`✗ ${o.id} [${o.category}] (${pts}pts pending)`);
    }
  }

  // 加分项：攻击链深度
  const chainDepth = bb.attack_path.length;
  const chainBonus = Math.min(chainDepth * 5, 50);
  if (chainBonus > 0) {
    total += chainBonus;
    breakdown.push(`⊕ 攻击链深度(${chainDepth}步) +${chainBonus}`);
  }

  console.log(`总分: ${total}`);
  for (const b of breakdown) console.log(`  ${b}`);

  // 控制统计
  const controlled = bb.assets.filter(a => a.access_level !== 'none').length;
  const domainAdmin = bb.assets.filter(a => a.access_level === 'domain_admin').length;
  console.log(`\n资产: ${controlled} 已控 (${domainAdmin} 域管) | 凭证: ${bb.credentials.length} | 网段: ${bb.network.length}`);
}

// ─── BB Merge: 追加式合并 ───

function bbMerge(jsonStr) {
  const patch = JSON.parse(jsonStr);
  const bb = loadBB();
  const changes = [];

  const appendArrays = ['intents','findings','failure_records','decision_log','source_intel'];
  for (const key of appendArrays) {
    if (patch[key] && Array.isArray(patch[key])) {
      if (!bb[key]) bb[key] = [];
      const existingIds = new Set(bb[key].map(x => x.id).filter(Boolean));
      for (const item of patch[key]) {
        if (item.id && existingIds.has(item.id)) {
          const idx = bb[key].findIndex(x => x.id === item.id);
          bb[key][idx] = { ...bb[key][idx], ...item };
          changes.push(`~${key}: ${item.id}`);
        } else {
          bb[key].push(item);
          changes.push(`+${key}: ${item.id || 'anon'}`);
        }
      }
    }
  }

  // scoreboard追加
  if (patch.scoreboard) {
    if (!bb.scoreboard) bb.scoreboard = [];
    for (const s of patch.scoreboard) {
      bb.scoreboard.push(s);
      changes.push(`+score: ${s.id || s.category}`);
    }
  }

  // meta字段更新
  if (patch.meta) {
    for (const [k, v] of Object.entries(patch.meta)) {
      bb.meta[k] = v;
      changes.push(`~meta.${k}`);
    }
  }

  saveBB(bb);
  logChange(patch._source || 'merge', changes);
  console.log(`merged ${changes.length} changes`);
  for (const c of changes) console.log(`  ${c}`);
}

// ─── BB Observe: 状态一致性检查 ───

function bbObserve() {
  const bb = loadBB();
  const issues = [];

  // 1. 凭证声称admin_on某资产，但该资产access_level仍低
  for (const c of bb.credentials) {
    for (const aid of c.admin_on) {
      const a = bb.assets.find(x => x.id === aid);
      if (a && !['admin','system','domain_admin'].includes(a.access_level)) {
        issues.push({ type: 'contradiction', detail: `cred ${c.id} claims admin on ${aid}, but asset access_level=${a.access_level}` });
      }
    }
  }

  // 2. 攻击路径引用不存在的asset
  const assetIds = new Set(bb.assets.map(a => a.id));
  for (const p of bb.attack_path) {
    if (p.from !== 'external' && !assetIds.has(p.from)) {
      issues.push({ type: 'orphan', detail: `path.from=${p.from} not in assets` });
    }
    if (!assetIds.has(p.to)) {
      issues.push({ type: 'orphan', detail: `path.to=${p.to} not in assets` });
    }
  }

  // 3. 持久化引用不存在的asset
  for (const p of bb.persistence_points) {
    if (!assetIds.has(p.asset)) {
      issues.push({ type: 'orphan', detail: `persistence ${p.id} refs asset ${p.asset} not in assets` });
    }
  }

  // 4. 目标in_progress超过3轮无进展
  for (const o of bb.objectives) {
    if (o.status === 'in_progress' && bb.meta.total_rounds - (o._started_round || 0) > 3) {
      issues.push({ type: 'stale', detail: `objective ${o.id} in_progress for >3 rounds` });
    }
  }

  // 5. 无progress streak过高
  if (bb.meta.no_progress_streak >= 3) {
    issues.push({ type: 'stall', detail: `no_progress_streak=${bb.meta.no_progress_streak}, consider changing approach` });
  }

  // 6. 重复失败
  const failCounts = {};
  for (const f of (bb.failure_records || [])) {
    const key = `${f.target || '?'}×${f.method || '?'}`;
    failCounts[key] = (failCounts[key] || 0) + 1;
  }
  for (const [key, count] of Object.entries(failCounts)) {
    if (count >= 3) {
      issues.push({ type: 'repeated_failure', detail: `${key} failed ${count}× — park or change approach` });
    }
  }

  if (issues.length === 0) {
    console.log('Observer: 状态一致，无异常');
    return;
  }
  console.log(`Observer: ${issues.length} 个问题`);
  const grouped = {};
  for (const i of issues) {
    if (!grouped[i.type]) grouped[i.type] = [];
    grouped[i.type].push(i.detail);
  }
  for (const [type, details] of Object.entries(grouped)) {
    console.log(`\n[${type}] (${details.length})`);
    for (const d of details) console.log(`  - ${d}`);
  }
}

// ─── BB Plan: 事件驱动建议 ───

function bbPlan() {
  const bb = loadBB();
  const actions = [];
  const stage = bb.meta.current_stage;

  // 事件1: 新凭证未测试 → 横向扩展
  const untestedCreds = bb.credentials.filter(c => c.valid && c.tested_on.length === 0);
  if (untestedCreds.length > 0) {
    actions.push({ trigger: 'new_creds', action: 'test_creds_lateral', ids: untestedCreds.map(c => c.id), priority: 1 });
  }

  // 事件2: 高权限资产无持久化 → 建立
  const highNoPersis = bb.assets.filter(a =>
    ['admin','system','domain_admin'].includes(a.access_level) &&
    !bb.persistence_points.some(p => p.asset === a.id)
  );
  if (highNoPersis.length > 0 && (stage === 'persist' || stage === 'lateral')) {
    actions.push({ trigger: 'high_priv_no_persist', action: 'establish_persistence', assets: highNoPersis.map(a => a.id), priority: 2 });
  }

  // 事件3: 推进门满足但未推进
  for (let i = STAGES.indexOf(stage) + 1; i < STAGES.length; i++) {
    const gate = STAGE_GATES[STAGES[i]];
    if (gate && gate(bb)) {
      actions.push({ trigger: 'gate_ready', action: `advance_to_${STAGES[i]}`, priority: 0 });
      break;
    }
  }

  // 事件4: 目标可直接达成
  for (const o of bb.objectives.filter(x => x.status === 'in_progress')) {
    if (o.category === 'target' || o.category === 'centralised_system') {
      const dcAssets = bb.assets.filter(a => a.role === 'dc' && a.access_level === 'domain_admin');
      if (o.category === 'target' && dcAssets.length > 0) {
        actions.push({ trigger: 'dc_controlled', action: 'claim_objective', objective: o.id, priority: 0 });
      }
    }
  }

  // 事件5: 所有目标达成 → 收尾
  if (bb.objectives.length > 0 && bb.objectives.every(o => o.status === 'achieved')) {
    actions.push({ trigger: 'all_objectives_achieved', action: 'finalize_report', priority: 0 });
  }

  actions.sort((a, b) => a.priority - b.priority);
  console.log(JSON.stringify({ stage, next_actions: actions }));
}

// ─── BB Log: changelog查看 ───

function bbLog(count) {
  if (!existsSync(CHANGELOG)) { console.log('无changelog'); return; }
  const lines = readFileSync(CHANGELOG, 'utf8').split('\n').filter(Boolean);
  const n = parseInt(count) || 10;
  for (const line of lines.slice(-n)) {
    const e = JSON.parse(line);
    console.log(`[${e.ts}] ${e.source}: ${e.changes.join(', ')}`);
  }
}

// ─── Summary: 交接摘要 ───

function summary() {
  const bb = loadBB();
  const lines = [];

  lines.push(`## 红队评估状态摘要`);
  lines.push(`阶段: ${bb.meta.current_stage} | 轮次: ${bb.meta.total_rounds} | 分支: ${bb.meta.branch}`);

  // 目标
  const achieved = bb.objectives.filter(o => o.status === 'achieved');
  const pending = bb.objectives.filter(o => o.status !== 'achieved');
  lines.push(`\n## 目标: ${achieved.length}/${bb.objectives.length} 达成`);
  for (const o of achieved) lines.push(`  ✓ ${o.id} [${o.weight}] ${o.category}: ${o.description || '-'}`);
  for (const o of pending) lines.push(`  ✗ ${o.id} [${o.weight}] ${o.category}: ${o.description || '-'} (${o.status})`);

  // 资产
  const controlled = bb.assets.filter(a => a.access_level !== 'none');
  if (controlled.length > 0) {
    lines.push(`\n## 已控资产: ${controlled.length}`);
    for (const a of controlled) {
      lines.push(`  ${a.id}: ${a.ip || '-'}/${a.hostname || '-'} [${a.access_level}]`);
    }
  }

  // 凭证
  const validCreds = bb.credentials.filter(c => c.valid);
  if (validCreds.length > 0) {
    lines.push(`\n## 有效凭证: ${validCreds.length}`);
    for (const c of validCreds) {
      lines.push(`  ${c.id}: ${c.type}:${c.username}${c.domain ? '@' + c.domain : ''}`);
    }
  }

  // 攻击路径
  if (bb.attack_path.length > 0) {
    lines.push(`\n## 攻击路径: ${bb.attack_path.length} 步`);
    for (const p of bb.attack_path) {
      lines.push(`  R${p.round} ${p.from} → ${p.to} [${p.method}]`);
    }
  }

  // Findings
  if (bb.findings && bb.findings.length > 0) {
    lines.push(`\n## Findings: ${bb.findings.length}`);
    for (const f of bb.findings) {
      lines.push(`  [${f.severity || '?'}] ${f.title || f.id || 'unnamed'}`);
    }
  }

  console.log(lines.join('\n'));
}

// ─── Trace: Worker通信 ───

function traceWrite(workerId, jsonStr) {
  traceDir();
  const entry = JSON.parse(jsonStr);
  entry.ts = new Date().toISOString();
  entry.worker = workerId;
  appendFileSync(join(TRACES_DIR, `${workerId}.jsonl`), JSON.stringify(entry) + '\n', 'utf8');
  console.log(`trace written → ${workerId}`);
}

function traceList() {
  traceDir();
  const files = readdirSync(TRACES_DIR).filter(f => f.endsWith('.jsonl'));
  if (files.length === 0) { console.log('无Worker trace'); return; }
  for (const f of files) {
    const lines = readFileSync(join(TRACES_DIR, f), 'utf8').split('\n').filter(Boolean);
    const last = lines.length > 0 ? JSON.parse(lines[lines.length - 1]) : null;
    console.log(`${f} (${lines.length} entries) — last: ${last ? last.ts : 'empty'}`);
  }
}

function traceSearch(keyword) {
  traceDir();
  const files = readdirSync(TRACES_DIR).filter(f => f.endsWith('.jsonl'));
  const results = [];
  const kw = keyword.toLowerCase();
  for (const f of files) {
    for (const line of readFileSync(join(TRACES_DIR, f), 'utf8').split('\n').filter(Boolean)) {
      if (line.toLowerCase().includes(kw)) {
        results.push({ file: f, data: JSON.parse(line) });
        if (results.length >= 20) break;
      }
    }
    if (results.length >= 20) break;
  }
  if (results.length === 0) { console.log(`未找到: ${keyword}`); return; }
  for (const r of results) console.log(`[${r.file}] ${r.data.ts} ${r.data.type || '-'}: ${r.data.msg || JSON.stringify(r.data).slice(0, 120)}`);
}

// ─── CLI 路由 ───

function main() {
  const args = process.argv.slice(2);
  const cmd = args[0];
  const sub = args[1];

  switch (cmd) {
    case 'init':
      init(args[1], args[2], args[3]);
      break;
    case 'obj':
      switch (sub) {
        case 'add': objAdd(args[2]); break;
        case 'update': objUpdate(args[2], args[3], args[4]); break;
        case 'list': objList(); break;
        default: console.error('用法: obj <add|update|list>'); process.exit(1);
      }
      break;
    case 'asset':
      switch (sub) {
        case 'add': assetAdd(args[2]); break;
        case 'update': assetUpdate(args[2], args[3], args[4]); break;
        case 'list': assetList(); break;
        default: console.error('用法: asset <add|update|list>'); process.exit(1);
      }
      break;
    case 'cred':
      switch (sub) {
        case 'add': credAdd(args[2]); break;
        case 'test': credTest(args[2], args[3], args[4]); break;
        case 'list': credList(); break;
        default: console.error('用法: cred <add|test|list>'); process.exit(1);
      }
      break;
    case 'net':
      switch (sub) {
        case 'add': netAdd(args[2]); break;
        case 'list': netList(); break;
        default: console.error('用法: net <add|list>'); process.exit(1);
      }
      break;
    case 'path':
      switch (sub) {
        case 'add': pathAdd(args[2]); break;
        case 'show': pathShow(); break;
        case 'next': pathNext(); break;
        default: console.error('用法: path <add|show|next>'); process.exit(1);
      }
      break;
    case 'persist':
      switch (sub) {
        case 'add': persistAdd(args[2]); break;
        default: console.error('用法: persist <add>'); process.exit(1);
      }
      break;
    case 'stage':
      switch (sub) {
        case 'check': stageCheck(); break;
        case 'advance': stageAdvance(args[2]); break;
        default: console.error('用法: stage <check|advance>'); process.exit(1);
      }
      break;
    case 'score':
      score();
      break;
    case 'summary':
      summary();
      break;
    case 'bb':
      switch (sub) {
        case 'merge': bbMerge(args[2]); break;
        case 'observe': bbObserve(); break;
        case 'plan': bbPlan(); break;
        case 'log': bbLog(args[2]); break;
        default: console.error('用法: bb <merge|observe|plan|log>'); process.exit(1);
      }
      break;
    case 'trace':
      switch (sub) {
        case 'write': traceWrite(args[2], args[3]); break;
        case 'list': traceList(); break;
        case 'search': traceSearch(args[2]); break;
        default: console.error('用法: trace <write|list|search>'); process.exit(1);
      }
      break;
    default:
      console.error('用法: redteam-state.mjs <init|obj|asset|cred|net|path|persist|stage|score|summary|bb|trace>');
      process.exit(1);
  }
}

main();
