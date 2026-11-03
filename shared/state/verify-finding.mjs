#!/usr/bin/env node
// verify-finding.mjs — 确定性漏洞验证器（XBOW模式：代码判断，非AI判断）
// 用法: node verify-finding.mjs <finding.json>
// 输入: Worker输出的finding JSON文件
// 输出: { verified: bool, confidence: "confirmed"|"suspected"|"rejected", reasons: [] }

import { readFileSync } from 'fs';

const VALIDATORS = {
  C_sqli: validateSQLi,
  D_xss: validateXSS,
  B_idor: validateIDOR,
  E_ssrf: validateSSRF,
  F_upload: validateUpload,
  G_lfi: validateLFI,
  A_unauth: validateUnauth,
  H_ssti: validateSSTI,
  I_rce: validateRCE,
};

function main() {
  const file = process.argv[2];
  if (!file) { console.error('用法: verify-finding.mjs <finding.json>'); process.exit(1); }
  const finding = JSON.parse(readFileSync(file, 'utf8'));
  const result = verify(finding);
  console.log(JSON.stringify(result, null, 2));
  if (!result.verified) process.exit(1);
}

function verify(f) {
  const reasons = [];
  const fails = [];

  // 通用门：必须有evidence
  if (!f.evidence) { fails.push('无evidence字段'); return { verified: false, confidence: 'rejected', reasons: fails }; }
  const ev = typeof f.evidence === 'string' ? f.evidence : JSON.stringify(f.evidence);

  // 必须有curl命令
  if (!ev.includes('curl')) fails.push('evidence缺少curl命令');

  // 必须有HTTP状态码（响应证据）
  if (!/HTTP\/[12][.\d]*\s+[2345]\d{2}/.test(ev) && !/status[:\s]*[2345]\d{2}/i.test(ev))
    fails.push('evidence缺少HTTP响应状态码');

  // 漏洞类型特定验证
  const validator = VALIDATORS[f.vuln_type];
  if (validator) {
    const { pass, fail } = validator(f, ev);
    reasons.push(...pass);
    fails.push(...fail);
  } else {
    reasons.push(`无${f.vuln_type}专用验证器，仅通用检查`);
  }

  if (fails.length === 0) return { verified: true, confidence: 'confirmed', reasons };
  if (fails.length <= 1 && reasons.length >= 2) return { verified: true, confidence: 'suspected', reasons: [...reasons, ...fails.map(f => `[WARN] ${f}`)] };
  return { verified: false, confidence: 'rejected', reasons: fails };
}

// --- 各类型验证器 ---

function validateSQLi(f, ev) {
  const pass = [], fail = [];
  const sqlSignals = [/sql syntax/i, /mysql/i, /ORA-\d+/i, /ODBC/i, /PostgreSQL/i, /sqlite/i, /mariadb/i,
    /union\s+select/i, /extractvalue/i, /updatexml/i, /sleep\(\d/i, /benchmark\(/i, /waitfor\s+delay/i,
    /database\(\)/i, /version\(\)/i, /@@version/i, /information_schema/i];
  const matched = sqlSignals.filter(r => r.test(ev));
  if (matched.length > 0) pass.push(`SQL信号匹配: ${matched.length}个`);
  else fail.push('响应中无SQL错误/注入成功标志');

  // 时间盲注：检查是否声称延迟
  if (/sleep|waitfor|pg_sleep|benchmark/i.test(ev) && !/\d+\.\d+\s*s|time.*\d{4,}/i.test(ev))
    fail.push('声称时间盲注但无响应时间证据');
  return { pass, fail };
}

function validateXSS(f, ev) {
  const pass = [], fail = [];
  if (/console\.log|<script|onerror|onload|javascript:/i.test(ev)) pass.push('XSS payload在响应中反射');
  else fail.push('响应中未见XSS payload反射');
  if (/alert\s*\(/i.test(ev)) fail.push('使用了alert弹窗（违反AGENTS.md规则）');
  if (/Content-Type.*application\/json/i.test(ev) && !/text\/html/i.test(ev))
    fail.push('响应Content-Type为JSON，浏览器不会渲染XSS');
  return { pass, fail };
}

function validateIDOR(f, ev) {
  const pass = [], fail = [];
  if (f.negation_evidence || /换.*账号|其他用户|不同.*token|user.*id.*不同/i.test(ev))
    pass.push('有跨账号验证证据');
  else fail.push('缺少跨账号/跨角色negation验证');
  if (/自己的数据|当前用户|own data/i.test(ev)) fail.push('可能访问的是自己的数据');
  return { pass, fail };
}

function validateSSRF(f, ev) {
  const pass = [], fail = [];
  if (/127\.0\.0\.1|localhost|169\.254\.169\.254|metadata|内网|10\.\d|172\.(1[6-9]|2\d|3[01])\./i.test(ev))
    pass.push('响应含内网/元数据地址访问证据');
  else fail.push('响应中无内网访问证据');
  return { pass, fail };
}

function validateUpload(f, ev) {
  const pass = [], fail = [];
  if (/上传成功|upload.*success|200|stored/i.test(ev)) pass.push('文件上传成功');
  else fail.push('无上传成功证据');
  if (/可访问|可执行|executed|phpinfo|whoami/i.test(ev)) pass.push('上传文件可访问/执行');
  else if (/不可访问|403|404|无法访问/i.test(ev)) pass.push('上传成功但不可访问（中危）');
  return { pass, fail };
}

function validateLFI(f, ev) {
  const pass = [], fail = [];
  const safeFiles = [/\[extensions\]|localhost|127\.0\.0\.1/i, /root:.*:0:0/i, /\/bin\/(ba)?sh/i, /\[boot loader\]/i];
  if (safeFiles.some(r => r.test(ev))) pass.push('响应含已知系统文件内容');
  else fail.push('响应中无系统文件内容特征');
  if (/\/etc\/shadow|\/etc\/passwd.*root.*password|web\.config.*password|\.env.*KEY/i.test(ev))
    fail.push('读取了敏感文件（违反AGENTS.md：只用无害路径验证）');
  return { pass, fail };
}

function validateUnauth(f, ev) {
  const pass = [], fail = [];
  if (/无.*cookie|无.*token|不带.*认证|without.*auth|no.*session/i.test(ev))
    pass.push('请求未携带认证信息');
  else fail.push('未证明请求不含认证凭证');
  if (/200|数据|records|列表|用户/i.test(ev)) pass.push('未认证请求返回了业务数据');
  return { pass, fail };
}

function validateSSTI(f, ev) {
  const pass = [], fail = [];
  if (/49|7\*7|{{|{%|\$\{|<%/i.test(ev) && /49(?!.*4\d{2})/.test(ev))
    pass.push('模板表达式被执行（如7*7=49）');
  else fail.push('响应中无模板执行证据');
  return { pass, fail };
}

function validateRCE(f, ev) {
  const pass = [], fail = [];
  if (/whoami|uid=\d|id\s|ipconfig|hostname/i.test(ev)) pass.push('命令执行输出存在');
  else fail.push('响应中无命令执行输出');
  if (/cat\s+\/etc|type\s+.*\\|net\s+user|tasklist|ls\s+\/|dir\s+c:/i.test(ev))
    fail.push('执行了非只读命令（违反AGENTS.md）');
  return { pass, fail };
}

main();
