#!/usr/bin/env bash
# DSH skills 同步脚本：仓库(域文件夹制) → DSH(平铺制)
# 背景：DSH 扫描器只认 skills/ 一层下的 SKILL.md，无 SKILL.md 的目录(如域文件夹)被忽略。
#      因此部署形态 = 域文件夹展开平铺；本脚本幂等（先删后拷），可重复执行。
# 路径适配：仓库 SKILL.md 内的 `../../shared/`（域文件夹两层）在 DSH 平铺布局下
#      应为 `../shared/`，拷贝后统一改写（仅改 DSH 副本，仓库不动）。
# 用法: bash /e/Agent/0x01_Skills/utils/dsh-admin/scripts/sync-from-repo.sh [--dry]
set -euo pipefail

REPO=/e/Agent/0x01_Skills
DSH=/e/Agent/DSH-NEXT/.dsh/skills
DRY=0; [[ "${1:-}" == "--dry" ]] && DRY=1

# 新名（= 域文件夹展开后的目录名）
NEW=(src-asset asset-triage bugbounty-asset bugbounty-triage \
     vuln-hunting api-recon mobile-pentest \
     code-audit \
     killchain arsenal \
     pentest-flow auto-handoff report-generator \
     playwright-cli mcp-status dsh-admin antidebug-breaker translate)
# 旧名（历史部署残留，需清除；js-reverse/jsreverser-playbook 于 2026-11-14 移除，方法论并入 shared/knowledge/appsec/js-reverse-guide.md）
OLD=(recon-src-asset recon-asset-triage web-vuln-hunting audit-js-reverse \
     js-reverse jsreverser-playbook \
     red-team redteam-arsenal core-pentest-flow core-auto-handoff \
     shared-playwright-cli shared-mcp-status shared-dsh-admin \
     shared-antidebug-breaker shared-jsreverser-playbook)

run() { if [[ $DRY == 1 ]]; then echo "[dry] $*"; else eval "$@"; fi; }

cd "$DSH"
echo "== 1. 清理旧名/旧拷贝 =="
for n in "${OLD[@]}" "${NEW[@]}"; do
  [[ -d "$n" ]] && run "rm -rf '$n'" && echo "  rm $n"
done

echo "== 2. 平铺拷入（域文件夹展开） =="
for d in recon pentest audit redteam core utils; do
  for s in "$REPO/$d"/*/; do
    name=$(basename "$s")
    [[ -f "$s/SKILL.md" ]] || continue   # 只拷 skill，跳过杂项目录
    run "cp -rf '$s' './$name'"
    echo "  cp $d/$name"
  done
done

echo "== 3. shared 知识库同步 =="
run "mkdir -p shared && cp -rf '$REPO/shared/'* shared/"

echo "== 4. 路径适配（DSH副本 ../../shared/ -> ../shared/） =="
if [[ $DRY == 1 ]]; then
  echo "  [dry] find+sed 适配各 skill 内 md"
else
  find . -name "*.md" -not -path "./shared/*" -not -path "./.system/*" \
    -exec grep -l '\.\./\.\./shared/' {} \; | while IFS= read -r f; do
      sed -i 's|\.\./\.\./shared/|../shared/|g' "$f" && echo "  fixed: $f"
    done
fi

echo "== 5. 验证 =="
echo -n "  skill目录数(除.system/shared): "
ls -d */ 2>/dev/null | grep -vE '^(\.system|shared)/$' | wc -l
echo "  残留单层引用(应为0): $(grep -rl '\.\./\.\./shared/' . --include='*.md' 2>/dev/null | grep -v '^./shared/' | wc -l)"
echo "完成。DSH 热生效，下次模型调用即见新技能。"
