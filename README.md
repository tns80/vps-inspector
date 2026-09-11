# VPS Inspector

一个以 **只读盘点 + 服务关系分析 + 部署冲突预检** 为目标的 Linux VPS 环境检查工具。

VPS Inspector 不依赖固定的“已知服务名称列表”，而是尽量从 `/proc`、systemd、socket、network namespace、容器运行时、网络、存储和包管理器等事实出发。遇到权限不足、命令缺失或无法检查的范围，会明确写入 `coverage.json`，不会把“没看到”误判成“没有”。

## v0.2.0 新增

v0.2.0 在 v0.1 采集层基础上增加 **服务关系报告**：

- 结构化解析 systemd service 状态
- 区分正在运行的 service 与 enabled-but-inactive service
- 展示 systemd timer 和 socket activation
- 从进程 cgroup 识别所属 systemd service
- 从 `ss` 提取 socket PID / process name
- 关联 `service -> PID -> socket/port`
- 把 cron/周期目录直接写入 `report.md`
- 把未能关联到 systemd service 的监听端口单独列出
- `inventory.json` 新增 `relationships` 数据
- 保留 `scan / diff / check` 三种模式

## 更新到 v0.2.0

已经 clone 过仓库：

```bash
cd /root/vps-inspector
git pull
python3 vps_inspector.py --version
```

应输出：

```text
vps-inspector 0.2.0
```

重新扫描：

```bash
rm -rf /root/vps-snapshot-v02
python3 vps_inspector.py scan -o /root/vps-snapshot-v02
cat /root/vps-snapshot-v02/report.md
```

如果当前已经是 root 登录，不需要再写 `sudo`。

## 输出文件

```text
/root/vps-snapshot-v02/
├── report.md       # 给人看的服务关系和环境摘要
├── inventory.json  # 完整结构化盘点结果
└── coverage.json   # 每个采集器的覆盖状态
```

### v0.2 report.md 重点内容

```text
Summary
Service relationships
Enabled but currently inactive services
systemd timers
systemd socket activation
Cron / periodic directories
Listening ports + Related service
Listeners not mapped to a systemd service
Network namespace coverage
Docker
Coverage / blind spots
```

理想关联效果：

```text
22/tcp
  -> PID 7901 sshd
  -> ssh.service
  -> active/running
  -> enabled
```

## 安全设计

`scan` 默认不会：

- 安装或卸载软件
- 升级系统
- start/stop/restart 服务
- 修改 firewall / sysctl
- 删除容器、镜像或 volume
- 修改现有配置

它只会创建指定的报告目录。`inventory.json` 可能包含 hostname、IP、路径、包版本、进程参数和容器 metadata。脚本进行基础 secret-like 参数脱敏，但分享扫描结果前仍应人工检查。

## 系统升级前后对比

升级前：

```bash
python3 vps_inspector.py scan -o /root/vps-before
```

升级、重启后：

```bash
python3 vps_inspector.py scan -o /root/vps-after
```

对比：

```bash
python3 vps_inspector.py diff \
  /root/vps-before/inventory.json \
  /root/vps-after/inventory.json \
  -o /root/vps-upgrade.diff

less /root/vps-upgrade.diff
```

`diff` 返回码：`0` 无差异，`1` 有差异。

## 新服务部署冲突预检

```bash
cp deployment-plan.example.json my-service.json
nano my-service.json

python3 vps_inspector.py check \
  /root/vps-snapshot-v02/inventory.json \
  my-service.json
```

当前会检查：

- 当前实际 TCP/UDP 监听端口冲突
- Docker published port 冲突
- 已停止 Docker 容器仍配置的 published port 冲突
- Docker bind mount 与计划数据目录重叠
- 计划数据目录已经存在

`check` 返回码：`0` 未发现冲突，`1` 有非高危发现，`2` 有高危冲突。

“未发现冲突”只代表当前 snapshot 已检查范围内没有发现，不代表端口永久可用。

## 主要采集范围

- 系统：发行版、内核、架构、虚拟化、init、uptime
- 进程：PID、PPID、用户、exe、cwd、cmdline、cgroup、netns、systemd service
- systemd：service、unit file、timer、socket activation
- cron：系统 cron 文件/周期目录清单
- 网络：TCP/UDP/Unix socket、namespace、地址、路由、policy rule、forwarding、nftables/iptables
- Docker：运行/停止容器、端口映射、mount、restart policy、network、volume
- Podman / CRI：存在时盘点
- 存储：filesystem、mount、inode、block device
- 软件包：dpkg/rpm、APT hold
- 资源：CPU/load/memory/swap/PSI
- SSH / 用户概要

## Coverage 状态

```text
ok
partial
unsupported
permission_denied
timeout
error
```

检查不到就明确报告，不会自动显示“正常”。

## 依赖

必须：Linux、Python 3.8+。

推荐存在：`ss`、`ip`、`systemctl`、`nsenter`、`nft`、`lsblk`。Docker/Podman/crictl 只在相应运行时存在时使用，缺失不会自动安装。

## 关于“不会遗漏”

同一台 VPS 内运行的脚本无法对恶意 kernel/rootkit、被篡改的系统工具，以及 VPS 外部的 cloud firewall、load balancer、DNS、外部 tunnel 控制面做绝对保证。

项目目标是：**不因为“不认识某个新服务”就漏掉可观察对象；尽量从进程、socket、namespace、容器和启动机制发现它，并明确告诉你哪些范围没有检查成功。**

## v0.3 后续方向

- rootless Docker / Podman 多用户运行时枚举
- nginx / Caddy / Traefik domain/upstream 关联
- Cloudflare Tunnel 等 tunnel client 识别
- Docker Compose project 关联
- 网络段/容器 subnet 冲突检查
- APT/DNF 升级模拟与 restart/reboot 风险
- 语义化 snapshot diff
- 可选 transient event 观察模式
