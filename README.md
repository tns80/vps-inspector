# VPS Inspector

一个以**只读盘点 + 部署冲突预检**为目标的 Linux VPS 环境检查工具。

它不依赖“已知服务名称列表”，而是尽量从 `/proc`、systemd、socket、network namespace、容器运行时、网络、存储和包管理器等底层事实出发，记录当前 VPS 上实际可观察到的对象。遇到权限不足、缺少命令或无法检查的范围，会明确写入 `coverage.json`，而不是把“没看到”误判成“没有”。

## v0.1.0 能做什么

- 系统：发行版、内核、架构、虚拟化、init、运行时长、root 权限状态
- 进程：PID、PPID、用户、可执行文件、工作目录、命令行、cgroup、namespace 信息
- systemd：当前/历史 unit、unit files、socket activation、timer
- cron：系统 cron 文件与目录清单
- 端口：TCP/UDP/Unix socket 监听情况
- network namespace：发现 `/proc/*/ns/net`，root 模式下尝试通过 `nsenter` 在每个 namespace 内执行宿主机 `ss`
- 网络：地址、路由、策略规则、转发状态、临时端口范围、保留端口、nftables/iptables
- Docker：运行中和已停止容器、端口映射、mount、restart policy、network、volume
- Podman：检测并盘点当前可见容器
- CRI：存在 `crictl` 时执行容器运行时盘点
- 存储：磁盘、文件系统、mount、inode
- 软件：dpkg/rpm 包清单、APT hold
- 资源：CPU、load、memory、swap、Linux PSI
- SSH / 用户：SSH 配置位置与哈希、系统用户概要
- Coverage：每个采集器记录 `ok / partial / unsupported / permission_denied / timeout / error`

## 安全设计

`scan` 默认只读，不会：

- 安装或卸载软件
- 升级系统
- restart/stop/start 服务
- 修改 firewall / sysctl
- 删除容器、镜像或 volume
- 修改现有配置

它只会创建自己的报告目录。系统命令本身可能产生正常日志，因此这里的“只读”不等于操作系统层面绝对零写入。

`inventory.json` 可能包含 hostname、IP、路径、包版本、进程参数和容器 metadata。脚本会做基础 secret-like 参数脱敏，但不要未经人工检查直接公开报告。

## 推荐运行方式

VPS 上直接复制：

```bash
git clone https://github.com/tns80/vps-inspector.git
cd vps-inspector
sudo python3 vps_inspector.py scan
```

成功后会看到：

```text
VPS Inspector 0.1.0 completed
Report:    vps-inspector-YYYYmmdd-HHMMSS/report.md
Inventory: vps-inspector-YYYYmmdd-HHMMSS/inventory.json
Coverage:  vps-inspector-YYYYmmdd-HHMMSS/coverage.json
Tip: run with sudo/root for broader process, namespace, firewall and container visibility.
```

查看人类可读报告：

```bash
sudo cat vps-inspector-*/report.md
```

建议第一次正式使用固定输出目录：

```bash
sudo python3 vps_inspector.py scan -o /root/vps-snapshot-before-upgrade
sudo less /root/vps-snapshot-before-upgrade/report.md
```

## 三个输出文件分别是什么

```text
/root/vps-snapshot-before-upgrade/
├── report.md       # 给人看的摘要
├── inventory.json  # 完整结构化盘点结果
└── coverage.json   # 哪些检查成功、失败、权限不足或工具缺失
```

其中最重要的不只是 `report.md`，还包括 `coverage.json`。例如：

```json
[
  {
    "collector": "sockets.namespace_coverage",
    "status": "partial",
    "detail": "discovered=6, proc_denied=1"
  },
  {
    "collector": "podman",
    "status": "unsupported",
    "detail": "podman not found"
  }
]
```

这种情况下不能说“系统只有 6 个 namespace”或“没有 Podman 容器”，只能说当前检查范围内发现了这些结果。

## 系统升级前后对比

升级前：

```bash
sudo python3 vps_inspector.py scan -o /root/vps-before
```

系统升级、重启后：

```bash
sudo python3 vps_inspector.py scan -o /root/vps-after
```

对比：

```bash
python3 vps_inspector.py diff \
  /root/vps-before/inventory.json \
  /root/vps-after/inventory.json \
  -o /root/vps-upgrade.diff

less /root/vps-upgrade.diff
```

`diff` 返回码：

```text
0 = 没有差异
1 = 检测到差异
```

## 新服务部署冲突预检

先复制示例：

```bash
cp deployment-plan.example.json my-service.json
nano my-service.json
```

示例：

```json
{
  "name": "new-service",
  "deployment": "docker",
  "network_mode": "bridge",
  "host_bindings": [
    {
      "address": "127.0.0.1",
      "port": 8080,
      "protocol": "tcp"
    }
  ],
  "data_paths": [
    "/srv/new-service/data"
  ],
  "domains": [
    "app.example.com"
  ],
  "memory_budget_mb": 512
}
```

检查：

```bash
python3 vps_inspector.py check \
  /root/vps-before/inventory.json \
  my-service.json
```

v0.1 当前会检查：

- 当前实际监听 TCP/UDP 端口冲突
- Docker published port 冲突
- 已停止 Docker 容器仍配置的 published port 冲突
- Docker bind mount 与计划数据目录重叠
- 当前机器上计划目录已经存在

例如：

```json
{
  "type": "port_conflict",
  "severity": "high",
  "wanted": {
    "address": "127.0.0.1",
    "port": 8080,
    "protocol": "tcp"
  },
  "existing": {
    "source": "socket",
    "protocol": "tcp",
    "address": "0.0.0.0",
    "port": 8080
  }
}
```

因为 `0.0.0.0:8080` 会覆盖所有 IPv4 本地地址，所以它与 `127.0.0.1:8080` 构成冲突。

`check` 返回码：

```text
0 = 当前规则和覆盖范围内未发现冲突
1 = 有非高危发现
2 = 有高危冲突
```

“未发现冲突”只代表当前 snapshot 的检查范围内没有发现，不代表该端口永久可用，也不代表外部 cloud firewall、负载均衡、DNS 或 tunnel 不会影响部署。

## 依赖

必须：

```text
Linux
Python 3.8+
```

推荐存在以下系统工具，可提升覆盖率：

```text
ss
ip
systemctl
nsenter
nft
lsblk
docker
podman
crictl
```

缺什么不会自动安装，而是明确记录为 `unsupported`。

## 关于“不会遗漏”

同一台 VPS 内运行的脚本无法对以下情况做绝对保证：恶意 kernel/rootkit、被篡改的内核接口、被劫持的系统工具，或者 VPS 外部的 cloud security group、load balancer、DNS、反向隧道控制面。

这个项目的目标是：

> 不因为“不认识某个新服务”就漏掉它；尽量从进程、socket、namespace、容器、启动机制和配置事实发现它，并明确告诉你哪些范围没有检查成功。

## v0.2 计划

- 更完整的 rootless Docker / Podman 多用户运行时枚举
- 更稳健的 `ss` 结构化解析和 PID ↔ socket ↔ systemd unit 关联
- nginx / Caddy / Traefik 等反向代理的 domain/upstream 关联
- Cloudflare Tunnel 等本机 tunnel 客户端检测
- APT/DNF 系统升级模拟与潜在 restart/reboot 影响分析
- Docker Compose project 关联
- 网络段/容器网段与新部署 subnet 冲突检查
- 语义化升级前后差异报告，而不是只做 JSON unified diff
- 可选 transient event 观察模式
