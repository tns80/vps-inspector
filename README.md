# VPS Inspector

一个面向 Linux VPS 的**只读环境盘点 + 服务关系分析 + 部署冲突预检**工具。

VPS Inspector 尽量从 `/proc`、systemd、socket、network namespace、容器运行时、网络、防火墙、存储、cron 和包管理器等可观察事实出发，而不是依赖固定的“已知服务名称列表”。检查不到的范围会写入 `coverage.json`，不会把“没看到”误判成“没有”。

## v0.3.0

v0.3.0 在 v0.2.1 基础上完成了一轮源码审计和回归修复，重点增加：

- Deployment preflight summary：报告首页直接列出监听地址、端口、范围和归属
- `host netns -> Docker container netns` 关联
- 每个可检查 network namespace 的实际监听端口
- 区分 Docker 容器声明端口、容器内部实际监听、宿主机 published port
- Docker network/subnet 盘点
- `check` 支持 `network_cidrs` 与 Docker subnet 重叠检查
- Docker published port 按 HostIp + protocol + port 关联，避免只按端口号误归属
- 运行中 Docker published port 不再与实际 socket 重复报冲突；停止容器的未来端口占用仍保留
- IPv4/IPv6 wildcard 冲突判断参考 `net.ipv6.bindv6only`
- systemd effective startup：识别 enabled、socket-activated、static/dependency 等情况
- 多用户 systemd unit 目录发现；有用户 bus 时尝试只读查询 `systemctl --user`
- cron 实际任务解析，并对常见 secret-like 参数做脱敏
- nftables/iptables 关键规则摘要
- 恢复并保留 Podman、CRI、lsblk/mount、PSI、SSH/用户概要等 v0.2 采集能力
- 修复 Markdown 表格中的换行和 `|` 导致的错位

## 更新并扫描

已经 clone 过仓库：

```bash
cd /root/vps-inspector
git pull
python3 vps_inspector.py --version
```

应输出：

```text
vps-inspector 0.3.0
```

建议新建快照，不覆盖 v0.2：

```bash
rm -rf /root/vps-snapshot-v03
python3 vps_inspector.py scan -o /root/vps-snapshot-v03
cat /root/vps-snapshot-v03/report.md
```

如果已经是 root 登录，不需要 `sudo`。

输出：

```text
/root/vps-snapshot-v03/
├── report.md
├── inventory.json
└── coverage.json
```

`report.md` 给人阅读；`inventory.json` 是完整结构化事实；`coverage.json` 用来判断哪些检查完整、失败、超时、缺工具或权限不足。

## v0.3 报告重点

报告会优先展示：

```text
Deployment preflight summary
Long-running service relationships
Network namespaces and containers
Docker
Docker networks
systemd socket activation
Cron jobs
Firewall / NAT summary
User systemd discovery
Coverage / blind spots
```

例如：

```text
0.0.0.0:8443/tcp
  -> docker-proxy
  -> docker.service
  -> Docker: game-image-api-gateway-1

container netns
  -> game-image-api-api-1
  -> actual internal listeners
```

注意：Docker 的 `EXPOSE`/声明端口不是宿主机端口占用。v0.3 会尽量把以下三类分开：

```text
Declared container port
Actual listener inside container namespace
Host-published port
```

## 新服务部署冲突预检

复制示例：

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
  "network_cidrs": [
    "172.30.0.0/16"
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

运行：

```bash
python3 vps_inspector.py check \
  /root/vps-snapshot-v03/inventory.json \
  my-service.json
```

v0.3 当前检查：

- 当前实际 TCP/UDP host socket 冲突
- Docker published port 冲突
- 已停止 Docker 容器配置的未来 published port 冲突
- IPv4/IPv6 wildcard 地址占用关系
- Docker bind mount 与计划数据目录重叠
- 计划数据目录已存在
- 计划 `network_cidrs` 与 Docker network subnet 重叠

返回码：

```text
0 = 当前检查范围内未发现冲突
1 = 有非高危发现
2 = 有高危冲突
```

“未发现冲突”只表示当前 snapshot 和已实现规则范围内没有发现冲突，不代表外部云防火墙、负载均衡、DNS、远端 tunnel 控制面或未来状态一定没有影响。

## 系统升级前后对比

```bash
python3 vps_inspector.py scan -o /root/vps-before
# 手动升级 / 重启
python3 vps_inspector.py scan -o /root/vps-after

python3 vps_inspector.py diff \
  /root/vps-before/inventory.json \
  /root/vps-after/inventory.json \
  -o /root/vps-upgrade.diff

less /root/vps-upgrade.diff
```

`diff` 返回 `0` 表示没有差异，`1` 表示检测到差异。

## 主要采集范围

- 系统：发行版、内核、架构、虚拟化、init、uptime、boot id
- 进程：PID、PPID、用户、exe、cmdline、cgroup、netns、systemd service
- systemd：service、unit file 状态、socket activation、timer、effective startup
- user systemd：系统/用户 unit 目录；存在 user bus 时尝试查询运行态
- cron：`/etc/crontab`、`/etc/cron.d`、用户 crontab、周期目录
- socket：TCP/UDP 监听、PID、进程名、network namespace
- 网络：地址、路由、policy rule、forwarding、bindv6only、DNS、临时/保留端口范围
- 防火墙：nftables 或 iptables 关键规则摘要
- Docker：运行/停止容器、published port、mount、restart policy、network、subnet、container netns
- Podman / CRI：工具存在时尝试盘点
- 存储：df、inode、mountinfo、lsblk
- 软件包：dpkg/rpm/apk
- 资源：CPU、load、memory、swap、Linux PSI
- SSH / 用户：配置位置/哈希与 passwd 用户概要，不读取密码哈希或私钥

## 安全与覆盖原则

`scan` 默认不会安装、升级、删除、restart/stop/start 服务，不会修改 firewall/sysctl，也不会修改容器。它只写指定的报告目录。

`inventory.json` 可能包含 hostname、IP、文件路径、包版本、进程命令行和容器 metadata。脚本对常见 password/token/secret 参数做基础脱敏，但分享报告前仍建议人工检查。

Coverage 状态可能包括：

```text
ok
partial
unsupported
permission_denied
timeout
error
```

建议使用 root 扫描以获得更完整的 `/proc`、namespace、防火墙和容器可见性。

同一台 VPS 内的工具无法证明恶意 kernel/rootkit、不可信系统工具或被篡改内核接口不存在；云厂商 Security Group、外部 Load Balancer、DNS 和远端 tunnel 控制面也不属于本地扫描可以完全确认的范围。

## 依赖

必须：Linux、Python 3.8+。

推荐存在：`ss`、`ip`、`systemctl`、`nsenter`、`nft`/`iptables-save`、`lsblk`、`runuser`。Docker/Podman/crictl 只在相应环境存在时使用，缺失不会自动安装。