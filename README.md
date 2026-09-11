# VPS Inspector

一个面向 Linux VPS 的**只读环境盘点 + 服务关系分析 + 部署冲突预检**工具。

VPS Inspector 尽量从 `/proc`、systemd、socket、network namespace、容器运行时、网络、防火墙、存储、cron 和包管理器等可观察事实出发，而不是依赖固定的“已知服务名称列表”。检查不到的范围会写入 `coverage.json`，不会把“没看到”误判成“没有”。

## v0.4.0

v0.4.0 的重点是把默认终端输出从“完整技术报告”改成“部署决策摘要”。

默认 `scan` 只在终端显示一屏左右的重要信息：

- `READY / CAUTION / HIGH RISK` 总体状态
- 关键采集覆盖状态
- 公网/全接口监听端口及归属
- Docker 真正发布到宿主机的端口
- socket-activated 启动方式，例如 SSH
- root crontab、`@reboot`、user-systemd、非 systemd 宿主机进程摘要
- Docker subnet
- 防火墙引用但当前 Docker network 中不存在的私有网段提示
- RAM、Swap、根分区剩余空间、系统 load
- 最多几条高优先级 Findings
- `report.md / inventory.json / coverage.json` 路径

完整技术信息仍然写入文件，不会因为终端简化而减少采集内容。

### 状态含义

```text
READY      当前实现范围内没有发现高优先级部署警告
CAUTION    有值得人工确认的项目，例如自定义 cron、@reboot、非标准进程、资源偏低或非关键采集不完整
HIGH RISK  关键采集失败/超时/权限不足，或存在无法归属的公网/全接口监听，结果不足以可靠判断部署风险
```

注意：在没有提供具体 deployment plan 时，80/443 等端口已经被正常服务占用并不会自动把扫描状态判为 `HIGH RISK`；端口是否与新项目冲突应继续用 `check` 判断。

## 更新并扫描

已经 clone 过仓库：

```bash
cd /root/vps-inspector
git pull
python3 vps_inspector.py --version
```

应输出：

```text
vps-inspector 0.4.0
```

建议创建新快照：

```bash
rm -rf /root/vps-snapshot-v04
python3 vps_inspector.py scan -o /root/vps-snapshot-v04
```

默认终端只显示关键摘要。

如果需要同时在终端看到额外的 inventory 计数：

```bash
python3 vps_inspector.py scan \
  -o /root/vps-snapshot-v04 \
  --verbose
```

完整输出文件始终存在：

```text
/root/vps-snapshot-v04/
├── report.md       # 完整人类可读技术报告
├── inventory.json  # 完整结构化盘点事实
└── coverage.json   # 采集覆盖、失败、超时和权限状态
```

## 默认终端摘要示例

```text
VPS Inspector 0.4.0
Host: example-vps
OS: Ubuntu 24.04 LTS
Scan coverage: OK

DEPLOYMENT STATUS: CAUTION

Public / wildcard listeners:
  TCP 22    -> ssh.service (socket-activated) [0.0.0.0, ::]
  TCP 80    -> derp.service [*]
  TCP 443   -> derp.service [*]
  TCP 8443  -> Docker:gateway, docker.service [0.0.0.0, ::]

Docker published ports:
  TCP 0.0.0.0:8443 -> gateway
  TCP :::8443      -> gateway

Non-standard startup:
  cron jobs: 12 total; root crontab: 3; @reboot: 1
  user systemd: 2 active/enabled unit(s)
  unmanaged host processes: 1 actionable (4 total)

Network:
  Docker subnets: 172.18.0.0/16, 172.19.0.0/16

Resources:
  RAM: 3.9 GiB free / 7.8 GiB
  Swap: 0.0 B used / 2.0 GiB
  Root disk: 40.0 GiB free / 80.0 GiB
  Load: 0.12 0.08 0.06

Findings:
  [WARN] 3 root crontab job(s) detected
  [WARN] 1 @reboot cron job(s) detected

Full report: /root/vps-snapshot-v04/report.md
Inventory:   /root/vps-snapshot-v04/inventory.json
Coverage:    /root/vps-snapshot-v04/coverage.json
```

## v0.3 / v0.4 主要能力

- 结构化 systemd service、socket、timer 和 effective startup
- 区分 `active/running` 与 `active/exited`
- `service -> PID -> listener` 关联
- `host netns -> Docker container netns` 关联
- 每个可检查 network namespace 的实际监听端口
- 区分 Docker 声明端口、容器内部实际监听、宿主机 published port
- Docker published port 按 HostIp + protocol + port 关联
- Docker network/subnet 盘点
- `check` 支持 Docker subnet overlap
- IPv4/IPv6 wildcard 冲突判断参考 `net.ipv6.bindv6only`
- 多用户 systemd unit 目录发现；存在 user bus 时尝试只读查询 `systemctl --user`
- cron 实际任务解析和常见 secret-like 参数脱敏
- nftables/iptables 关键规则摘要
- 非 systemd 宿主机进程摘要
- 扫描器自身进程从业务进程盘点中排除
- Podman、CRI、lsblk/mount、PSI、SSH/用户概要等采集

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
  /root/vps-snapshot-v04/inventory.json \
  my-service.json
```

当前 `check` 会检查：

- 当前实际 TCP/UDP host socket 冲突
- Docker published port 冲突
- 已停止 Docker 容器配置的未来 published port 冲突
- IPv4/IPv6 wildcard / dual-stack 地址占用关系
- Docker bind mount 与计划数据目录重叠
- 计划数据目录已存在
- `network_cidrs` 与 Docker network subnet 重叠

返回码：

```text
0 = 当前检查范围内未发现冲突
1 = 有非高危发现
2 = 有高危冲突
```

## 系统升级前后对比

```bash
python3 vps_inspector.py scan -o /root/vps-before
# 手动升级 / 重启
python3 vps_inspector.py scan -o /root/vps-after

python3 vps_inspector.py diff \
  /root/vps-before/inventory.json \
  /root/vps-after/inventory.json \
  -o /root/vps-upgrade.diff
```

`diff` 返回 `0` 表示没有差异，`1` 表示检测到差异。

## 安全与覆盖原则

`scan` 默认不会安装、升级、删除、start/stop/restart 服务，不会修改 firewall/sysctl，也不会修改容器。它只写指定的报告目录。

`inventory.json` 可能包含 hostname、IP、文件路径、包版本、进程命令行和容器 metadata。脚本会对常见 password/token/secret 参数做基础脱敏，但分享结果前仍建议人工检查。

Coverage 状态包括：

```text
ok
partial
unsupported
permission_denied
timeout
error
```

`partial` 也包括命令成功但输出超过采集上限而被截断的情况。

建议使用 root 扫描以获得更完整的 `/proc`、namespace、防火墙和容器可见性。

同一台 VPS 内的工具无法证明恶意 kernel/rootkit、不可信系统工具或被篡改内核接口不存在；云厂商 Security Group、外部 Load Balancer、DNS 和远端 tunnel 控制面也不属于本地扫描可以完全确认的范围。

## 依赖

必须：Linux、Python 3.8+。

推荐存在：`ss`、`ip`、`systemctl`、`nsenter`、`nft`/`iptables-save`、`lsblk`、`runuser`。Docker/Podman/crictl 只在相应环境存在时使用，缺失不会自动安装。