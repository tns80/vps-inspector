# VPS Inspector

一个面向 Linux VPS 的**只读环境盘点工具**。目标不是维护一份“已知服务名称列表”，而是从系统实际可观察对象出发，盘点进程、端口、systemd、网络命名空间、容器、网络、磁盘、软件包和资源状态，帮助你在升级系统或部署新服务前了解现有环境。

> 当前版本：v0.1.0（第一版）。它会明确记录覆盖缺口，不宣称能够从一台可能已被内核级恶意程序控制的主机内部证明“绝无隐藏对象”。

## 第一版覆盖范围

- 系统：发行版、内核、架构、虚拟化、启动 ID、运行时间、当前权限
- 进程：直接枚举 `/proc`，记录 PID/PPID、用户、命令、可执行文件、工作目录、cgroup、网络命名空间
- 端口：TCP/UDP 监听和 Unix socket，保留进程关联信息
- 网络命名空间：从 `/proc/*/ns/net` 枚举；root + `nsenter` + `ss` 时逐个命名空间检查监听端口
- systemd：当前/全部 units、unit files、socket units、timers、failed units
- 定时任务：`/etc/crontab`、`/etc/cron.d` 和常见用户 crontab spool（权限允许时）
- Docker：强制查询本机 `/var/run/docker.sock`，列出运行/停止容器、端口、网络、挂载、重启策略和标签
- Podman：当前用户可见容器；明确提示其他用户 rootless 容器的可见性限制
- 网络：地址、路由、策略路由、nftables/iptables、IPv4/IPv6 转发、临时端口范围/保留端口
- 存储：文件系统、inode、挂载和块设备
- 软件包：支持 dpkg、rpm、apk
- 资源：CPU 数、loadavg、内存和 PSI pressure
- 维护：选定 SSH 有效配置、reboot-required 状态
- 输出：`report.md`、`inventory.json`、`coverage.json`
- 快照比较：`diff` 子命令

## 最推荐的运行方式

先下载脚本：

```bash
curl -fL https://raw.githubusercontent.com/tns80/vps-inspector/main/vps_inspector.py -o vps_inspector.py
chmod 700 vps_inspector.py
```

仓库当前为 Private 时，GitHub 的 raw URL 不能匿名下载。此时可以在你自己的电脑 `git clone` 后上传脚本，或者把仓库改成 Public。也可以直接从 GitHub 网页复制 `vps_inspector.py` 到 VPS。

先以普通用户运行也可以，但为了最大化 `/proc`、端口、防火墙、网络命名空间、Docker 和系统配置的可见范围，正式盘点推荐：

```bash
sudo python3 ./vps_inspector.py scan -o ./vps-scan-before-change
```

完成后：

```bash
sudo less ./vps-scan-before-change/report.md
sudo less ./vps-scan-before-change/coverage.json
```

如果你要把报告复制给 ChatGPT 或其他人分析，优先复制 `report.md`；需要更深入分析时再提供 `inventory.json` 和 `coverage.json`。输出可能包含主机名、IP、进程命令、路径、容器标签等环境信息，分享前请自行检查。

## 升级前后比较

升级前：

```bash
sudo python3 ./vps_inspector.py scan -o ./before
```

升级或部署完成后：

```bash
sudo python3 ./vps_inspector.py scan -o ./after
```

比较两个机器可读快照：

```bash
python3 ./vps_inspector.py diff ./before/inventory.json ./after/inventory.json > diff.txt
less diff.txt
```

## 输出说明

### `report.md`

给人阅读的摘要，重点展示覆盖情况、进程数量、网络命名空间、容器、监听端口、systemd、磁盘和网络状态。

### `inventory.json`

完整的结构化采集结果。后续版本的冲突检查、升级风险分析和自动化比较都基于它。

### `coverage.json`

非常重要。记录每个采集模块是否成功，以及工具本身已知的观察边界。`unsupported`、`partial`、`permission_denied`、`error` 都不应该被解释成“该对象不存在”。

## 安全设计

脚本第一版遵循这些原则：

1. 不安装/卸载软件，不运行 apt/yum/dnf upgrade，不启动、停止或重启服务。
2. 不修改防火墙、sysctl、网络、容器或 systemd 配置。
3. 不执行扫描过程中发现的未知二进制文件。
4. 外部命令使用固定参数、超时和输出大小限制。
5. 对常见 `password=...`、`token=...`、`secret=...`、`api_key=...` 形式做基础脱敏。
6. 输出目录权限设为仅当前用户可访问（0700）。
7. Docker 查询显式指向本机 `/var/run/docker.sock`，避免当前 Docker context 意外指向其他服务器。

基础脱敏无法覆盖所有软件自定义的秘密格式，因此报告仍应按敏感系统信息处理。

## 当前明确限制

- 单次扫描是时间点快照，极短生命周期进程可能在扫描间隙出现并退出。
- 如果 VPS 内核或系统工具已经被 rootkit/攻击者控制，主机内部脚本无法独立证明采集结果可信。
- 云厂商安全组、外部负载均衡、DNS/CDN 控制面、第三方 Tunnel 等外部状态需要对应平台 API 才能完整核验。
- v0.1 不会穷举解析所有软件的配置文件；未知软件仍尽可能通过进程、socket、cgroup 和网络命名空间呈现。
- rootless Docker/Podman 可能存在于不同用户会话；v0.1 已标记这一缺口，后续版本会加强多用户运行时发现。
- 当前 `diff` 是结构化 JSON 的统一 diff，还没有进行“语义级变化归类”。

## Roadmap

下一阶段计划：

- `check`：读取 `deployment-plan.json`，判断新服务的端口、目录、网络、资源等冲突
- 更强的 rootless Docker/Podman/containerd/CRI 发现
- socket → PID → systemd unit → container 的统一关联图
- systemd 用户级服务、更多启动机制和 supervisor/PM2 等进程管理器识别
- Docker Compose 项目关联和潜在端口（包括停止容器）分析
- 配置声明端口与实际监听端口交叉验证
- apt/dnf 升级模拟与升级风险报告（仍保持默认只读）
- 语义化 snapshot diff
- 可选 `observe` 模式捕获短生命周期变化

## Python 版本

建议 Python 3.9+。不依赖第三方 Python 包。

## License

第一版暂未添加开源许可证。在你确定希望使用 MIT、Apache-2.0 或保持私有后再添加。
