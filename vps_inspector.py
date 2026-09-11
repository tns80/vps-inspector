#!/usr/bin/env python3
"""VPS Inspector v0.1.0

Read-only Linux VPS inventory and deployment conflict preflight tool.
Designed to prefer observable facts over service-name heuristics and to report
coverage gaps explicitly instead of treating inaccessible areas as empty.
"""

from __future__ import annotations

import argparse
import datetime as dt
import difflib
import hashlib
import json
import os
import pathlib
import platform
import pwd
import re
import shutil
import socket
import subprocess
from typing import Any, Dict, Iterable, List, Optional, Tuple

VERSION = "0.1.0"
DEFAULT_TIMEOUT = 8
MAX_OUTPUT = 2_000_000
SENSITIVE_ARG_PATTERNS = [
    re.compile(r"(?i)(password|passwd|token|secret|api[_-]?key|authorization)=([^\s]+)"),
    re.compile(r"(?i)(--password|--passwd|--token|--secret|--api-key)\s+([^\s]+)"),
]


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def redact(text: str) -> str:
    out = text
    for pat in SENSITIVE_ARG_PATTERNS:
        if pat.pattern.startswith("(?i)(--"):
            out = pat.sub(lambda m: f"{m.group(1)} <redacted>", out)
        else:
            out = pat.sub(lambda m: f"{m.group(1)}=<redacted>", out)
    return out


def read_text(path: str, limit: int = 200_000) -> Optional[str]:
    try:
        with open(path, "rb") as f:
            data = f.read(limit + 1)
        if len(data) > limit:
            data = data[:limit] + b"\n...<truncated>"
        return data.decode("utf-8", "replace")
    except (OSError, PermissionError):
        return None


def read_json_file(path: pathlib.Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def which(name: str) -> Optional[str]:
    return shutil.which(name)


class Inspector:
    def __init__(self, timeout: int = DEFAULT_TIMEOUT, strict: bool = False):
        self.timeout = timeout
        self.strict = strict
        self.coverage: List[Dict[str, Any]] = []
        self.inventory: Dict[str, Any] = {
            "schema_version": 1,
            "tool": {"name": "vps-inspector", "version": VERSION},
            "collected_at": utc_now(),
        }

    def mark(self, collector: str, status: str, detail: str = "", **extra: Any) -> None:
        row = {"collector": collector, "status": status, "detail": detail}
        row.update(extra)
        self.coverage.append(row)

    def run(self, cmd: List[str], collector: str, timeout: Optional[int] = None,
            env: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        if not which(cmd[0]):
            self.mark(collector, "unsupported", f"command not found: {cmd[0]}")
            return {"ok": False, "status": "unsupported", "stdout": "", "stderr": ""}
        safe_env = os.environ.copy()
        if env:
            safe_env.update(env)
        safe_env.setdefault("LC_ALL", "C")
        safe_env.setdefault("LANG", "C")
        try:
            p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                               errors="replace", timeout=timeout or self.timeout, env=safe_env, check=False)
            stdout = p.stdout[:MAX_OUTPUT]
            stderr = p.stderr[:MAX_OUTPUT]
            status = "ok" if p.returncode == 0 else "error"
            if p.returncode != 0 and any(x in stderr.lower() for x in ("permission denied", "operation not permitted")):
                status = "permission_denied"
            self.mark(collector, status, f"exit={p.returncode}", command=" ".join(cmd))
            return {"ok": p.returncode == 0, "status": status, "stdout": stdout, "stderr": stderr, "returncode": p.returncode}
        except subprocess.TimeoutExpired as e:
            self.mark(collector, "timeout", f"timeout after {timeout or self.timeout}s", command=" ".join(cmd))
            return {"ok": False, "status": "timeout", "stdout": (e.stdout or "")[:MAX_OUTPUT], "stderr": (e.stderr or "")[:MAX_OUTPUT]}
        except Exception as e:
            self.mark(collector, "error", f"{type(e).__name__}: {e}", command=" ".join(cmd))
            return {"ok": False, "status": "error", "stdout": "", "stderr": str(e)}

    def collect_system(self) -> None:
        os_release = {}
        txt = read_text("/etc/os-release")
        if txt:
            for line in txt.splitlines():
                if "=" in line and not line.startswith("#"):
                    k, v = line.split("=", 1)
                    os_release[k] = v.strip().strip('"')
        self.inventory["system"] = {
            "hostname": socket.gethostname(), "fqdn": socket.getfqdn(), "platform": platform.platform(),
            "kernel": platform.release(), "architecture": platform.machine(), "python": platform.python_version(),
            "uid": os.geteuid(), "is_root": os.geteuid() == 0, "os_release": os_release,
            "boot_id": (read_text("/proc/sys/kernel/random/boot_id") or "").strip(), "uptime_seconds": self._uptime(),
            "virtualization": self._virtualization(), "init": self._init_name(),
        }
        self.mark("system", "ok")

    def _uptime(self) -> Optional[float]:
        txt = read_text("/proc/uptime")
        try:
            return float(txt.split()[0]) if txt else None
        except Exception:
            return None

    def _virtualization(self) -> Dict[str, Any]:
        if which("systemd-detect-virt"):
            r = self.run(["systemd-detect-virt"], "virtualization")
            return {"type": r["stdout"].strip() if r["ok"] else None, "detail": r["stderr"].strip()}
        return {"type": None, "detail": "systemd-detect-virt unavailable"}

    def _init_name(self) -> Optional[str]:
        try:
            return os.path.basename(os.readlink("/proc/1/exe"))
        except OSError:
            return None

    def collect_processes(self) -> None:
        rows: List[Dict[str, Any]] = []
        denied = 0
        for name in os.listdir("/proc"):
            if not name.isdigit():
                continue
            pid = int(name)
            base = f"/proc/{pid}"
            try:
                status = read_text(f"{base}/status", 50_000) or ""
                data = {}
                for line in status.splitlines():
                    if ":" in line:
                        k, v = line.split(":", 1)
                        if k in {"Name", "State", "PPid", "Uid", "Gid", "Threads", "NSpid"}:
                            data[k] = v.strip()
                cmdraw = read_text(f"{base}/cmdline", 100_000)
                cmdline = redact(cmdraw.replace("\x00", " ").strip()) if cmdraw is not None else ""
                exe = cwd = None
                try: exe = os.readlink(f"{base}/exe")
                except OSError: pass
                try: cwd = os.readlink(f"{base}/cwd")
                except OSError: pass
                cgroup = read_text(f"{base}/cgroup", 50_000)
                stat = read_text(f"{base}/stat", 50_000)
                start_ticks = None
                if stat:
                    parts = stat.split()
                    if len(parts) > 21: start_ticks = parts[21]
                uid = user = None
                if "Uid" in data:
                    try:
                        uid = int(data["Uid"].split()[0]); user = pwd.getpwuid(uid).pw_name
                    except Exception: pass
                rows.append({"pid": pid, "ppid": int(data.get("PPid", "0") or 0), "name": data.get("Name"),
                             "state": data.get("State"), "uid": uid, "user": user, "threads": data.get("Threads"),
                             "nspid": data.get("NSpid"), "exe": exe, "cwd": cwd, "cmdline": cmdline[:4000],
                             "cgroup": (cgroup or "")[:4000], "start_ticks": start_ticks})
            except PermissionError:
                denied += 1
            except FileNotFoundError:
                continue
            except Exception:
                continue
        rows.sort(key=lambda x: x["pid"])
        self.inventory["processes"] = rows
        self.mark("processes", "partial" if denied else "ok", f"processes={len(rows)}, denied={denied}")

    def collect_systemd(self) -> None:
        if not which("systemctl"):
            self.inventory["systemd"] = {"available": False}; self.mark("systemd", "unsupported", "systemctl not found"); return
        out: Dict[str, Any] = {"available": True}
        cmds = {"units": ["systemctl", "list-units", "--all", "--no-pager", "--no-legend"],
                "unit_files": ["systemctl", "list-unit-files", "--no-pager", "--no-legend"],
                "sockets": ["systemctl", "list-sockets", "--all", "--no-pager", "--no-legend"],
                "timers": ["systemctl", "list-timers", "--all", "--no-pager", "--no-legend"]}
        for key, cmd in cmds.items():
            r = self.run(cmd, f"systemd.{key}", timeout=12); out[key] = redact(r["stdout"])
        self.inventory["systemd"] = out

    def collect_cron(self) -> None:
        paths = ["/etc/crontab", "/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.weekly", "/etc/cron.monthly", "/var/spool/cron", "/var/spool/cron/crontabs"]
        entries = []
        for p in paths:
            path = pathlib.Path(p)
            try:
                if path.is_dir(): entries.append({"path": p, "type": "dir", "entries": sorted(x.name for x in path.iterdir())})
                elif path.exists(): entries.append({"path": p, "type": "file", "sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "size": path.stat().st_size})
            except PermissionError:
                entries.append({"path": p, "error": "permission_denied"})
        self.inventory["cron"] = entries; self.mark("cron", "ok")

    def collect_sockets(self) -> None:
        out: Dict[str, Any] = {"network_namespaces": []}
        if not which("ss"):
            self.inventory["sockets"] = out; self.mark("sockets", "unsupported", "ss not found"); return
        current = self.run(["ss", "-H", "-lntup"], "sockets.current.tcpudp")
        unix = self.run(["ss", "-H", "-lxup"], "sockets.current.unix")
        out["current_namespace"] = {"tcp_udp_listen_raw": redact(current["stdout"]), "unix_listen_raw": redact(unix["stdout"]), "parsed_tcp_udp": self._parse_ss(current["stdout"])}
        ns_map: Dict[str, int] = {}; denied = 0
        for name in os.listdir("/proc"):
            if not name.isdigit(): continue
            try: ns_map.setdefault(os.readlink(f"/proc/{name}/ns/net"), int(name))
            except PermissionError: denied += 1
            except OSError: continue
        for ns, pid in sorted(ns_map.items()):
            row: Dict[str, Any] = {"namespace": ns, "representative_pid": pid}
            if os.geteuid() == 0 and which("nsenter"):
                r = self.run(["nsenter", "-t", str(pid), "-n", "ss", "-H", "-lntup"], f"sockets.netns.{pid}")
                row.update({"status": r["status"], "tcp_udp_listen_raw": redact(r["stdout"]), "parsed_tcp_udp": self._parse_ss(r["stdout"])})
            else:
                row.update({"status": "not_inspected", "reason": "requires root and nsenter"})
            out["network_namespaces"].append(row)
        out["namespace_discovery_denied"] = denied; self.inventory["sockets"] = out
        status = "partial" if denied or any(x.get("status") != "ok" for x in out["network_namespaces"]) else "ok"
        self.mark("sockets.namespace_coverage", status, f"discovered={len(ns_map)}, proc_denied={denied}")

    def _parse_ss(self, text: str) -> List[Dict[str, Any]]:
        rows = []
        for line in text.splitlines():
            parts = line.split()
            if len(parts) < 5: continue
            proto, state, local = parts[0], parts[1], parts[4]
            process = " ".join(parts[6:]) if len(parts) > 6 else ""
            host, port = self._split_host_port(local)
            rows.append({"proto": proto, "state": state, "local": local, "address": host, "port": port, "process": redact(process)})
        return rows

    @staticmethod
    def _split_host_port(value: str) -> Tuple[Optional[str], Optional[int]]:
        m = re.match(r"^\[(.*)\]:(\d+)$", value)
        if m: return m.group(1), int(m.group(2))
        if ":" in value:
            host, p = value.rsplit(":", 1)
            if p.isdigit(): return host, int(p)
        return value or None, None

    def collect_network(self) -> None:
        net: Dict[str, Any] = {}
        for key, cmd in {"addresses": ["ip", "-j", "address"], "routes": ["ip", "-j", "route", "show", "table", "all"], "rules": ["ip", "-j", "rule"]}.items():
            r = self.run(cmd, f"network.{key}")
            if r["ok"]:
                try: net[key] = json.loads(r["stdout"])
                except json.JSONDecodeError: net[key] = r["stdout"]
            else: net[key] = {"error": r["status"], "stderr": r["stderr"][:2000]}
        net["dns_resolv_conf"] = (read_text("/etc/resolv.conf", 50_000) or "")[:50_000]
        for key, path in {"ip_forward_v4": "/proc/sys/net/ipv4/ip_forward", "ip_local_port_range": "/proc/sys/net/ipv4/ip_local_port_range",
                          "ip_local_reserved_ports": "/proc/sys/net/ipv4/ip_local_reserved_ports", "ipv6_forwarding_all": "/proc/sys/net/ipv6/conf/all/forwarding"}.items():
            net[key] = (read_text(path, 10_000) or "").strip() or None
        if which("nft"):
            r = self.run(["nft", "-j", "list", "ruleset"], "network.nft", timeout=12)
            if r["ok"]:
                try: net["nftables"] = json.loads(r["stdout"])
                except json.JSONDecodeError: net["nftables_raw"] = r["stdout"]
        elif which("iptables-save"):
            r = self.run(["iptables-save"], "network.iptables", timeout=12); net["iptables_save"] = r["stdout"]
        self.inventory["network"] = net

    def collect_container_runtime(self, runtime: str) -> Dict[str, Any]:
        out: Dict[str, Any] = {"available": bool(which(runtime))}
        if not out["available"]:
            self.mark(runtime, "unsupported", f"{runtime} not found"); return out
        if runtime == "docker":
            r = self.run(["docker", "info", "--format", "{{json .}}"], "docker.info", timeout=12); out["info_status"] = r["status"]
            if r["ok"]:
                try: out["info"] = json.loads(r["stdout"])
                except json.JSONDecodeError: out["info_raw"] = r["stdout"]
            ps = self.run(["docker", "ps", "-a", "--no-trunc", "--format", "{{json .}}"], "docker.ps", timeout=12)
            containers, ids = [], []
            for line in ps["stdout"].splitlines():
                try:
                    item = json.loads(line); containers.append(item)
                    if item.get("ID"): ids.append(item["ID"])
                except json.JSONDecodeError: pass
            out["containers_summary"] = containers
            if ids:
                ins = self.run(["docker", "inspect", *ids], "docker.inspect", timeout=20)
                if ins["ok"]:
                    try: out["containers"] = [self._sanitize_container(x) for x in json.loads(ins["stdout"])]
                    except json.JSONDecodeError: out["containers_inspect_raw"] = redact(ins["stdout"])
            for key, cmd in {"networks": ["docker", "network", "ls", "--format", "{{json .}}"], "volumes": ["docker", "volume", "ls", "--format", "{{json .}}"]}.items():
                rr = self.run(cmd, f"docker.{key}"); out[key] = [json.loads(x) for x in rr["stdout"].splitlines() if x.strip().startswith("{")]
            out["local_socket_candidates"] = self._docker_socket_candidates()
        elif runtime == "podman":
            r = self.run(["podman", "info", "--format", "json"], "podman.info", timeout=12); out["info_status"] = r["status"]
            try: out["info"] = json.loads(r["stdout"]) if r["ok"] else None
            except json.JSONDecodeError: out["info_raw"] = r["stdout"]
            ps = self.run(["podman", "ps", "-a", "--no-trunc", "--format", "json"], "podman.ps", timeout=12)
            try: out["containers"] = json.loads(ps["stdout"]) if ps["ok"] else []
            except json.JSONDecodeError: out["containers_raw"] = ps["stdout"]
        return out

    def _sanitize_container(self, x: Dict[str, Any]) -> Dict[str, Any]:
        cfg, host, net, state = x.get("Config") or {}, x.get("HostConfig") or {}, x.get("NetworkSettings") or {}, x.get("State") or {}
        labels = cfg.get("Labels") or {}; safe_labels = {k: v for k, v in labels.items() if not re.search(r"(?i)(secret|token|password|key)", k)}
        mounts = [{k: m.get(k) for k in ("Type", "Name", "Source", "Destination", "Mode", "RW", "Propagation")} for m in x.get("Mounts") or []]
        return {"Id": x.get("Id"), "Name": x.get("Name"), "Created": x.get("Created"), "Path": x.get("Path"),
                "Args": [redact(str(a)) for a in (x.get("Args") or [])], "State": {k: state.get(k) for k in ("Status", "Running", "Paused", "Restarting", "OOMKilled", "Dead", "Pid", "ExitCode", "StartedAt", "FinishedAt")},
                "Image": x.get("Image"), "Config": {"Hostname": cfg.get("Hostname"), "Image": cfg.get("Image"), "ExposedPorts": cfg.get("ExposedPorts"), "Labels": safe_labels, "User": cfg.get("User"), "WorkingDir": cfg.get("WorkingDir")},
                "HostConfig": {"NetworkMode": host.get("NetworkMode"), "PortBindings": host.get("PortBindings"), "RestartPolicy": host.get("RestartPolicy"), "Binds": host.get("Binds"), "Privileged": host.get("Privileged")},
                "NetworkSettings": {"Ports": net.get("Ports"), "Networks": net.get("Networks"), "SandboxKey": net.get("SandboxKey")}, "Mounts": mounts}

    def _docker_socket_candidates(self) -> List[Dict[str, Any]]:
        cands = []
        for p in [pathlib.Path("/var/run/docker.sock"), pathlib.Path("/run/docker.sock")]:
            if p.exists(): cands.append({"path": str(p), "owner_uid": p.stat().st_uid})
        run_user = pathlib.Path("/run/user")
        if run_user.is_dir():
            for d in run_user.iterdir():
                p = d / "docker.sock"
                try:
                    if p.exists(): cands.append({"path": str(p), "owner_uid": p.stat().st_uid})
                except OSError: pass
        return cands

    def collect_containers(self) -> None:
        self.inventory["containers"] = {"docker": self.collect_container_runtime("docker"), "podman": self.collect_container_runtime("podman")}
        if which("crictl"):
            r = self.run(["crictl", "ps", "-a", "-o", "json"], "crictl.ps", timeout=12)
            try: self.inventory["containers"]["cri"] = json.loads(r["stdout"]) if r["ok"] else {"error": r["status"]}
            except json.JSONDecodeError: self.inventory["containers"]["cri"] = {"raw": r["stdout"], "error": r["status"]}
        else:
            self.inventory["containers"]["cri"] = {"available": False}; self.mark("crictl", "unsupported", "crictl not found")

    def collect_storage(self) -> None:
        st: Dict[str, Any] = {}
        r = self.run(["df", "-PT", "-x", "tmpfs", "-x", "devtmpfs"], "storage.df"); st["df"] = r["stdout"]
        r = self.run(["df", "-Pi", "-x", "tmpfs", "-x", "devtmpfs"], "storage.inodes"); st["inodes"] = r["stdout"]
        st["mountinfo"] = read_text("/proc/self/mountinfo", 1_000_000) or ""
        if which("lsblk"):
            r = self.run(["lsblk", "-J", "-o", "NAME,KNAME,TYPE,SIZE,FSTYPE,FSVER,LABEL,UUID,MOUNTPOINTS"], "storage.lsblk")
            try: st["lsblk"] = json.loads(r["stdout"]) if r["ok"] else None
            except json.JSONDecodeError: st["lsblk_raw"] = r["stdout"]
        self.inventory["storage"] = st

    def collect_packages(self) -> None:
        packages: Dict[str, Any] = {}
        if which("dpkg-query"):
            r = self.run(["dpkg-query", "-W", "-f=${binary:Package}\t${Version}\n"], "packages.dpkg", timeout=20)
            packages.update({"manager": "dpkg", "installed": [x for x in r["stdout"].splitlines() if x.strip()]})
            if which("apt-mark"):
                rr = self.run(["apt-mark", "showhold"], "packages.apt_hold"); packages["held"] = rr["stdout"].splitlines()
        elif which("rpm"):
            r = self.run(["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}.%{ARCH}\n"], "packages.rpm", timeout=20)
            packages.update({"manager": "rpm", "installed": [x for x in r["stdout"].splitlines() if x.strip()]})
        else:
            packages.update({"manager": None, "installed": []}); self.mark("packages", "unsupported", "no dpkg-query or rpm")
        packages["count"] = len(packages["installed"]); self.inventory["packages"] = packages

    def collect_resources(self) -> None:
        res: Dict[str, Any] = {"cpu_count": os.cpu_count(), "loadavg": os.getloadavg() if hasattr(os, "getloadavg") else None,
                               "meminfo": self._kv_file("/proc/meminfo"), "swaps": read_text("/proc/swaps", 100_000) or "", "pressure": {}}
        for name in ("cpu", "memory", "io"):
            txt = read_text(f"/proc/pressure/{name}", 100_000)
            if txt is not None: res["pressure"][name] = txt
        self.inventory["resources"] = res; self.mark("resources", "ok")

    def _kv_file(self, path: str) -> Dict[str, str]:
        out = {}
        for line in (read_text(path, 200_000) or "").splitlines():
            if ":" in line:
                k, v = line.split(":", 1); out[k] = v.strip()
        return out

    def collect_security_summary(self) -> None:
        sec: Dict[str, Any] = {"sshd_config_locations": [], "users": []}
        for p in ["/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d"]:
            path = pathlib.Path(p)
            try:
                if path.is_file(): sec["sshd_config_locations"].append({"path": p, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
                elif path.is_dir(): sec["sshd_config_locations"].append({"path": p, "files": sorted(x.name for x in path.glob("*.conf"))})
            except PermissionError: sec["sshd_config_locations"].append({"path": p, "error": "permission_denied"})
        try:
            for u in pwd.getpwall(): sec["users"].append({"name": u.pw_name, "uid": u.pw_uid, "gid": u.pw_gid, "home": u.pw_dir, "shell": u.pw_shell})
        except Exception as e: sec["users_error"] = str(e)
        self.inventory["security_summary"] = sec; self.mark("security_summary", "ok")

    def scan(self) -> Dict[str, Any]:
        for fn in (self.collect_system, self.collect_processes, self.collect_systemd, self.collect_cron, self.collect_sockets,
                   self.collect_network, self.collect_containers, self.collect_storage, self.collect_packages, self.collect_resources, self.collect_security_summary):
            fn()
        self.inventory["coverage"] = self.coverage; self.inventory["summary"] = self.build_summary(); return self.inventory

    def build_summary(self) -> Dict[str, Any]:
        listeners = self.inventory.get("sockets", {}).get("current_namespace", {}).get("parsed_tcp_udp", [])
        public = [x for x in listeners if (x.get("address") or "").strip("[]") in {"0.0.0.0", "::", "*"}]
        docker = self.inventory.get("containers", {}).get("docker", {})
        running_docker = sum(1 for c in docker.get("containers", []) or [] if (c.get("State") or {}).get("Running"))
        statuses: Dict[str, int] = {}
        for c in self.coverage: statuses[c["status"]] = statuses.get(c["status"], 0) + 1
        return {"process_count": len(self.inventory.get("processes", [])), "listener_count_current_namespace": len(listeners),
                "wildcard_listener_count": len(public), "docker_container_count": len(docker.get("containers", []) or []),
                "docker_running_count": running_docker, "installed_package_count": self.inventory.get("packages", {}).get("count", 0),
                "coverage_status_counts": statuses}


def write_outputs(inv: Dict[str, Any], outdir: pathlib.Path) -> None:
    outdir.mkdir(parents=True, exist_ok=True); os.chmod(outdir, 0o700)
    for name, content in {"inventory.json": json.dumps(inv, indent=2, ensure_ascii=False),
                          "coverage.json": json.dumps(inv.get("coverage", []), indent=2, ensure_ascii=False),
                          "report.md": render_report(inv)}.items():
        p = outdir / name; p.write_text(content, encoding="utf-8"); os.chmod(p, 0o600)


def render_report(inv: Dict[str, Any]) -> str:
    s, sysi = inv.get("summary", {}), inv.get("system", {})
    lines = ["# VPS Inspector Report", "", f"- Collected at: `{inv.get('collected_at')}`", f"- Tool version: `{inv.get('tool', {}).get('version')}`",
             f"- Hostname: `{sysi.get('hostname')}`", f"- OS: `{(sysi.get('os_release') or {}).get('PRETTY_NAME') or sysi.get('platform')}`",
             f"- Kernel: `{sysi.get('kernel')}`", f"- Root scan: `{sysi.get('is_root')}`", "", "## Summary", "",
             f"- Processes observed: **{s.get('process_count', 0)}**", f"- Listening TCP/UDP sockets in current netns: **{s.get('listener_count_current_namespace', 0)}**",
             f"- Wildcard listeners (`0.0.0.0`, `::`, `*`): **{s.get('wildcard_listener_count', 0)}**",
             f"- Docker containers: **{s.get('docker_container_count', 0)}** total / **{s.get('docker_running_count', 0)}** running",
             f"- Installed packages observed: **{s.get('installed_package_count', 0)}**", "", "## Listening ports (current network namespace)", "",
             "| Proto | State | Address | Port | Process |", "|---|---|---|---:|---|"]
    for x in inv.get("sockets", {}).get("current_namespace", {}).get("parsed_tcp_udp", [])[:500]:
        proc = str(x.get("process") or "").replace("|", "\\|")
        lines.append(f"| {x.get('proto','')} | {x.get('state','')} | `{x.get('address','')}` | {x.get('port') or ''} | `{proc[:160]}` |")
    lines += ["", "## Network namespace coverage", ""]
    for ns in inv.get("sockets", {}).get("network_namespaces", []): lines.append(f"- `{ns.get('namespace')}` via PID `{ns.get('representative_pid')}`: **{ns.get('status')}**")
    lines += ["", "## Docker", ""]
    docker = inv.get("containers", {}).get("docker", {})
    if not docker.get("available"): lines.append("Docker CLI not found.")
    elif not docker.get("containers"): lines.append(f"Docker available; inspect status: `{docker.get('info_status')}`; no inspectable containers were returned.")
    else:
        for c in docker.get("containers", []):
            st, hc = c.get("State") or {}, c.get("HostConfig") or {}
            lines.append(f"- `{c.get('Name')}` — status `{st.get('Status')}`, network `{hc.get('NetworkMode')}`, restart `{(hc.get('RestartPolicy') or {}).get('Name')}`")
            ports = (c.get("NetworkSettings") or {}).get("Ports")
            if ports: lines.append(f"  - Ports: `{json.dumps(ports, ensure_ascii=False)[:800]}`")
            for m in (c.get("Mounts") or [])[:20]: lines.append(f"  - Mount: `{m.get('Source')}` -> `{m.get('Destination')}` ({m.get('Type')})")
    lines += ["", "## systemd", "", "Raw unit, unit-file, socket and timer inventories are stored in `inventory.json`." if inv.get("systemd", {}).get("available") else "systemd/systemctl not available.",
              "", "## Coverage / blind spots", ""]
    bad = [x for x in inv.get("coverage", []) if x.get("status") != "ok"]
    if not bad: lines.append("All implemented collectors completed successfully. This is not proof that the host contains no hidden or kernel-level activity.")
    else:
        for x in bad:
            cmd = f" — `{x.get('command')}`" if x.get("command") else ""; lines.append(f"- **{x.get('status')}** `{x.get('collector')}`: {x.get('detail','')}{cmd}")
    lines += ["", "## Interpretation notes", "", "- This tool reports observable host state and configured startup sources. It does not claim to defeat a malicious kernel/rootkit.",
              "- `EXPOSE` inside a container image is not treated as a host port reservation; published bindings and actual sockets matter more.",
              "- Cloud firewalls, load balancers, DNS and external tunnels are outside local-host certainty unless separately verified.",
              "- A stopped container or enabled service can still create a future conflict after reboot/restart, so inspect configured state as well as current listeners.", ""]
    return "\n".join(lines)


def normalize_for_diff(obj: Any) -> Any:
    if isinstance(obj, dict): return {k: normalize_for_diff(v) for k, v in sorted(obj.items()) if k not in {"collected_at", "coverage"}}
    if isinstance(obj, list): return [normalize_for_diff(x) for x in obj]
    return obj


def cmd_diff(a: pathlib.Path, b: pathlib.Path, output: Optional[pathlib.Path]) -> int:
    ja, jb = normalize_for_diff(read_json_file(a)), normalize_for_diff(read_json_file(b))
    ta = json.dumps(ja, indent=2, ensure_ascii=False, sort_keys=True).splitlines(); tb = json.dumps(jb, indent=2, ensure_ascii=False, sort_keys=True).splitlines()
    diff = "\n".join(difflib.unified_diff(ta, tb, fromfile=str(a), tofile=str(b), lineterm=""))
    if output: output.write_text(diff + ("\n" if diff else ""), encoding="utf-8")
    else: print(diff or "No differences found.")
    return 1 if diff else 0


def iter_bindings(inv: Dict[str, Any]) -> Iterable[Dict[str, Any]]:
    for x in inv.get("sockets", {}).get("current_namespace", {}).get("parsed_tcp_udp", []):
        if x.get("port"): yield {"source": "socket", "protocol": x.get("proto", "tcp").lower(), "address": x.get("address") or "*", "port": x.get("port"), "detail": x.get("process")}
    for c in inv.get("containers", {}).get("docker", {}).get("containers", []) or []:
        for container_port, vals in ((c.get("HostConfig") or {}).get("PortBindings") or {}).items():
            proto = container_port.split("/")[-1] if "/" in container_port else "tcp"
            for v in vals or []:
                hp = v.get("HostPort")
                if hp and str(hp).isdigit(): yield {"source": "docker", "protocol": proto, "address": v.get("HostIp") or "0.0.0.0", "port": int(hp), "detail": c.get("Name")}


def address_conflicts(a: str, b: str) -> bool:
    wild = {"", "*", "0.0.0.0", "::", "[::]"}; return a in wild or b in wild or a == b


def cmd_check(snapshot: pathlib.Path, plan: pathlib.Path) -> int:
    inv, p, findings = read_json_file(snapshot), read_json_file(plan), []
    existing = list(iter_bindings(inv))
    for want in p.get("host_bindings", []):
        wp, wproto, waddr = int(want["port"]), str(want.get("protocol", "tcp")).lower(), str(want.get("address", "0.0.0.0"))
        for have in existing:
            hproto = str(have.get("protocol", "tcp")).lower()
            if hproto.startswith("tcp"): hproto = "tcp"
            if hproto.startswith("udp"): hproto = "udp"
            if hproto == wproto and have.get("port") == wp and address_conflicts(str(have.get("address", "*")), waddr):
                findings.append({"type": "port_conflict", "severity": "high", "wanted": want, "existing": have})
    for path in p.get("data_paths", []):
        if pathlib.Path(path).exists(): findings.append({"type": "path_exists", "severity": "medium", "path": path, "detail": "Path already exists on the machine running check; review ownership/content before deployment."})
        for c in inv.get("containers", {}).get("docker", {}).get("containers", []) or []:
            for m in c.get("Mounts") or []:
                src = m.get("Source")
                if src and (path == src or path.startswith(src.rstrip("/") + "/") or src.startswith(path.rstrip("/") + "/")):
                    findings.append({"type": "docker_mount_overlap", "severity": "high", "path": path, "existing": {"container": c.get("Name"), "mount": m}})
    print(json.dumps({"plan": p.get("name"), "checked_snapshot": str(snapshot), "findings": findings,
                      "coverage_warning": "No conflict found means only no conflict was observed within this snapshot's checked scope."}, indent=2, ensure_ascii=False))
    return 2 if any(x.get("severity") == "high" for x in findings) else (1 if findings else 0)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Read-only VPS inventory and deployment conflict preflight"); p.add_argument("--version", action="version", version=f"vps-inspector {VERSION}")
    sub = p.add_subparsers(dest="command", required=True)
    s = sub.add_parser("scan", help="Collect a VPS snapshot"); s.add_argument("-o", "--output", default=None); s.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT); s.add_argument("--strict", action="store_true")
    d = sub.add_parser("diff", help="Compare two inventory.json snapshots"); d.add_argument("before"); d.add_argument("after"); d.add_argument("-o", "--output", default=None)
    c = sub.add_parser("check", help="Check a deployment plan against a snapshot"); c.add_argument("snapshot"); c.add_argument("plan")
    return p


def main() -> int:
    args = build_parser().parse_args()
    if args.command == "scan":
        out = pathlib.Path(args.output) if args.output else pathlib.Path(dt.datetime.now().strftime("vps-inspector-%Y%m%d-%H%M%S"))
        inv = Inspector(timeout=max(1, args.timeout), strict=args.strict).scan(); write_outputs(inv, out)
        print(f"VPS Inspector {VERSION} completed\nReport:    {out / 'report.md'}\nInventory: {out / 'inventory.json'}\nCoverage:  {out / 'coverage.json'}")
        print("Tip: run with sudo/root for broader process, namespace, firewall and container visibility."); return 0
    if args.command == "diff": return cmd_diff(pathlib.Path(args.before), pathlib.Path(args.after), pathlib.Path(args.output) if args.output else None)
    if args.command == "check": return cmd_check(pathlib.Path(args.snapshot), pathlib.Path(args.plan))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
