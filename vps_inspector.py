#!/usr/bin/env python3
"""VPS Inspector - read-only Linux VPS inventory and conflict-preflight helper.

Designed to prefer observed kernel/runtime state over a list of known service names.
No third-party Python packages are required.
"""
from __future__ import annotations

import argparse
import datetime as dt
import difflib
import json
import os
import platform
import pwd
import re
import shutil
import socket
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable

VERSION = "0.1.0"
DEFAULT_TIMEOUT = 12
MAX_OUTPUT = 2_000_000
REDACT_RE = re.compile(r"(?i)(password|passwd|secret|token|api[_-]?key|authorization|cookie)=([^\s]+)")


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).astimezone().isoformat(timespec="seconds")


def redact(text: str) -> str:
    return REDACT_RE.sub(r"\1=<redacted>", text)


def read_text(path: str, limit: int = 512_000) -> str | None:
    try:
        with open(path, "rb") as f:
            data = f.read(limit + 1)
        suffix = "\n<truncated>" if len(data) > limit else ""
        return data[:limit].decode("utf-8", "replace") + suffix
    except (OSError, PermissionError):
        return None


def command_exists(name: str) -> bool:
    return shutil.which(name) is not None


def run(cmd: list[str], timeout: int = DEFAULT_TIMEOUT, env: dict[str, str] | None = None) -> dict[str, Any]:
    safe_env = {"PATH": os.environ.get("PATH", "/usr/sbin:/usr/bin:/sbin:/bin"), "LANG": "C", "LC_ALL": "C"}
    if env:
        safe_env.update(env)
    try:
        p = subprocess.run(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           timeout=timeout, env=safe_env, text=True, errors="replace", check=False)
        out = redact(p.stdout[:MAX_OUTPUT])
        err = redact(p.stderr[:MAX_OUTPUT])
        return {"ok": p.returncode == 0, "returncode": p.returncode, "stdout": out, "stderr": err,
                "truncated": len(p.stdout) > MAX_OUTPUT or len(p.stderr) > MAX_OUTPUT}
    except subprocess.TimeoutExpired as e:
        return {"ok": False, "returncode": None, "stdout": redact((e.stdout or "")[:MAX_OUTPUT] if isinstance(e.stdout, str) else ""),
                "stderr": "timeout", "truncated": False, "timeout": True}
    except (OSError, PermissionError) as e:
        return {"ok": False, "returncode": None, "stdout": "", "stderr": str(e), "truncated": False}


def os_release() -> dict[str, str]:
    out: dict[str, str] = {}
    text = read_text("/etc/os-release") or ""
    for line in text.splitlines():
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            out[k] = v.strip().strip('"')
    return out


def collect_system() -> dict[str, Any]:
    virt = run(["systemd-detect-virt"]) if command_exists("systemd-detect-virt") else None
    return {
        "hostname": socket.gethostname(), "os_release": os_release(), "kernel": platform.release(),
        "architecture": platform.machine(), "python": platform.python_version(), "uid": os.geteuid(),
        "user": pwd.getpwuid(os.geteuid()).pw_name, "is_root": os.geteuid() == 0,
        "boot_id": (read_text("/proc/sys/kernel/random/boot_id") or "").strip() or None,
        "virtualization": virt["stdout"].strip() if virt and virt["ok"] else None,
        "uptime_seconds": float((read_text("/proc/uptime") or "0").split()[0]),
    }


def proc_owner(pid: str) -> str | None:
    try:
        return pwd.getpwuid(os.stat(f"/proc/{pid}").st_uid).pw_name
    except (OSError, KeyError):
        return None


def collect_processes() -> dict[str, Any]:
    items, denied, vanished = [], 0, 0
    for pid in sorted((x for x in os.listdir("/proc") if x.isdigit()), key=int):
        base = f"/proc/{pid}"
        try:
            raw = Path(f"{base}/cmdline").read_bytes()[:131072]
            cmdline = redact(raw.replace(b"\0", b" ").decode("utf-8", "replace").strip())
            comm = (read_text(f"{base}/comm", 4096) or "").strip()
            try: exe = os.readlink(f"{base}/exe")
            except OSError: exe = None
            try: cwd = os.readlink(f"{base}/cwd")
            except OSError: cwd = None
            status = read_text(f"{base}/status", 32768) or ""
            ppid_m = re.search(r"^PPid:\s+(\d+)", status, re.M)
            cgroup = read_text(f"{base}/cgroup", 32768)
            netns = None
            try: netns = os.readlink(f"{base}/ns/net")
            except OSError: pass
            items.append({"pid": int(pid), "ppid": int(ppid_m.group(1)) if ppid_m else None, "user": proc_owner(pid),
                          "comm": comm, "cmdline": cmdline, "exe": exe, "cwd": cwd, "cgroup": cgroup, "netns": netns})
        except PermissionError:
            denied += 1
        except (FileNotFoundError, ProcessLookupError):
            vanished += 1
        except OSError:
            vanished += 1
    return {"processes": items, "visible_count": len(items), "permission_denied": denied, "vanished_during_scan": vanished}


def collect_sockets() -> dict[str, Any]:
    if not command_exists("ss"):
        return {"status": "unsupported", "reason": "ss command not found", "listeners": []}
    r = run(["ss", "-H", "-lntup"])
    unix = run(["ss", "-H", "-lxnp"])
    return {"status": "ok" if r["ok"] else "partial", "inet_raw": r["stdout"], "unix_raw": unix["stdout"],
            "errors": [x["stderr"] for x in (r, unix) if x["stderr"]]}


def collect_netns() -> dict[str, Any]:
    ns: dict[str, dict[str, Any]] = {}
    for pid in (x for x in os.listdir("/proc") if x.isdigit()):
        try:
            ident = os.readlink(f"/proc/{pid}/ns/net")
            ns.setdefault(ident, {"id": ident, "sample_pid": int(pid), "pids": []})["pids"].append(int(pid))
        except OSError:
            pass
    views = []
    if os.geteuid() == 0 and command_exists("nsenter") and command_exists("ss"):
        for entry in ns.values():
            r = run(["nsenter", "-t", str(entry["sample_pid"]), "-n", "ss", "-H", "-lntup"], timeout=8)
            views.append({"id": entry["id"], "sample_pid": entry["sample_pid"], "status": "ok" if r["ok"] else "error",
                          "listeners_raw": r["stdout"], "error": r["stderr"]})
    return {"discovered": list(ns.values()), "views": views,
            "note": "per-netns socket views require root, nsenter and ss" if not views else None}


def collect_systemd() -> dict[str, Any]:
    if not command_exists("systemctl") or not Path("/run/systemd/system").exists():
        return {"status": "unsupported", "reason": "systemd not detected"}
    commands = {
        "units": ["systemctl", "list-units", "--all", "--no-pager", "--plain"],
        "unit_files": ["systemctl", "list-unit-files", "--no-pager", "--plain"],
        "sockets": ["systemctl", "list-sockets", "--all", "--no-pager", "--plain"],
        "timers": ["systemctl", "list-timers", "--all", "--no-pager", "--plain"],
        "failed": ["systemctl", "--failed", "--no-pager", "--plain"],
    }
    data = {k: run(v, timeout=20) for k, v in commands.items()}
    return {"status": "ok" if all(x["ok"] for x in data.values()) else "partial", **data}


def collect_cron() -> dict[str, Any]:
    files: dict[str, str] = {}
    candidates = ["/etc/crontab"]
    for d in ("/etc/cron.d", "/var/spool/cron", "/var/spool/cron/crontabs"):
        if os.path.isdir(d):
            try:
                candidates.extend(str(Path(d) / x) for x in os.listdir(d))
            except OSError:
                pass
    for p in candidates:
        if os.path.isfile(p):
            text = read_text(p, 128000)
            if text is not None:
                files[p] = redact(text)
    return {"files": files}


def docker_inspect() -> dict[str, Any]:
    if not command_exists("docker"):
        return {"status": "unsupported", "reason": "docker CLI not found"}
    info = run(["docker", "--host", "unix:///var/run/docker.sock", "info", "--format", "{{json .}}"], timeout=15)
    if not info["ok"]:
        return {"status": "unavailable", "error": info["stderr"] or info["stdout"]}
    ps = run(["docker", "--host", "unix:///var/run/docker.sock", "ps", "-aq"])
    ids = [x for x in ps["stdout"].splitlines() if x]
    inspected: list[Any] = []
    if ids:
        ri = run(["docker", "--host", "unix:///var/run/docker.sock", "inspect", *ids], timeout=30)
        if ri["ok"]:
            try:
                raw = json.loads(ri["stdout"])
                for c in raw:
                    cfg = c.get("Config") or {}; hc = c.get("HostConfig") or {}; ns = c.get("NetworkSettings") or {}
                    inspected.append({"id": c.get("Id"), "name": c.get("Name", "").lstrip("/"), "created": c.get("Created"),
                        "state": c.get("State"), "image": cfg.get("Image"), "labels": cfg.get("Labels"), "exposed_ports": cfg.get("ExposedPorts"),
                        "network_mode": hc.get("NetworkMode"), "port_bindings": hc.get("PortBindings"), "restart_policy": hc.get("RestartPolicy"),
                        "mounts": c.get("Mounts"), "ports": ns.get("Ports"), "networks": ns.get("Networks")})
            except json.JSONDecodeError:
                pass
    return {"status": "ok", "daemon_info": info["stdout"], "containers": inspected, "container_count": len(inspected)}


def podman_inspect() -> dict[str, Any]:
    if not command_exists("podman"):
        return {"status": "unsupported", "reason": "podman CLI not found"}
    r = run(["podman", "ps", "-a", "--format", "json"], timeout=15)
    if not r["ok"]:
        return {"status": "unavailable", "error": r["stderr"]}
    try: data = json.loads(r["stdout"] or "[]")
    except json.JSONDecodeError: data = []
    return {"status": "ok", "containers": data, "note": "rootless containers belonging to other users may require per-user inspection"}


def collect_network() -> dict[str, Any]:
    cmds = {}
    for key, cmd in {
        "addresses": ["ip", "-details", "addr"], "routes": ["ip", "route", "show", "table", "all"],
        "rules": ["ip", "rule", "show"], "nftables": ["nft", "list", "ruleset"],
        "iptables": ["iptables-save"], "ip6tables": ["ip6tables-save"],
    }.items():
        if command_exists(cmd[0]): cmds[key] = run(cmd, timeout=15)
    sysctls = {}
    for p in ["/proc/sys/net/ipv4/ip_forward", "/proc/sys/net/ipv6/conf/all/forwarding", "/proc/sys/net/ipv4/ip_local_port_range", "/proc/sys/net/ipv4/ip_local_reserved_ports"]:
        sysctls[p] = (read_text(p) or "").strip()
    return {"commands": cmds, "sysctls": sysctls, "resolv_conf": read_text("/etc/resolv.conf", 65536)}


def collect_storage() -> dict[str, Any]:
    out = {}
    for key, cmd in {"df": ["df", "-hT"], "df_inode": ["df", "-hi"], "mounts": ["findmnt", "--json", "-A"], "block": ["lsblk", "-J", "-o", "NAME,TYPE,FSTYPE,SIZE,FSAVAIL,FSUSE%,MOUNTPOINTS"]}.items():
        if command_exists(cmd[0]): out[key] = run(cmd, timeout=15)
    return out


def collect_packages() -> dict[str, Any]:
    if command_exists("dpkg-query"):
        r = run(["dpkg-query", "-W", "-f=${binary:Package}\t${Version}\n"], timeout=30)
        return {"manager": "dpkg", "status": "ok" if r["ok"] else "partial", "installed": r["stdout"]}
    if command_exists("rpm"):
        r = run(["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}.%{ARCH}\n"], timeout=30)
        return {"manager": "rpm", "status": "ok" if r["ok"] else "partial", "installed": r["stdout"]}
    if command_exists("apk"):
        r = run(["apk", "info", "-vv"], timeout=30)
        return {"manager": "apk", "status": "ok" if r["ok"] else "partial", "installed": r["stdout"]}
    return {"manager": None, "status": "unsupported"}


def collect_resources() -> dict[str, Any]:
    return {"loadavg": (read_text("/proc/loadavg") or "").strip(), "meminfo": read_text("/proc/meminfo", 128000),
            "pressure": {k: read_text(f"/proc/pressure/{k}", 32768) for k in ("cpu", "memory", "io")},
            "cpu_count": os.cpu_count()}


def collect_security_maintenance() -> dict[str, Any]:
    sshd = None
    if command_exists("sshd"):
        sshd = run(["sshd", "-T"], timeout=10)
        if sshd and sshd["stdout"]:
            keep = ("port ", "listenaddress ", "permitrootlogin ", "passwordauthentication ", "pubkeyauthentication ", "allowusers ", "allowgroups ")
            sshd["stdout"] = "\n".join(x for x in sshd["stdout"].splitlines() if x.startswith(keep))
    return {"sshd_effective_selected": sshd, "reboot_required": Path("/var/run/reboot-required").exists(),
            "reboot_required_packages": read_text("/var/run/reboot-required.pkgs", 128000)}


COLLECTORS: list[tuple[str, Callable[[], dict[str, Any]]]] = [
    ("system", collect_system), ("processes", collect_processes), ("sockets", collect_sockets), ("network_namespaces", collect_netns),
    ("systemd", collect_systemd), ("cron", collect_cron), ("docker", docker_inspect), ("podman", podman_inspect),
    ("network", collect_network), ("storage", collect_storage), ("packages", collect_packages), ("resources", collect_resources),
    ("security_maintenance", collect_security_maintenance),
]


def scan() -> tuple[dict[str, Any], dict[str, Any]]:
    inv: dict[str, Any] = {"schema_version": 1, "tool_version": VERSION, "collected_at": now_iso()}
    coverage: dict[str, Any] = {"tool_version": VERSION, "collected_at": inv["collected_at"], "collectors": {}}
    for name, fn in COLLECTORS:
        started = dt.datetime.now(dt.timezone.utc)
        try:
            inv[name] = fn()
            status = inv[name].get("status", "ok") if isinstance(inv[name], dict) else "ok"
            coverage["collectors"][name] = {"status": status}
        except PermissionError as e:
            inv[name] = {"error": str(e)}; coverage["collectors"][name] = {"status": "permission_denied", "error": str(e)}
        except Exception as e:
            inv[name] = {"error": f"{type(e).__name__}: {e}"}; coverage["collectors"][name] = {"status": "error", "error": str(e)}
        coverage["collectors"][name]["duration_ms"] = int((dt.datetime.now(dt.timezone.utc) - started).total_seconds() * 1000)
    coverage["limitations"] = [
        "A scan is a point-in-time observation; very short-lived workloads can be missed.",
        "Kernel/rootkit compromise cannot be ruled out from inside the inspected host.",
        "Cloud security groups, external load balancers, DNS providers and tunnels are not fully verifiable without their external APIs.",
        "Other users' rootless container runtimes may not be queryable from the current account.",
        "Configuration files are not exhaustively parsed in v0.1; unknown software is still represented through processes/sockets where observable.",
    ]
    return inv, coverage


def md_code(text: str, limit: int = 100_000) -> str:
    text = text[:limit]
    return "```text\n" + text.replace("```", "` ` `") + "\n```\n"


def render_report(inv: dict[str, Any], cov: dict[str, Any]) -> str:
    s = inv.get("system", {}); procs = inv.get("processes", {}); dock = inv.get("docker", {}); pod = inv.get("podman", {})
    lines = ["# VPS Inspector Report", "", f"- Collected: `{inv.get('collected_at')}`", f"- Tool: `vps-inspector {VERSION}`",
             f"- Host: `{s.get('hostname')}`", f"- OS: `{(s.get('os_release') or {}).get('PRETTY_NAME', 'unknown')}`",
             f"- Kernel: `{s.get('kernel')}` / `{s.get('architecture')}`", f"- Privilege: `{'root' if s.get('is_root') else s.get('user')}`", ""]
    lines += ["## Coverage", "", "| Collector | Status |", "|---|---|"]
    for k, v in cov.get("collectors", {}).items(): lines.append(f"| {k} | {v.get('status')} |")
    lines += ["", "## Quick inventory", "", f"- Visible processes: **{procs.get('visible_count', 0)}**",
              f"- Process permission denials: **{procs.get('permission_denied', 0)}**",
              f"- Network namespaces discovered: **{len(inv.get('network_namespaces', {}).get('discovered', []))}**",
              f"- Docker containers: **{dock.get('container_count', 0) if dock.get('status') == 'ok' else dock.get('status', 'unknown')}**",
              f"- Podman: **{pod.get('status', 'unknown')}**", ""]
    for title, path, field in [("Listening TCP/UDP sockets", "sockets", "inet_raw"), ("Unix sockets", "sockets", "unix_raw")]:
        lines += [f"## {title}", ""]
        val = inv.get(path, {}).get(field, "")
        lines.append(md_code(val or "No data / collector unavailable"))
    lines += ["## systemd units", "", md_code(inv.get("systemd", {}).get("units", {}).get("stdout", "No data / systemd unavailable")),
              "## systemd unit files", "", md_code(inv.get("systemd", {}).get("unit_files", {}).get("stdout", "No data / systemd unavailable")),
              "## systemd sockets", "", md_code(inv.get("systemd", {}).get("sockets", {}).get("stdout", "No data / systemd unavailable")),
              "## systemd timers", "", md_code(inv.get("systemd", {}).get("timers", {}).get("stdout", "No data / systemd unavailable"))]
    if dock.get("containers"):
        lines += ["## Docker containers", "", "| Name | State | Image | Network | Port bindings |", "|---|---|---|---|---|"]
        for c in dock["containers"]:
            st = (c.get("state") or {}).get("Status", "?")
            lines.append(f"| {c.get('name')} | {st} | {c.get('image')} | {c.get('network_mode')} | `{json.dumps(c.get('port_bindings'), ensure_ascii=False)}` |")
        lines.append("")
    lines += ["## Storage", "", md_code(inv.get("storage", {}).get("df", {}).get("stdout", "No data")),
              "## Network addresses", "", md_code(inv.get("network", {}).get("commands", {}).get("addresses", {}).get("stdout", "No data")),
              "## Routes", "", md_code(inv.get("network", {}).get("commands", {}).get("routes", {}).get("stdout", "No data")),
              "## Limitations / unknowns", ""]
    lines.extend(f"- {x}" for x in cov.get("limitations", []))
    lines += ["", "Full machine-readable evidence is in `inventory.json`; collection gaps are in `coverage.json`.", ""]
    return "\n".join(lines)


def save_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")


def cmd_scan(args: argparse.Namespace) -> int:
    out = Path(args.output).resolve(); out.mkdir(parents=True, exist_ok=True); os.chmod(out, stat.S_IRWXU)
    inv, cov = scan(); save_json(out / "inventory.json", inv); save_json(out / "coverage.json", cov)
    (out / "report.md").write_text(render_report(inv, cov), encoding="utf-8")
    print(f"Scan complete: {out}")
    print(f"  Report:    {out / 'report.md'}")
    print(f"  Inventory: {out / 'inventory.json'}")
    print(f"  Coverage:  {out / 'coverage.json'}")
    return 0


def cmd_diff(args: argparse.Namespace) -> int:
    a = json.loads(Path(args.old).read_text(encoding="utf-8")); b = json.loads(Path(args.new).read_text(encoding="utf-8"))
    aa = json.dumps(a, indent=2, ensure_ascii=False, sort_keys=True).splitlines(); bb = json.dumps(b, indent=2, ensure_ascii=False, sort_keys=True).splitlines()
    print("\n".join(difflib.unified_diff(aa, bb, fromfile=args.old, tofile=args.new, lineterm="")))
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description="Read-only Linux VPS inventory tool")
    p.add_argument("--version", action="version", version=VERSION)
    sp = p.add_subparsers(dest="command", required=True)
    ps = sp.add_parser("scan", help="collect a point-in-time inventory"); ps.add_argument("-o", "--output", default="./vps-inspector-output"); ps.set_defaults(func=cmd_scan)
    pd = sp.add_parser("diff", help="diff two inventory JSON snapshots"); pd.add_argument("old"); pd.add_argument("new"); pd.set_defaults(func=cmd_diff)
    args = p.parse_args(); return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
