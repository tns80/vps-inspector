#!/usr/bin/env python3
"""VPS Inspector v0.3.1 - read-only Linux VPS inventory and deployment preflight."""
from __future__ import annotations
import argparse, datetime as dt, difflib, hashlib, ipaddress, json, os, pathlib, platform, pwd, re, shutil, socket, subprocess
from typing import Any, Dict, Iterable, List, Optional, Tuple

VERSION="0.3.1"; SCHEMA_VERSION=5; DEFAULT_TIMEOUT=8; MAX_OUTPUT=2_000_000
SENSITIVE=[re.compile(r"(?i)(password|passwd|token|secret|api[_-]?key|authorization)=([^\s]+)"),re.compile(r"(?i)(--password|--passwd|--token|--secret|--api-key)\s+([^\s]+)")]
SVC_RE=re.compile(r"(?:^|/)([^/]+\.service)(?:/|$)"); PID_RE=re.compile(r"pid=(\d+)"); PROC_RE=re.compile(r'users:\(\(\"([^\"]+)\"')

def now(): return dt.datetime.now(dt.timezone.utc).isoformat()
def which(x): return shutil.which(x)
def md(x): return " ".join(str(x or "").replace("|","\\|").splitlines())
def cname(x): return str(x or "").lstrip("/")
def proto(x):
    x=str(x or "").lower(); return "tcp" if x.startswith("tcp") else ("udp" if x.startswith("udp") else x)
def redact(s):
    for p in SENSITIVE:
        s=p.sub((lambda m:f"{m.group(1)} <redacted>") if p.pattern.startswith("(?i)(--") else (lambda m:f"{m.group(1)}=<redacted>"),s)
    return re.sub(r"(?i)(https?://[^:/\s]+:)[^@/\s]+@",r"\1<redacted>@",s)
def read(path,limit=200000):
    try:
        b=pathlib.Path(path).read_bytes()[:limit+1]; return b[:limit].decode("utf-8","replace")+("\n...<truncated>" if len(b)>limit else "")
    except OSError: return None
def scope(addr):
    a=(addr or "").strip("[]"); z=a.split("%",1)[0]
    if a in {"*","0.0.0.0","::"}: return "wildcard"
    try:
        ip=ipaddress.ip_address(z)
        if ip.is_loopback:return "loopback"
        if ip.version==4 and ip in ipaddress.ip_network("100.64.0.0/10"):return "shared/overlay"
        if ip.is_private:return "private/overlay"
        if not ip.is_global:return "special/non-global"
        return "specific/public"
    except ValueError:return "specific"

def split_host_port(v):
    m=re.match(r"^\[(.*)\]:(\d+)$",v)
    if m:return m.group(1),int(m.group(2))
    if ":" in v:
        h,p=v.rsplit(":",1)
        if p.isdigit():return h,int(p)
    return v or None,None

def parse_ss(text):
    out=[]
    for line in text.splitlines():
        p=line.split()
        if len(p)<5:continue
        h,port=split_host_port(p[4]); proc=" ".join(p[6:]) if len(p)>6 else ""
        out.append({"proto":p[0],"state":p[1],"address":h,"port":port,"scope":scope(h or ""),"process":redact(proc),"pids":sorted({int(x) for x in PID_RE.findall(proc)}),"process_names":sorted(set(PROC_RE.findall(proc)))})
    return out

class Inspector:
    def __init__(self,timeout=DEFAULT_TIMEOUT):
        self.timeout=timeout; self.coverage=[]; self.inv={"schema_version":SCHEMA_VERSION,"tool":{"name":"vps-inspector","version":VERSION},"collected_at":now()}
    def mark(self,name,status,detail="",**kw): self.coverage.append({"collector":name,"status":status,"detail":detail,**kw})
    def run(self,cmd,name,timeout=None,env=None):
        if not which(cmd[0]): self.mark(name,"unsupported",f"command not found: {cmd[0]}"); return {"ok":False,"status":"unsupported","stdout":"","stderr":""}
        e={"PATH":os.environ.get("PATH","/usr/sbin:/usr/bin:/sbin:/bin"),"LANG":"C","LC_ALL":"C"}; e.update(env or {})
        try:
            p=subprocess.run(cmd,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,errors="replace",timeout=timeout or self.timeout,env=e,check=False)
            st="ok" if p.returncode==0 else ("permission_denied" if any(x in p.stderr.lower() for x in ("permission denied","operation not permitted")) else "error")
            self.mark(name,st,f"exit={p.returncode}",command=" ".join(cmd),truncated=len(p.stdout)>MAX_OUTPUT or len(p.stderr)>MAX_OUTPUT)
            return {"ok":p.returncode==0,"status":st,"stdout":p.stdout[:MAX_OUTPUT],"stderr":p.stderr[:MAX_OUTPUT]}
        except subprocess.TimeoutExpired:self.mark(name,"timeout",f"timeout after {timeout or self.timeout}s"); return {"ok":False,"status":"timeout","stdout":"","stderr":""}
        except Exception as ex:self.mark(name,"error",f"{type(ex).__name__}: {ex}"); return {"ok":False,"status":"error","stdout":"","stderr":str(ex)}
    def system(self):
        o={}
        for l in (read("/etc/os-release") or "").splitlines():
            if "=" in l and not l.startswith("#"):k,v=l.split("=",1);o[k]=v.strip().strip('"')
        try: ns=os.readlink("/proc/1/ns/net")
        except OSError: ns=None
        virt=self.run(["systemd-detect-virt"],"virtualization")["stdout"].strip() if which("systemd-detect-virt") else None
        try:init=os.path.basename(os.readlink("/proc/1/exe"))
        except OSError:init=None
        try:uptime=float((read("/proc/uptime",10000) or "0").split()[0])
        except (ValueError,IndexError):uptime=None
        self.inv["system"]={"hostname":socket.gethostname(),"fqdn":socket.getfqdn(),"platform":platform.platform(),"kernel":platform.release(),"architecture":platform.machine(),"python":platform.python_version(),"uid":os.geteuid(),"is_root":os.geteuid()==0,"os_release":o,"host_netns":ns,"virtualization":virt,"init":init,"uptime_seconds":uptime,"boot_id":(read("/proc/sys/kernel/random/boot_id",10000) or "").strip()};self.mark("system","ok")
    def processes(self):
        rows=[];denied=0
        for n in os.listdir("/proc"):
            if not n.isdigit():continue
            pid=int(n);base=f"/proc/{pid}"
            try:
                d={}
                for l in (read(base+"/status",50000) or "").splitlines():
                    if ":" in l:
                        k,v=l.split(":",1)
                        if k in {"Name","State","PPid","Uid","Threads","NSpid"}:d[k]=v.strip()
                raw=pathlib.Path(base+"/cmdline").read_bytes()[:100000];cmd=redact(raw.replace(b"\0",b" ").decode("utf-8","replace").strip())
                try:exe=os.readlink(base+"/exe")
                except OSError:exe=None
                try:netns=os.readlink(base+"/ns/net")
                except OSError:netns=None
                cg=read(base+"/cgroup",50000) or "";m=SVC_RE.findall(cg);uid=int(d.get("Uid","0").split()[0]) if d.get("Uid") else None
                try:user=pwd.getpwuid(uid).pw_name if uid is not None else None
                except KeyError:user=None
                rows.append({"pid":pid,"ppid":int(d.get("PPid","0") or 0),"name":d.get("Name"),"uid":uid,"user":user,"exe":exe,"cmdline":cmd[:4000],"cgroup":cg[:4000],"systemd_service":m[-1] if m else None,"netns":netns})
            except PermissionError:denied+=1
            except (OSError,ValueError):continue
        rows.sort(key=lambda x:x["pid"]);self.inv["processes"]=rows;self.mark("processes","partial" if denied else "ok",f"processes={len(rows)}, denied={denied}")
    def _blocks(self,text,suffix):
        out=[]
        for b in re.split(r"\n\s*\n",text.strip()):
            d={}
            for l in b.splitlines():
                if "=" in l:k,v=l.split("=",1);d[k]=v
            u=d.get("Id")
            if not u or not u.endswith(suffix):continue
            x={"unit":u,"description":d.get("Description"),"load_state":d.get("LoadState"),"active_state":d.get("ActiveState"),"sub_state":d.get("SubState"),"unit_file_state":d.get("UnitFileState") or None,"fragment_path":d.get("FragmentPath") or None}
            if suffix==".service":
                try:mp=int(d.get("MainPID","0") or 0)
                except ValueError:mp=0
                x["main_pid"]=mp or None
            else:x.update({"listen":d.get("Listen") or None,"triggers":d.get("Triggers") or None})
            out.append(x)
        return out
    def systemd(self):
        if not which("systemctl"):self.inv["systemd"]={"available":False};self.mark("systemd","unsupported");return
        uf=self.run(["systemctl","list-unit-files","--no-pager","--no-legend","--plain"],"systemd.unit_files",15);states={}
        for l in uf["stdout"].splitlines():
            p=l.split()
            if len(p)>=2:states[p[0]]=p[1]
        sp="Id,Description,LoadState,ActiveState,SubState,UnitFileState,MainPID,FragmentPath";sr=self.run(["systemctl","show","--type=service","--all","--no-pager","--property="+sp],"systemd.services",25);services=self._blocks(sr["stdout"],".service") if sr["ok"] else []
        for x in services:x["unit_file_state"]=x.get("unit_file_state") or states.get(x["unit"])
        kp="Id,Description,LoadState,ActiveState,SubState,UnitFileState,FragmentPath,Listen,Triggers";kr=self.run(["systemctl","show","--type=socket","--all","--no-pager","--property="+kp],"systemd.sockets",25);socks=self._blocks(kr["stdout"],".socket") if kr["ok"] else [];by={x["unit"]:x for x in socks}
        for u,st in states.items():
            if u.endswith(".socket"):by.setdefault(u,{"unit":u,"active_state":"not-loaded","sub_state":"not-loaded"});by[u]["unit_file_state"]=by[u].get("unit_file_state") or st
        tr=self.run(["systemctl","list-timers","--all","--no-pager","--no-legend","--plain"],"systemd.timers",15);timers=[]
        for l in tr["stdout"].splitlines():
            p=l.split();u=next((z for z in p if z.endswith(".timer")),"")
            if u:timers.append({"unit":u,"activates":p[-1] if p[-1].endswith(".service") else "","raw":l.strip()})
        self.inv["systemd"]={"available":True,"services":services,"sockets":sorted(by.values(),key=lambda x:x.get("unit","")),"timers":timers}
    def cron(self):
        files=[];jobs=[]
        targets=[]
        if pathlib.Path("/etc/crontab").is_file():targets.append((pathlib.Path("/etc/crontab"),True,None))
        d=pathlib.Path("/etc/cron.d")
        if d.is_dir():targets += [(p,True,None) for p in sorted(d.iterdir()) if p.is_file() and not p.name.startswith(".")]
        d=pathlib.Path("/var/spool/cron/crontabs")
        if d.is_dir():
            try:targets += [(p,False,p.name) for p in sorted(d.iterdir()) if p.is_file()]
            except PermissionError:self.mark("cron.user_spool","permission_denied")
        for p,has_user,user in targets:
            text=read(str(p));row={"path":str(p),"jobs":[]}
            if text is None:row["status"]="permission_denied";files.append(row);continue
            row["sha256"]=hashlib.sha256(text.encode()).hexdigest()
            for no,raw in enumerate(text.splitlines(),1):
                l=raw.strip()
                if not l or l.startswith("#") or re.match(r"^[A-Za-z_][A-Za-z0-9_]*=",l):continue
                ps=l.split()
                if l.startswith("@"):
                    if len(ps)<(3 if has_user else 2):continue
                    sch=ps[0];ju=ps[1] if has_user else user;cmd=" ".join(ps[2:] if has_user else ps[1:])
                else:
                    if len(ps)<(7 if has_user else 6):continue
                    sch=" ".join(ps[:5]);ju=ps[5] if has_user else user;cmd=" ".join(ps[6:] if has_user else ps[5:])
                row["jobs"].append({"line":no,"schedule":sch,"user":ju,"command":redact(cmd)[:2000]})
            files.append(row);jobs+=row["jobs"]
        periodic={}
        for x in ("hourly","daily","weekly","monthly"):
            p=pathlib.Path("/etc/cron."+x)
            try:periodic[str(p)]=sorted(z.name for z in p.iterdir() if z.is_file() and not z.name.startswith(".")) if p.is_dir() else []
            except PermissionError:periodic[str(p)]=["<permission_denied>"]
        self.inv["cron"]={"files":files,"jobs":jobs,"periodic":periodic};self.mark("cron","ok",f"jobs={len(jobs)}")
    def sockets(self):
        if not which("ss"):self.inv["sockets"]={};self.mark("sockets","unsupported");return
        cur=self.run(["ss","-H","-lntup"],"sockets.host");out={"current_namespace":{"parsed_tcp_udp":parse_ss(cur["stdout"])} ,"network_namespaces":[]};ns={}
        for n in os.listdir("/proc"):
            if n.isdigit():
                try:ns.setdefault(os.readlink(f"/proc/{n}/ns/net"),[]).append(int(n))
                except OSError:pass
        for ident,pids in sorted(ns.items()):
            row={"namespace":ident,"representative_pid":min(pids),"pids":pids[:100]}
            if os.geteuid()==0 and which("nsenter"):
                r=self.run(["nsenter","-t",str(row["representative_pid"]),"-n","ss","-H","-lntup"],f"sockets.netns.{row['representative_pid']}");row.update({"status":r["status"],"parsed_tcp_udp":parse_ss(r["stdout"])})
            else:row["status"]="not_inspected"
            out["network_namespaces"].append(row)
        self.inv["sockets"]=out;self.mark("sockets.namespace_coverage","partial" if any(x["status"]!="ok" for x in out["network_namespaces"]) else "ok",f"discovered={len(ns)}")
    def network(self):
        out={}
        for k,cmd in {"addresses":["ip","-j","address"],"routes":["ip","-j","route","show","table","all"],"rules":["ip","-j","rule"]}.items():
            r=self.run(cmd,"network."+k)
            try:out[k]=json.loads(r["stdout"]) if r["ok"] else {"error":r["status"]}
            except json.JSONDecodeError:out[k]=r["stdout"]
        for k,p in {"ip_forward_v4":"/proc/sys/net/ipv4/ip_forward","ipv6_forwarding_all":"/proc/sys/net/ipv6/conf/all/forwarding","bindv6only":"/proc/sys/net/ipv6/bindv6only","ip_local_port_range":"/proc/sys/net/ipv4/ip_local_port_range","ip_local_reserved_ports":"/proc/sys/net/ipv4/ip_local_reserved_ports"}.items():out[k]=(read(p,10000) or "").strip() or None
        out["dns_resolv_conf"]=(read("/etc/resolv.conf",50000) or "")
        fw={"engine":"none","interesting_rules":[]}
        if which("nft"):r=self.run(["nft","list","ruleset"],"network.nft",15);fw.update({"engine":"nftables","status":r["status"]})
        elif which("iptables-save"):r=self.run(["iptables-save"],"network.iptables",15);fw.update({"engine":"iptables","status":r["status"]})
        else:r={"stdout":""}
        fw["interesting_rules"]=[md(l) for l in r.get("stdout","").splitlines() if re.search(r"(?i)(dport|sport|dnat|snat|redirect|masquerade|drop|reject|accept)",l)][:500];out["firewall"]=fw;self.inv["network"]=out
    def containers(self):
        if not which("docker"):docker={"available":False,"containers":[],"networks":[]};self.mark("docker","unsupported")
        else:
            ps=self.run(["docker","ps","-a","--no-trunc","--format","{{.ID}}"],"docker.ps",15);ids=[x for x in ps["stdout"].splitlines() if x];cs=[]
            if ids:
                ir=self.run(["docker","inspect",*ids],"docker.inspect",25)
                if ir["ok"]:
                    try:
                        for x in json.loads(ir["stdout"]):
                            st=x.get("State") or {};cfg=x.get("Config") or {};hc=x.get("HostConfig") or {};nw=x.get("NetworkSettings") or {};pid=int(st.get("Pid") or 0)
                            try:ns=os.readlink(f"/proc/{pid}/ns/net") if pid else None
                            except OSError:ns=None
                            labels=cfg.get("Labels") or {};safe_labels={k:v for k,v in labels.items() if not re.search(r"(?i)(secret|token|password|key)",k)}
                            cs.append({"Id":x.get("Id"),"Name":cname(x.get("Name")),"netns":ns,"State":{k:st.get(k) for k in ("Status","Running","Paused","Restarting","OOMKilled","Dead","Pid","ExitCode")},"Config":{"Image":cfg.get("Image"),"ExposedPorts":cfg.get("ExposedPorts"),"Labels":safe_labels},"HostConfig":{"NetworkMode":hc.get("NetworkMode"),"PortBindings":hc.get("PortBindings"),"RestartPolicy":hc.get("RestartPolicy"),"Privileged":hc.get("Privileged")},"NetworkSettings":{"Ports":nw.get("Ports"),"Networks":nw.get("Networks")},"Mounts":[{k:m.get(k) for k in ("Type","Name","Source","Destination","Mode","RW")} for m in x.get("Mounts") or []]})
                    except json.JSONDecodeError:self.mark("docker.inspect.parse","error")
            nets=[];nr=self.run(["docker","network","ls","-q"],"docker.network_ls",15);nids=[x for x in nr["stdout"].splitlines() if x]
            if nids:
                ni=self.run(["docker","network","inspect",*nids],"docker.network_inspect",25)
                if ni["ok"]:
                    try:
                        for n in json.loads(ni["stdout"]):
                            ipam=n.get("IPAM") or {};nets.append({"Id":n.get("Id"),"Name":n.get("Name"),"Driver":n.get("Driver"),"Internal":n.get("Internal"),"Config":[{"Subnet":z.get("Subnet"),"Gateway":z.get("Gateway"),"IPRange":z.get("IPRange")} for z in ipam.get("Config") or []]})
                    except json.JSONDecodeError:self.mark("docker.network_inspect.parse","error")
            docker={"available":True,"containers":cs,"networks":nets}
        pod={"available":False,"containers":[]}
        if which("podman"):
            pr=self.run(["podman","ps","-a","--no-trunc","--format","json"],"podman.ps",15);pod["available"]=True
            if pr["ok"]:
                try:pod["containers"]=json.loads(pr["stdout"] or "[]")
                except json.JSONDecodeError:self.mark("podman.parse","error")
        else:self.mark("podman","unsupported")
        cri={"available":False}
        if which("crictl"):
            cr=self.run(["crictl","ps","-a","-o","json"],"crictl.ps",15);cri["available"]=True
            if cr["ok"]:
                try:cri["data"]=json.loads(cr["stdout"])
                except json.JSONDecodeError:self.mark("crictl.parse","error")
        else:self.mark("crictl","unsupported")
        self.inv["containers"]={"docker":docker,"podman":pod,"cri":cri}
    def user_systemd(self):
        dirs=[];runtime=[];paths=[pathlib.Path("/etc/systemd/user"),pathlib.Path("/usr/lib/systemd/user")]
        for u in pwd.getpwall():
            if u.pw_uid==0 or u.pw_uid>=1000:paths.append(pathlib.Path(u.pw_dir)/".config/systemd/user")
        for p in dict.fromkeys(map(str,paths)):
            q=pathlib.Path(p)
            if q.is_dir():
                try:files=sorted(str(x) for x in q.rglob("*.service"))[:1000]
                except PermissionError:files=["<permission_denied>"]
                dirs.append({"path":p,"service_files":files})
        ru=pathlib.Path("/run/user")
        if ru.is_dir():
            for d in sorted(ru.iterdir(),key=lambda x:x.name):
                if not d.name.isdigit():continue
                uid=int(d.name)
                try:user=pwd.getpwuid(uid).pw_name
                except KeyError:user=str(uid)
                bus=d/"bus";row={"uid":uid,"user":user,"bus_present":bus.exists(),"services":[]}
                cmd=[]
                if bus.exists() and which("systemctl"):
                    if uid==os.geteuid():cmd=["systemctl","--user","show","--type=service","--all","--no-pager","--property=Id,Description,LoadState,ActiveState,SubState,UnitFileState,MainPID,FragmentPath"]
                    elif os.geteuid()==0 and which("runuser"):cmd=["runuser","-u",user,"--","systemctl","--user","show","--type=service","--all","--no-pager","--property=Id,Description,LoadState,ActiveState,SubState,UnitFileState,MainPID,FragmentPath"]
                if cmd:
                    r=self.run(cmd,f"user_systemd.{uid}",20,{"XDG_RUNTIME_DIR":str(d),"DBUS_SESSION_BUS_ADDRESS":f"unix:path={bus}"});row["status"]=r["status"];row["services"]=self._blocks(r["stdout"],".service") if r["ok"] else []
                else:row["status"]="no_bus" if not bus.exists() else "not_inspected"
                runtime.append(row)
        self.inv["user_systemd"]={"unit_directories":dirs,"runtime_users":runtime};self.mark("user_systemd","ok")
    def misc(self):
        st={"mountinfo":read("/proc/self/mountinfo",1_000_000) or ""}
        for k,c in {"df":["df","-PT","-x","tmpfs","-x","devtmpfs"],"inodes":["df","-Pi","-x","tmpfs","-x","devtmpfs"]}.items():st[k]=self.run(c,"storage."+k)["stdout"]
        if which("lsblk"):
            lr=self.run(["lsblk","-J","-o","NAME,KNAME,TYPE,SIZE,FSTYPE,FSVER,LABEL,UUID,MOUNTPOINTS"],"storage.lsblk",15)
            if lr["ok"]:
                try:st["lsblk"]=json.loads(lr["stdout"])
                except json.JSONDecodeError:st["lsblk_raw"]=lr["stdout"]
        self.inv["storage"]=st;pk=[];mgr=None
        if which("dpkg-query"):r=self.run(["dpkg-query","-W","-f=${binary:Package}\t${Version}\n"],"packages.dpkg",25);pk=[x for x in r["stdout"].splitlines() if x];mgr="dpkg"
        elif which("rpm"):r=self.run(["rpm","-qa","--qf","%{NAME}\t%{VERSION}-%{RELEASE}.%{ARCH}\n"],"packages.rpm",25);pk=[x for x in r["stdout"].splitlines() if x];mgr="rpm"
        elif which("apk"):r=self.run(["apk","info","-vv"],"packages.apk",25);pk=[x for x in r["stdout"].splitlines() if x];mgr="apk"
        else:self.mark("packages","unsupported","no supported package query tool")
        self.inv["packages"]={"manager":mgr,"installed":pk,"count":len(pk)}
        pressure={k:read(f"/proc/pressure/{k}",100000) for k in ("cpu","memory","io") if pathlib.Path(f"/proc/pressure/{k}").exists()}
        self.inv["resources"]={"cpu_count":os.cpu_count(),"loadavg":os.getloadavg() if hasattr(os,"getloadavg") else None,"meminfo":read("/proc/meminfo",100000),"swaps":read("/proc/swaps",100000),"pressure":pressure}
        sec={"sshd_config_locations":[],"users":[]}
        for p in ("/etc/ssh/sshd_config","/etc/ssh/sshd_config.d"):
            q=pathlib.Path(p)
            try:
                if q.is_file():sec["sshd_config_locations"].append({"path":p,"sha256":hashlib.sha256(q.read_bytes()).hexdigest()})
                elif q.is_dir():sec["sshd_config_locations"].append({"path":p,"files":sorted(x.name for x in q.glob("*.conf"))})
            except PermissionError:sec["sshd_config_locations"].append({"path":p,"error":"permission_denied"})
        for u in pwd.getpwall():sec["users"].append({"name":u.pw_name,"uid":u.pw_uid,"gid":u.pw_gid,"home":u.pw_dir,"shell":u.pw_shell})
        self.inv["security_summary"]=sec;self.mark("resources","ok");self.mark("security_summary","ok")
    def relationships(self):
        procs=self.inv.get("processes",[]);pb={p["pid"]:p for p in procs};svcs={s["unit"]:dict(s) for s in self.inv.get("systemd",{}).get("services",[])}
        for s in svcs.values():
            ids=sorted({p["pid"] for p in procs if p.get("systemd_service")==s["unit"]}|({s["main_pid"]} if s.get("main_pid") else set()));s["processes"]=[{"pid":i,"name":pb.get(i,{}).get("name")} for i in ids if i in pb];s["listeners"]=[]
        dports=[];dns={}
        for c in self.inv.get("containers",{}).get("docker",{}).get("containers",[]):
            if c.get("netns"):dns[c["netns"]]=c["Name"]
            seen_bindings=set()
            for source in ((c.get("HostConfig",{}).get("PortBindings") or {}),(c.get("NetworkSettings",{}).get("Ports") or {})):
                for cp,vals in source.items():
                    for v in vals or []:
                        hp=str(v.get("HostPort") or "")
                        if not hp.isdigit():continue
                        item=(proto(cp.split("/")[-1]),int(hp),str(v.get("HostIp") or "0.0.0.0"),c["Name"])
                        if item in seen_bindings:continue
                        seen_bindings.add(item);dports.append({"proto":item[0],"port":item[1],"address":item[2],"container":item[3]})
        listeners=[];v6=str(self.inv.get("network",{}).get("bindv6only") or "0")
        for x in self.inv.get("sockets",{}).get("current_namespace",{}).get("parsed_tcp_udp",[]):
            y=dict(x);owners=sorted({pb.get(i,{}).get("systemd_service") for i in x.get("pids",[]) if pb.get(i,{}).get("systemd_service")});y["systemd_services"]=owners
            y["docker_containers"]=sorted({b["container"] for b in dports if x.get("port") and b["proto"]==proto(x.get("proto")) and b["port"]==int(x["port"]) and addr_conflict(str(b["address"]),str(x.get("address") or "*"),v6)})
            for o in owners:
                if o in svcs:svcs[o]["listeners"].append(y)
            listeners.append(y)
        tmap={}
        for s in self.inv.get("systemd",{}).get("sockets",[]):
            for target in str(s.get("triggers") or "").split():
                if target.endswith(".service"):tmap.setdefault(target,[]).append(s)
        for n,s in svcs.items():
            ts=tmap.get(n,[]);ufs=s.get("unit_file_state")
            s["activating_sockets"]=[x.get("unit") for x in ts];s["effective_startup"]="enabled" if ufs in {"enabled","enabled-runtime"} else ("socket-activated" if any(x.get("unit_file_state") in {"enabled","enabled-runtime"} for x in ts) else ("static/dependency" if ufs=="static" else (ufs or "unknown")))
        hostns=self.inv.get("system",{}).get("host_netns");nss=[]
        for x in self.inv.get("sockets",{}).get("network_namespaces",[]):
            y=dict(x);y["kind"]="host" if x.get("namespace")==hostns else ("docker" if x.get("namespace") in dns else "other");y["docker_container"]=dns.get(x.get("namespace"));nss.append(y)
        unmanaged=[p for p in procs if p.get("netns")==hostns and not p.get("systemd_service") and p.get("pid",0)>1 and p.get("cmdline")]
        vals=list(svcs.values());self.inv["relationships"]={"services":vals,"running_services":[x for x in vals if x.get("active_state")=="active" and x.get("sub_state")=="running"],"active_exited_services":[x for x in vals if x.get("active_state")=="active" and x.get("sub_state")=="exited"],"enabled_inactive_services":[x for x in vals if x.get("unit_file_state") in {"enabled","enabled-runtime"} and x.get("active_state")!="active"],"listeners":listeners,"network_namespaces":nss,"unmanaged_host_processes":unmanaged}
    def scan(self):
        for fn in (self.system,self.processes,self.systemd,self.cron,self.sockets,self.network,self.containers,self.user_systemd,self.misc):fn()
        self.relationships();r=self.inv["relationships"];d=self.inv["containers"]["docker"];self.inv["summary"]={"process_count":len(self.inv["processes"]),"running_service_count":len(r["running_services"]),"active_exited_service_count":len(r["active_exited_services"]),"enabled_inactive_service_count":len(r["enabled_inactive_services"]),"listener_count":len(r["listeners"]),"wildcard_count":sum(x.get("scope")=="wildcard" for x in r["listeners"]),"netns_count":len(r["network_namespaces"]),"docker_count":len(d.get("containers",[])),"docker_running":sum(bool(c.get("State",{}).get("Running")) for c in d.get("containers",[])),"timer_count":len(self.inv.get("systemd",{}).get("timers",[])),"socket_count":len(self.inv.get("systemd",{}).get("sockets",[])),"cron_count":len(self.inv["cron"]["jobs"]),"package_count":self.inv["packages"]["count"]};self.inv["coverage"]=self.coverage;return self.inv

def render(inv):
    s=inv["summary"];r=inv["relationships"];sysi=inv["system"];fw=inv.get("network",{}).get("firewall",{});L=["# VPS Inspector Report","",f"- Tool version: `{VERSION}`",f"- Collected at: `{inv.get('collected_at')}`",f"- Hostname: `{sysi.get('hostname')}`",f"- OS: `{sysi.get('os_release',{}).get('PRETTY_NAME') or sysi.get('platform')}`",f"- Kernel: `{sysi.get('kernel')}`",f"- Root scan: `{sysi.get('is_root')}`","","## Summary","",f"- Processes: **{s['process_count']}**",f"- Long-running services: **{s['running_service_count']}**",f"- Active/exited services: **{s['active_exited_service_count']}**",f"- Enabled inactive services: **{s['enabled_inactive_service_count']}**",f"- Host listeners: **{s['listener_count']}** (wildcard **{s['wildcard_count']}**)",f"- Network namespaces: **{s['netns_count']}**",f"- Docker: **{s['docker_count']}** total / **{s['docker_running']}** running",f"- Timers: **{s['timer_count']}**, sockets: **{s['socket_count']}**, cron jobs: **{s['cron_count']}**","","## Deployment preflight summary","","| Scope | Proto | Address | Port | Owner |","|---|---|---|---:|---|"]
    for x in r["listeners"]:
        owners=x.get("systemd_services",[])+["Docker:"+c for c in x.get("docker_containers",[])] or x.get("process_names",[]) or ["unknown"];L.append(f"| {md(x.get('scope'))} | {proto(x.get('proto'))} | `{md(x.get('address'))}` | {x.get('port') or ''} | {md(', '.join(dict.fromkeys(owners)))} |")
    L += ["",f"Firewall: **{fw.get('engine','none')}**, captured rule lines: **{len(fw.get('interesting_rules',[]))}**.","","## Long-running service relationships",""]
    for x in sorted(r["running_services"],key=lambda z:z.get("unit","")):
        L += [f"### `{x.get('unit')}`",f"- State: `{x.get('active_state')}/{x.get('sub_state')}`; unit startup: `{x.get('unit_file_state') or 'unknown'}`; effective startup: `{x.get('effective_startup')}`"]
        if x.get("activating_sockets"):L.append("- Activating sockets: "+", ".join(f"`{z}`" for z in x["activating_sockets"]))
        if x.get("processes"):L.append("- Processes: "+", ".join(f"PID {p['pid']} `{p.get('name') or ''}`" for p in x["processes"][:20]))
        L.append("- Host listeners: "+(", ".join(f"`{proto(z.get('proto'))} {z.get('address')}:{z.get('port')}`" for z in x.get("listeners",[])) or "none"));L.append("")
    L += ["## Network namespaces and containers","","| Namespace | Kind | Docker | PID | Actual listeners |","|---|---|---|---:|---|"]
    for x in r["network_namespaces"]:
        actual=", ".join(f"{proto(z.get('proto'))} {z.get('address')}:{z.get('port')}" for z in x.get("parsed_tcp_udp",[])[:30]) or "none"
        L.append(f"| `{md(x.get('namespace'))}` | {x.get('kind')} | `{md(x.get('docker_container'))}` | {x.get('representative_pid')} | {md(actual)} |")
    L += ["","## Docker",""]
    for c in inv.get("containers",{}).get("docker",{}).get("containers",[]):L += [f"### `{c['Name']}`",f"- State: `{c.get('State',{}).get('Status')}`; netns: `{c.get('netns') or ''}`",f"- Declared container ports: `{json.dumps(c.get('Config',{}).get('ExposedPorts') or {},ensure_ascii=False)}`",f"- Host-published ports: `{json.dumps(c.get('NetworkSettings',{}).get('Ports') or {},ensure_ascii=False)}`"]+[f"- Mount: `{m.get('Source')}` -> `{m.get('Destination')}`" for m in c.get("Mounts",[])]+[""]
    nets=inv.get("containers",{}).get("docker",{}).get("networks",[]);L += ["## Docker networks","","| Network | Driver | Internal | Subnets |","|---|---|---|---|"]
    for n in nets:L.append(f"| `{md(n.get('Name'))}` | `{md(n.get('Driver'))}` | `{n.get('Internal')}` | `{md(', '.join(z.get('Subnet') or '' for z in n.get('Config',[]) if z.get('Subnet')))}` |")
    L += ["","## systemd socket activation","","| Socket | State | Startup | Triggers | Listen |","|---|---|---|---|---|"]
    for x in inv.get("systemd",{}).get("sockets",[]):L.append(f"| `{md(x.get('unit'))}` | `{md(x.get('active_state'))}/{md(x.get('sub_state'))}` | `{md(x.get('unit_file_state') or 'unknown')}` | `{md(x.get('triggers'))}` | `{md(x.get('listen'))}` |")
    L += ["","## Cron jobs",""]
    if inv["cron"]["jobs"]:
        L += ["| Source | Line | Schedule | User | Command |","|---|---:|---|---|---|"]
        for f in inv["cron"]["files"]:
            for j in f.get("jobs",[]):L.append(f"| `{md(f['path'])}` | {j['line']} | `{md(j['schedule'])}` | `{md(j['user'])}` | `{md(j['command'])}` |")
    else:L.append("No parsed cron jobs.")
    L += ["","## Firewall / NAT summary",""]
    if fw.get("interesting_rules"):L += ["```text",*fw["interesting_rules"][:200],"```"]
    else:L.append("No matching local firewall/NAT rules captured.")
    L += ["","## Host processes not attributed to a systemd service",""]
    unmanaged=r.get("unmanaged_host_processes",[])
    if unmanaged:
        L += ["| PID | User | Process | Command |","|---:|---|---|---|"]
        for p in unmanaged[:100]:L.append(f"| {p.get('pid')} | `{md(p.get('user'))}` | `{md(p.get('name'))}` | `{md((p.get('cmdline') or '')[:300])}` |")
    else:L.append("None observed.")
    L += ["","## User systemd discovery",""]
    for x in inv.get("user_systemd",{}).get("runtime_users",[]):
        L.append(f"### `{x.get('user')}` uid={x.get('uid')} — `{x.get('status')}`")
        shown=[u for u in x.get('services',[]) if u.get('active_state')=='active' or u.get('unit_file_state') in {'enabled','enabled-runtime'}]
        if shown:
            L += ["| Unit | State | Startup | PID |","|---|---|---|---:|"]
            for u in shown[:100]:L.append(f"| `{md(u.get('unit'))}` | `{md(u.get('active_state'))}/{md(u.get('sub_state'))}` | `{md(u.get('unit_file_state') or 'unknown')}` | {u.get('main_pid') or ''} |")
        else:L.append("No active/enabled user services observed.")
    L += ["","## Coverage / blind spots",""]
    bad=[x for x in inv.get("coverage",[]) if x.get("status")!="ok"]
    L += [f"- **{x.get('status')}** `{x.get('collector')}`: {md(x.get('detail'))}" for x in bad] or ["All implemented collectors completed successfully."]
    L += ["","## Notes","","- Container declared ports are not host reservations; published ports and actual per-netns listeners are shown separately.","- `effective_startup=socket-activated` means a disabled service can still start through an enabled socket.","- `shared/overlay` includes RFC 6598 shared address space such as Tailscale 100.64.0.0/10; it is not classified as public Internet space.","- Local firewall summaries do not include cloud firewalls, external load balancers, DNS, or remote tunnel control planes.","- Same-host tools cannot prove absence of kernel/rootkit concealment.",""];return "\n".join(L)

def write_outputs(inv,out):
    out.mkdir(parents=True,exist_ok=True)
    try:os.chmod(out,0o700)
    except OSError:pass
    for n,c in {"inventory.json":json.dumps(inv,indent=2,ensure_ascii=False),"coverage.json":json.dumps(inv.get("coverage",[]),indent=2,ensure_ascii=False),"report.md":render(inv)}.items():
        p=out/n;p.write_text(c,encoding="utf-8")
        try:os.chmod(p,0o600)
        except OSError:pass

def normalized(x):
    if isinstance(x,dict):return {k:normalized(v) for k,v in sorted(x.items()) if k not in {"collected_at","coverage"}}
    if isinstance(x,list):return [normalized(v) for v in x]
    return x

def afam(a):
    a=(a or "").strip("[]").split("%",1)[0]
    if a in {"","*"}:return None
    try:return ipaddress.ip_address(a).version
    except ValueError:return None
def addr_conflict(a,b,v6only="0"):
    a=a.strip("[]");b=b.strip("[]")
    if a==b:return True
    fa,fb=afam(a),afam(b)
    if a in {"","*"} or b in {"","*"}:return True
    if a=="0.0.0.0":return fb in {None,4}
    if b=="0.0.0.0":return fa in {None,4}
    if a=="::":return fb in {None,6} or (fb==4 and v6only!="1")
    if b=="::":return fa in {None,6} or (fa==4 and v6only!="1")
    return False

def bindings(inv)->Iterable[Dict[str,Any]]:
    observed=inv.get("relationships",{}).get("listeners",[])
    v6=str(inv.get("network",{}).get("bindv6only") or "0")
    for x in observed:
        if x.get("port"):
            yield {"source":"socket","protocol":proto(x.get("proto")),"address":x.get("address") or "*","port":int(x["port"]),"detail":x.get("process"),"systemd_services":x.get("systemd_services",[]),"docker_containers":x.get("docker_containers",[])}
    for c in inv.get("containers",{}).get("docker",{}).get("containers",[]):
        running=bool(c.get("State",{}).get("Running"))
        for cp,vals in (c.get("HostConfig",{}).get("PortBindings") or {}).items():
            cp_proto=proto(cp.split("/")[-1])
            for v in vals or []:
                hp=str(v.get("HostPort") or "")
                if not hp.isdigit():continue
                bind_addr=str(v.get("HostIp") or "0.0.0.0");port=int(hp)
                seen_runtime=running and any(proto(x.get("proto"))==cp_proto and int(x.get("port") or 0)==port and addr_conflict(bind_addr,str(x.get("address") or "*"),v6) for x in observed)
                if not seen_runtime:
                    yield {"source":"docker_config","protocol":cp_proto,"address":bind_addr,"port":port,"detail":c["Name"],"container_running":running}

def check(snapshot,plan):
    inv=json.loads(snapshot.read_text());p=json.loads(plan.read_text());f=[];v6=str(inv.get("network",{}).get("bindv6only") or "0")
    for w in p.get("host_bindings",[]):
        for h in bindings(inv):
            if proto(h["protocol"])==proto(w.get("protocol","tcp")) and h["port"]==int(w["port"]) and addr_conflict(str(h["address"]),str(w.get("address","0.0.0.0")),v6):f.append({"type":"port_conflict","severity":"high","wanted":w,"existing":h})
    for wanted in p.get("network_cidrs",[]):
        try:wn=ipaddress.ip_network(str(wanted),strict=False)
        except ValueError:
            f.append({"type":"invalid_network_cidr","severity":"medium","cidr":wanted});continue
        for n in inv.get("containers",{}).get("docker",{}).get("networks",[]):
            for cfg in n.get("Config",[]):
                sub=cfg.get("Subnet")
                if not sub:continue
                try:en=ipaddress.ip_network(sub,strict=False)
                except ValueError:continue
                if wn.version==en.version and wn.overlaps(en):f.append({"type":"docker_subnet_overlap","severity":"high","wanted":str(wn),"existing":{"network":n.get("Name"),"subnet":str(en)}})
    for path in p.get("data_paths",[]):
        q=os.path.abspath(os.path.expanduser(path))
        if pathlib.Path(q).exists():f.append({"type":"path_exists","severity":"medium","path":q})
        for c in inv.get("containers",{}).get("docker",{}).get("containers",[]):
            for m in c.get("Mounts",[]):
                src=os.path.abspath(str(m.get("Source") or "")) if m.get("Source") else ""
                if src and (q==src or q.startswith(src.rstrip("/")+"/") or src.startswith(q.rstrip("/")+"/")):f.append({"type":"docker_mount_overlap","severity":"high","path":q,"existing":{"container":c["Name"],"mount":m}})
    ded=[];seen=set()
    for x in f:
        k=json.dumps(x,sort_keys=True,ensure_ascii=False)
        if k not in seen:seen.add(k);ded.append(x)
    print(json.dumps({"plan":p.get("name"),"checked_snapshot":str(snapshot),"findings":ded,"coverage_warning":"No conflict found means only no conflict was observed within this snapshot's checked scope."},indent=2,ensure_ascii=False));return 2 if any(x["severity"]=="high" for x in ded) else (1 if ded else 0)

def main():
    p=argparse.ArgumentParser();p.add_argument("--version",action="version",version=f"vps-inspector {VERSION}");s=p.add_subparsers(dest="cmd",required=True)
    a=s.add_parser("scan");a.add_argument("-o","--output");a.add_argument("--timeout",type=int,default=DEFAULT_TIMEOUT)
    d=s.add_parser("diff");d.add_argument("before");d.add_argument("after");d.add_argument("-o","--output")
    c=s.add_parser("check");c.add_argument("snapshot");c.add_argument("plan");x=p.parse_args()
    if x.cmd=="scan":
        out=pathlib.Path(x.output) if x.output else pathlib.Path(dt.datetime.now().strftime("vps-inspector-%Y%m%d-%H%M%S"));inv=Inspector(max(1,x.timeout)).scan();write_outputs(inv,out);print(f"VPS Inspector {VERSION} completed\nReport:    {out/'report.md'}\nInventory: {out/'inventory.json'}\nCoverage:  {out/'coverage.json'}");return 0
    if x.cmd=="diff":
        a=json.dumps(normalized(json.loads(pathlib.Path(x.before).read_text())),indent=2,sort_keys=True,ensure_ascii=False).splitlines();b=json.dumps(normalized(json.loads(pathlib.Path(x.after).read_text())),indent=2,sort_keys=True,ensure_ascii=False).splitlines();z="\n".join(difflib.unified_diff(a,b,fromfile=x.before,tofile=x.after,lineterm=""));pathlib.Path(x.output).write_text(z+"\n") if x.output else print(z or "No differences found.");return 1 if z else 0
    return check(pathlib.Path(x.snapshot),pathlib.Path(x.plan))
if __name__=="__main__":raise SystemExit(main())