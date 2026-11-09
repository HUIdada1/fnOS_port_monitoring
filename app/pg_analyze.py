# -*- coding: utf-8 -*-
"""State machine, conflict detection, attribution and risk scoring."""

import json
import os
import time
from collections import deque

import pg_apps
import pg_collect

STATE_LABEL = {
    "ACTIVE": "活跃",
    "WARM": "低频",
    "IDLE": "闲置",
    "FRESH": "刚启动",
    "ORPHAN": "僵尸",
    "KERNEL": "内核态",
    "GHOST": "幽灵",
    "GHOST_SOFT": "幽灵(声明)",
}

STATE_ORDER = {
    "ACTIVE": 0, "WARM": 1, "IDLE": 2, "FRESH": 3,
    "ORPHAN": 4, "KERNEL": 5, "GHOST": 6, "GHOST_SOFT": 7,
}

UNIT_LABELS = {
    "trim_nginx": "fnOS Web 网关",
    "trim_app_center": "fnOS 应用中心",
    "trim_connect": "fnOS 连接服务",
    "trim_media": "fnOS 影视",
    "postgresql@15-main": "PostgreSQL 15",
    "rabbitmq-server": "RabbitMQ",
    "epmd": "Erlang 端口映射",
    "smbd": "SMB 文件共享",
    "nmbd": "NetBIOS 名称服务",
    "smbftpd": "FTP 服务",
    "nfs-mountd": "NFS 挂载",
    "nfs-idmapd": "NFS ID 映射",
    "nfsdcld": "NFS 客户端跟踪",
    "rpcbind": "RPC 端口映射",
    "rpc-statd": "NFS 锁状态",
    "avahi-daemon": "mDNS 服务发现",
    "wsdd2": "WS-Discovery",
    "sshd": "SSH 远程管理",
    "docker": "Docker 引擎",
    "containerd": "containerd",
    "libvirtd": "虚拟机管理",
    "upnp_service": "UPnP 端口映射",
}

KERNEL_PORTS = {2049, 111}


class Usage:
    """Sliding window of connection counts and DNAT packet deltas."""

    def __init__(self, window=300):
        self.window = window
        self.samples = deque()
        self._last_packets = {}

    def update(self, ts, conns, dnat_rules):
        deltas = {}
        for rule in dnat_rules:
            key = (rule["proto"], rule["host_port"])
            prev = self._last_packets.get(key)
            current = rule["packets"]
            if prev is None or current < prev:
                delta = 0
            else:
                delta = current - prev
            self._last_packets[key] = current
            deltas[key] = delta

        snap = {}
        for (port, proto), val in conns.items():
            snap[(port, proto)] = (val["in"], val["out"])
        self.samples.append((ts, snap, deltas))
        while self.samples and ts - self.samples[0][0] > self.window:
            self.samples.popleft()

    def stats(self, port, proto):
        peak = 0
        conns_in = 0
        conns_out = 0
        ext = 0
        for _, snap, deltas in self.samples:
            cin, cout = snap.get((port, proto), (0, 0))
            peak = max(peak, cin + cout)
            conns_in = max(conns_in, cin)
            conns_out = max(conns_out, cout)
            ext += deltas.get((proto, port), 0)
        return {"peak": peak, "in": conns_in, "out": conns_out, "ext_packets": ext}


def load_kb(path):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def kb_lookup(kb, port):
    return kb.get(str(port), {}) or {}


def _owner_label(app, kind, unit, container):
    if kind == "fnos":
        return "飞牛应用 · %s" % app
    if kind == "docker":
        return "容器 · %s" % app
    if kind == "system":
        label = UNIT_LABELS.get(unit, unit or "")
        return "系统服务 · %s" % label if label else "系统服务"
    return "未归属"


def _resolve(sock, apps, docker, dnat_rule):
    container = None
    cid = sock.get("container", "")
    if cid and cid in docker.get("by_id", {}):
        container = docker["by_id"][cid]
    if container is None and dnat_rule:
        container = docker.get("by_ip", {}).get(dnat_rule.get("dest_ip", ""))

    app_name = pg_apps.app_from_path(sock.get("exe", ""), apps) or \
        pg_apps.app_from_path(sock.get("cmdline", ""), apps)

    if app_name:
        info = apps.get(app_name, {})
        return {
            "app": info.get("display_name") or app_name,
            "app_raw": app_name,
            "kind": "fnos",
            "container": container["name"] if container else "",
            "image": container["image"] if container else "",
        }
    if container:
        return {
            "app": container["name"],
            "app_raw": container["name"],
            "kind": "docker",
            "container": container["name"],
            "image": container["image"],
        }
    unit = sock.get("unit", "")
    if unit:
        return {"app": UNIT_LABELS.get(unit, unit), "app_raw": unit,
                "kind": "system", "container": "", "image": ""}
    return {"app": sock.get("comm", "") or "未知", "app_raw": "", "kind": "unknown",
            "container": "", "image": ""}


def _to_int(value, default):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _risk(exposure_score, sensitivity, auth):
    score = exposure_score + _to_int(sensitivity, 20) + _to_int(auth, 10)
    score = max(0, min(100, score))
    if score >= 70:
        level = "high"
    elif score >= 40:
        level = "mid"
    else:
        level = "low"
    return score, level


def analyze(snap, usage, apps_snapshot, dnat, labels=None):
    apps = apps_snapshot.get("apps", {})
    docker = apps_snapshot.get("docker", {"by_id": {}, "by_ip": {}, "by_name": {}})
    fw_ports = apps_snapshot.get("fw", set())
    kb = load_kb(os.path.join(os.path.dirname(os.path.abspath(__file__)), "kb_ports.json"))
    has_v6 = snap.get("has_global_v6", False)

    dnat_by_host = {}
    for rule in dnat.get("rules", []):
        dnat_by_host.setdefault((rule["proto"], rule["host_port"]), []).append(rule)

    groups = {}
    for sock in snap["sockets"]:
        key = (sock["port"], sock["proto"])
        groups.setdefault(key, []).append(sock)

    # Ports that exist only as a DNAT mapping or a firewall declaration.
    listeners = set(groups)
    ghosts = []
    for (proto, host_port), rules in dnat_by_host.items():
        if (host_port, proto) not in listeners:
            ghosts.append((host_port, proto, "hard", rules))
    for port in sorted(fw_ports):
        if (port, "tcp") not in listeners and (port, "udp") not in listeners:
            if not any(g[0] == port for g in ghosts):
                ghosts.append((port, "tcp", "soft", []))

    records = []
    peek_started = time.time()
    peek_budget = 2.5
    for (port, proto), socks in groups.items():
        kb_entry = kb_lookup(kb, port)
        addrs = sorted({s["ip"] for s in socks})
        exposure = pg_collect.exposure_of(addrs, has_v6)
        stats = usage.stats(port, proto)

        pids = sorted({s["pid"] for s in socks if s.get("pid")})
        primary = next((s for s in socks if s.get("pid")), socks[0])
        rules = dnat_by_host.get((proto, port), [])
        rule = rules[0] if rules else None

        # A shared port can have several owners (e.g. mDNS: avahi + trim-media).
        # Prefer the most specific one: fnOS app > container > systemd > unknown.
        rank = {"fnos": 0, "docker": 1, "system": 2, "unknown": 3}
        owner = None
        owners = []
        for s in socks:
            cand = _resolve(s, apps, docker, rule)
            owners.append(_owner_label(cand["app"], cand["kind"], s.get("unit", ""),
                                       cand["container"]))
            if owner is None or rank.get(cand["kind"], 9) < rank.get(owner["kind"], 9):
                owner = cand

        conflicts = []
        comms = {s.get("comm", "") for s in socks if s.get("comm")}
        if len(comms) > 1:
            conflicts.append({
                "code": "SHARED", "level": "info",
                "detail": "同一端口被 %d 个不同进程共享（SO_REUSEPORT）" % len(comms),
            })

        # state
        if not pids:
            state = "KERNEL" if (port in KERNEL_PORTS or kb_entry.get("kernel")) else "ORPHAN"
        elif stats["peak"] > 0 or stats["ext_packets"] > 0:
            state = "ACTIVE" if stats["peak"] >= 5 or stats["ext_packets"] >= 100 else "WARM"
        elif primary.get("uptime", 0) and primary["uptime"] < 1800:
            state = "FRESH"
        else:
            state = "IDLE"

        # hijack: a well-known port served by something unexpected
        expect = kb_entry.get("expect_proc") or []
        comm = primary.get("comm", "")
        if expect and comm and comm not in expect and comm not in ("docker-proxy", "systemd"):
            if kb_entry.get("category") in ("database", "remote", "panel"):
                conflicts.append({
                    "code": "HIJACK", "level": "high",
                    "detail": "该端口预期由 %s 使用，实际为 %s" % ("/".join(expect), comm),
                })

        # risk: an all-interface bind is "expected" for servers designed to listen
        # broadly (nginx / SMB / gateway), and should not dominate the score.
        e_score = exposure["score"]
        if kb_entry.get("expect_any") and exposure["level"] in ("any", "public_v6"):
            e_score = int(e_score * 0.6)
        # container internals: only worth one nsenter call when a DNAT maps to it
        inner_proc = ""
        inner_ports = []
        inner_verified = False
        if owner["kind"] == "docker" and rule and (time.time() - peek_started) < peek_budget:
            cinfo = docker.get("by_name", {}).get(owner["container"]) or {}
            inner = pg_apps.container_listeners(cinfo.get("pid", 0))
            inner_ports = sorted(inner["ports"])
            inner_proc = inner["procs"].get(rule["dest_port"], "")
            inner_verified = rule["dest_port"] in inner["ports"]

        risk, level = _risk(e_score, kb_entry.get("sensitivity"),
                            kb_entry.get("auth_score", 10))

        app_label = _owner_label(owner["app"], owner["kind"], primary.get("unit", ""),
                                 owner["container"])
        desc = kb_entry.get("desc", "")
        advice = kb_entry.get("advice", "")
        if state == "KERNEL":
            app_label = "内核态 · %s" % (kb_entry.get("service") or "系统服务")
            if not desc:
                desc = "由内核直接持有 socket，用户态进程表中查不到持有者"
        elif state == "ORPHAN":
            app_label = "无归属 · socket 残留"
            if not desc:
                desc = "端口处于监听状态，但找不到持有它的进程，socket 所属 cgroup 已消失"
            if not advice:
                advice = "通常是容器或进程退出后 socket 未回收，重启对应容器或主机即可释放"

        records.append({
            "port": port,
            "proto": proto,
            "state": state,
            "state_label": STATE_LABEL.get(state, state),
            "service": kb_entry.get("service") or primary.get("comm") or "未知服务",
            "category": kb_entry.get("category", "unknown"),
            "desc": desc,
            "advice": advice,
            "app": owner["app"],
            "app_raw": owner["app_raw"],
            "app_kind": owner["kind"],
            "app_label": app_label,
            "owners": sorted(set(owners)),
            "comm": comm,
            "pid": pids[0] if pids else 0,
            "pids": pids,
            "exe": primary.get("exe", ""),
            "cmdline": primary.get("cmdline", ""),
            "cgroup": primary.get("cgroup", ""),
            "unit": primary.get("unit", ""),
            "container": owner["container"],
            "image": owner["image"],
            "addrs": addrs,
            "exposure": exposure["level"],
            "exposure_score": exposure["score"],
            "exposure_label": exposure["label"],
            "conns_in": stats["in"],
            "conns_out": stats["out"],
            "ext_packets": stats["ext_packets"],
            "risk": risk,
            "risk_level": level,
            "conflicts": conflicts,
            "mapped_to": ("%s:%d" % (rule["dest_ip"], rule["dest_port"])) if rule else "",
            "inner_proc": inner_proc,
            "inner_ports": inner_ports,
            "inner_verified": inner_verified,
            "n_links": len(socks),
            "note": "",
            "accepted": False,
        })

    # conflicts that need the whole picture
    by_port = {}
    for rec in records:
        by_port.setdefault(rec["port"], []).append(rec)

    for port, recs in by_port.items():
        protos = {r["proto"] for r in recs}
        if len(protos) > 1:
            for rec in recs:
                rec["conflicts"].append({
                    "code": "DUAL_PROTO", "level": "info",
                    "detail": "同一端口号同时被 TCP 与 UDP 使用（正常，仅提示）",
                })

    # declared vs actual for fnOS apps
    for name, manifest in apps.items():
        declared = str(manifest.get("service_port") or "").strip()
        if not declared.isdigit():
            continue
        dport = int(declared)
        matched = [r for r in records if r["port"] == dport]
        owned = [r for r in matched if r.get("app_raw") == name]
        if not matched:
            target = next((r for r in records if r.get("app_raw") == name), None)
            if target is not None:
                target["conflicts"].append({
                    "code": "DECL_MISMATCH", "level": "mid",
                    "detail": "manifest 声明端口 %d，实际监听 %d" % (dport, target["port"]),
                })
        elif not owned:
            for r in matched:
                r["conflicts"].append({
                    "code": "DECL_MISMATCH", "level": "mid",
                    "detail": "端口被声明给应用 %s，实际归属 %s" % (name, r["app"]),
                })

    for rule_list in dnat_by_host.values():
        for rule in rule_list:
            if rule.get("duplicate"):
                for rec in records:
                    if rec["port"] == rule["host_port"] and rec["proto"] == rule["proto"]:
                        rec["conflicts"].append({
                            "code": "MAP_CONFLICT", "level": "high",
                            "detail": "多条 DNAT 规则抢占同一宿主端口，后写入的不会生效",
                        })

    # ghost records (no listener)
    for port, proto, kind, rules in ghosts:
        kb_entry = kb_lookup(kb, port)
        rec = {
            "port": port, "proto": proto, "state": "GHOST" if kind == "hard" else "GHOST_SOFT",
            "state_label": STATE_LABEL["GHOST" if kind == "hard" else "GHOST_SOFT"],
            "service": kb_entry.get("service") or "未知服务",
            "category": kb_entry.get("category", "unknown"),
            "desc": kb_entry.get("desc", ""), "advice": kb_entry.get("advice", ""),
            "app": "—", "app_raw": "", "app_kind": "none", "app_label": "无监听",
            "owners": [],
            "comm": "", "pid": 0, "pids": [], "exe": "", "cmdline": "", "cgroup": "",
            "unit": "", "container": "", "image": "",
            "addrs": [], "exposure": "none", "exposure_score": 0,
            "exposure_label": "无监听",
            "conns_in": 0, "conns_out": 0, "ext_packets": 0,
            "risk": 20, "risk_level": "low",
            "conflicts": [{
                "code": "GHOST_HARD" if kind == "hard" else "GHOST_SOFT",
                "level": "mid" if kind == "hard" else "info",
                "detail": "存在端口映射但无监听" if kind == "hard"
                          else "防火墙配置声明放行但无监听（配置层，非内核事实）",
            }],
            "mapped_to": ("%s:%d" % (rules[0]["dest_ip"], rules[0]["dest_port"])) if rules else "",
            "inner_proc": "", "inner_ports": [], "inner_verified": False,
            "n_links": 0, "note": "", "accepted": False,
        }
        records.append(rec)

    records.sort(key=lambda r: (-r["risk"], r["port"], r["proto"]))

    overview = {
        "ts": snap["ts"],
        "elapsed_ms": snap["elapsed_ms"],
        "total": len(records),
        "listening": sum(1 for r in records if r["state"] not in ("GHOST", "GHOST_SOFT")),
        "high": sum(1 for r in records if r["risk_level"] == "high"),
        "mid": sum(1 for r in records if r["risk_level"] == "mid"),
        "low": sum(1 for r in records if r["risk_level"] == "low"),
        "idle": sum(1 for r in records if r["state"] == "IDLE"),
        "abnormal": sum(1 for r in records
                        if r["state"] in ("ORPHAN", "GHOST", "GHOST_SOFT")
                        or any(c["level"] == "high" for c in r["conflicts"])),
        "exposed": sum(1 for r in records if r["exposure"] in ("any", "public_v6")),
        "public_v6": sum(1 for r in records if r["exposure"] == "public_v6"),
        "has_global_v6": has_v6,
        "dnat_tool": dnat.get("tool", ""),
        "dnat_error": dnat.get("error", ""),
        "pid_count": snap.get("pid_count", 0),
    }

    conflicts_total = []
    for rec in records:
        for item in rec["conflicts"]:
            conflicts_total.append({
                "port": rec["port"], "proto": rec["proto"], "service": rec["service"],
                "code": item["code"], "level": item["level"], "detail": item["detail"],
            })

    return records, overview, conflicts_total
