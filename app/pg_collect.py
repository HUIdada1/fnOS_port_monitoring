# -*- coding: utf-8 -*-
"""Read-only collectors built on /proc. No third-party dependency, no writes."""

import os
import socket
import struct
import time

TCP_LISTEN = "0A"
UDP_UNCONN = "07"

CLK_TCK = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100

IPV4_ANY = "0.0.0.0"
IPV6_ANY = "::"


# ---------------------------------------------------------------- address utils

def _hex_to_ip(hex_addr: str) -> str:
    """Convert a /proc/net address field into a printable IP string."""
    try:
        raw = bytes.fromhex(hex_addr)
    except ValueError:
        return "?"
    if len(raw) == 4:
        return socket.inet_ntop(socket.AF_INET, raw[::-1])
    if len(raw) == 16:
        # each 32-bit group is stored little-endian
        buf = b"".join(raw[i:i + 4][::-1] for i in range(0, 16, 4))
        try:
            ip = socket.inet_ntop(socket.AF_INET6, buf)
        except OSError:
            return "?"
        if ip.startswith("::ffff:") and "." in ip:
            return ip[7:]
        return ip
    return "?"


def classify_addr(ip: str) -> str:
    """loopback / any / linklocal / private / public / nic."""
    if ip in (IPV4_ANY, IPV6_ANY):
        return "any"
    if ip.startswith("127.") or ip == "::1":
        return "loopback"
    if ip.lower().startswith("fe80:"):
        return "linklocal"
    if ip.startswith("10.") or ip.startswith("192.168."):
        return "private"
    if ip.startswith("172."):
        try:
            second = int(ip.split(".")[1])
            if 16 <= second <= 31:
                return "private"
        except (ValueError, IndexError):
            pass
        return "public"
    if ip.startswith("169.254."):
        return "linklocal"
    return "public"


def exposure_of(addrs, has_global_v6: bool) -> dict:
    """Roll a set of listen addresses up to one exposure level."""
    kinds = {classify_addr(a) for a in addrs}
    if "loopback" in kinds and len(kinds) == 1:
        return {"level": "loopback", "score": 0, "label": "仅本机"}
    if IPV6_ANY in addrs and has_global_v6:
        return {"level": "public_v6", "score": 40, "label": "公网 IPv6 可直连"}
    if IPV4_ANY in addrs or IPV6_ANY in addrs:
        return {"level": "any", "score": 32, "label": "全网卡"}
    if kinds & {"private", "linklocal"}:
        return {"level": "nic", "score": 20, "label": "指定网卡"}
    return {"level": "nic", "score": 20, "label": "指定地址"}


# ---------------------------------------------------------------- /proc/net

def _parse_net(path: str, proto: str, want_states) -> list:
    rows = []
    try:
        with open(path, "r", encoding="ascii", errors="replace") as fh:
            next(fh, None)
            for line in fh:
                fields = line.split()
                if len(fields) < 10:
                    continue
                st = fields[3]
                if st not in want_states:
                    continue
                local, _, lport = fields[1].rpartition(":")
                remote, _, rport = fields[2].rpartition(":")
                try:
                    inode = int(fields[9])
                except ValueError:
                    continue
                rows.append({
                    "proto": proto,
                    "ip": _hex_to_ip(local),
                    "port": int(lport, 16),
                    "rip": _hex_to_ip(remote),
                    "rport": int(rport, 16),
                    "state": st,
                    "uid": int(fields[7]),
                    "inode": inode,
                })
    except OSError:
        pass
    return rows


def listen_sockets() -> list:
    """All bound sockets in the host network namespace."""
    out = []
    out += _parse_net("/proc/net/tcp", "tcp", (TCP_LISTEN,))
    out += _parse_net("/proc/net/tcp6", "tcp", (TCP_LISTEN,))
    out += _parse_net("/proc/net/udp", "udp", (UDP_UNCONN, TCP_LISTEN))
    out += _parse_net("/proc/net/udp6", "udp", (UDP_UNCONN, TCP_LISTEN))
    return out


def established() -> dict:
    """(port, proto) -> {in, out} connection counters split by peer scope."""
    counters = {}
    for proto, path in (("tcp", "/proc/net/tcp"), ("tcp", "/proc/net/tcp6"),
                        ("udp", "/proc/net/udp"), ("udp", "/proc/net/udp6")):
        for row in _parse_net(path, proto, ("01",)):
            key = (row["port"], proto)
            slot = counters.setdefault(key, {"in": 0, "out": 0})
            if classify_addr(row["rip"]) in ("private", "loopback", "linklocal"):
                slot["in"] += 1
            else:
                slot["out"] += 1
    return counters


# ---------------------------------------------------------------- processes

def scan_fds() -> tuple:
    """inode -> pid map. Single pass over /proc/<pid>/fd."""
    inode2pid = {}
    pids = []
    try:
        entries = os.listdir("/proc")
    except OSError:
        return inode2pid, pids
    for name in entries:
        if not name.isdigit():
            continue
        pid = int(name)
        fddir = "/proc/%d/fd" % pid
        try:
            fds = os.listdir(fddir)
        except OSError:
            continue
        pids.append(pid)
        for fd in fds:
            try:
                link = os.readlink("%s/%s" % (fddir, fd))
            except OSError:
                continue
            if link.startswith("socket:["):
                try:
                    inode2pid.setdefault(int(link[8:-1]), pid)
                except ValueError:
                    continue
    return inode2pid, pids


def read_proc(pid: int) -> dict:
    info = {"pid": pid, "comm": "", "cmdline": "", "exe": "", "uid": -1,
            "ppid": 0, "uptime": 0}
    try:
        with open("/proc/%d/comm" % pid, "r", encoding="utf-8", errors="replace") as fh:
            info["comm"] = fh.read().strip()
    except OSError:
        pass
    try:
        with open("/proc/%d/cmdline" % pid, "rb") as fh:
            raw = fh.read(4096)
        info["cmdline"] = raw.replace(b"\x00", b" ").decode("utf-8", "replace").strip()
    except OSError:
        pass
    try:
        info["exe"] = os.readlink("/proc/%d/exe" % pid)
    except OSError:
        pass
    try:
        with open("/proc/%d/status" % pid, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if line.startswith("Uid:"):
                    info["uid"] = int(line.split()[1])
                elif line.startswith("PPid:"):
                    info["ppid"] = int(line.split()[1])
    except (OSError, ValueError):
        pass
    try:
        with open("/proc/%d/stat" % pid, "r", encoding="utf-8", errors="replace") as fh:
            fields = fh.read().rsplit(") ", 1)[-1].split()
        start_ticks = int(fields[19])
        with open("/proc/uptime", "r", encoding="ascii") as fh:
            uptime = float(fh.read().split()[0])
        info["uptime"] = max(0, int(uptime - start_ticks / CLK_TCK))
    except (OSError, ValueError, IndexError):
        pass
    return info


def read_cgroup(pid: int) -> str:
    try:
        with open("/proc/%d/cgroup" % pid, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                parts = line.strip().split(":", 2)
                if len(parts) == 3 and parts[2]:
                    return parts[2]
    except OSError:
        pass
    return ""


def unit_of(cgroup: str) -> str:
    if not cgroup:
        return ""
    name = cgroup.rstrip("/").rsplit("/", 1)[-1]
    if name.endswith(".service"):
        return name[:-8]
    if name.endswith(".scope"):
        return name[:-6]
    return ""


def container_of(cgroup: str) -> str:
    """docker-<64 hex>.scope -> short id."""
    if not cgroup:
        return ""
    name = cgroup.rstrip("/").rsplit("/", 1)[-1]
    if name.startswith("docker-") and name.endswith(".scope"):
        return name[7:-6].split("-")[0]
    return ""


def has_global_ipv6() -> bool:
    try:
        with open("/proc/net/if_inet6", "r", encoding="ascii") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) >= 4 and parts[3] == "00":
                    addr = parts[0]
                    if addr != "0" * 32:
                        return True
    except OSError:
        pass
    return False


def proc_uptime() -> float:
    try:
        with open("/proc/uptime", "r", encoding="ascii") as fh:
            return float(fh.read().split()[0])
    except (OSError, ValueError):
        return 0.0


def snapshot() -> dict:
    """One full read-only collection pass."""
    started = time.time()
    sockets = listen_sockets()
    inode2pid, pids = scan_fds()

    need = set()
    for sock in sockets:
        pid = inode2pid.get(sock["inode"])
        if pid:
            need.add(pid)

    procs = {}
    for pid in need:
        procs[pid] = read_proc(pid)
        procs[pid]["cgroup"] = read_cgroup(pid)
        procs[pid]["unit"] = unit_of(procs[pid]["cgroup"])
        procs[pid]["container"] = container_of(procs[pid]["cgroup"])

    for sock in sockets:
        pid = inode2pid.get(sock["inode"], 0)
        sock["pid"] = pid
        info = procs.get(pid, {})
        sock["comm"] = info.get("comm", "")
        sock["cmdline"] = info.get("cmdline", "")
        sock["exe"] = info.get("exe", "")
        sock["uid"] = info.get("uid", sock.get("uid", -1))
        sock["uptime"] = info.get("uptime", 0)
        sock["cgroup"] = info.get("cgroup", "")
        sock["unit"] = info.get("unit", "")
        sock["container"] = info.get("container", "")

    return {
        "ts": int(started),
        "elapsed_ms": int((time.time() - started) * 1000),
        "sockets": sockets,
        "procs": procs,
        "pid_count": len(pids),
        "has_global_v6": has_global_ipv6(),
        "uptime": proc_uptime(),
    }
