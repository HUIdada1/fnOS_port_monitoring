# -*- coding: utf-8 -*-
"""fnOS application manifests, docker metadata and firewall declarations."""

import json
import os
import re
import subprocess
import time

_SHOT = {"ts": 0, "apps": {}, "docker": {}, "fw": set(), "projects": {}}
_TTL_APPS = 60
_TTL_DOCKER = 300

_APP_PATH_RE = re.compile(
    r"/(?:@appcenter|@appdata|@appconf|@apphome|@appmeta|@apptemp|@appshare)"
    r"/([^/\s]+)"
)


def _run(cmd, timeout=4):
    try:
        proc = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=timeout, check=False,
        )
        return proc.returncode, proc.stdout.decode("utf-8", "replace")
    except (OSError, subprocess.SubprocessError):
        return 127, ""


def _unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        return value[1:-1]
    return value


def parse_manifest(path: str) -> dict:
    data = {}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                data[key.strip()] = _unquote(value.strip())
    except OSError:
        return {}
    return data


def load_apps() -> dict:
    """appname -> manifest dict, with resolved target path."""
    apps = {}
    base = "/var/apps"
    try:
        entries = sorted(os.listdir(base))
    except OSError:
        return apps
    for name in entries:
        mpath = os.path.join(base, name, "manifest")
        if not os.path.isfile(mpath):
            continue
        manifest = parse_manifest(mpath)
        if not manifest:
            continue
        target = os.path.join(base, name, "target")
        try:
            manifest["_target"] = os.path.realpath(target)
        except OSError:
            manifest["_target"] = target
        manifest["_dir"] = os.path.join(base, name)
        apps[manifest.get("appname") or name] = manifest
    return apps


def _parse_ports(blob):
    ports = set()
    if isinstance(blob, dict):
        for key, value in blob.items():
            if key == "ports" and isinstance(value, list):
                ports.update(int(p) for p in value if isinstance(p, int))
            else:
                ports |= _parse_ports(value)
    elif isinstance(blob, list):
        for item in blob:
            ports |= _parse_ports(item)
    return ports


def load_fw_ports() -> set:
    """Ports declared by the fnOS firewall config (declaration, not kernel truth)."""
    path = "/usr/trim/etc/fw.conf"
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return set()
    return _parse_ports(data)


def load_projects() -> dict:
    """docker compose project name -> folder (from fnOS dockermgr config)."""
    path = "/usr/trim/etc/dockermgr.conf"
    out = {}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return out
    for item in data.get("projects", []) or []:
        name = (item or {}).get("name")
        folder = (item or {}).get("folder")
        if name and folder:
            out[name] = folder
    return out


def load_docker() -> dict:
    """{'by_id': {...}, 'by_ip': {...}, 'by_name': {...}} via a single inspect."""
    code, out = _run(["docker", "ps", "-q"])
    if code != 0 or not out.strip():
        return {"by_id": {}, "by_ip": {}, "by_name": {}}
    ids = out.split()
    fmt = ("{{.Id}}|{{.Name}}|{{.Config.Image}}|{{.State.Status}}|{{.State.Pid}}|"
           "{{range $k,$v := .NetworkSettings.Networks}}{{$k}}={{$v.IPAddress}};{{end}}")
    code, out = _run(["docker", "inspect", "--format", fmt] + ids, timeout=6)
    by_id, by_ip, by_name = {}, {}, {}
    if code != 0:
        return {"by_id": {}, "by_ip": {}, "by_name": {}}
    for line in out.splitlines():
        parts = line.split("|")
        if len(parts) < 6:
            continue
        cid, name, image, status, pid, nets = parts[:6]
        ips = []
        for chunk in nets.split(";"):
            if "=" in chunk:
                ip = chunk.split("=", 1)[1].strip()
                if ip:
                    ips.append(ip)
        try:
            pid = int(pid)
        except ValueError:
            pid = 0
        info = {"id": cid[:12], "name": name.lstrip("/"), "image": image,
                "status": status, "ips": ips, "pid": pid}
        by_id[cid[:12]] = info
        by_name[info["name"]] = info
        for ip in ips:
            by_ip[ip] = info
    return {"by_id": by_id, "by_ip": by_ip, "by_name": by_name}


def refresh(force=False) -> dict:
    now = time.time()
    if force or now - _SHOT["ts"] > _TTL_APPS:
        _SHOT["apps"] = load_apps()
        _SHOT["fw"] = load_fw_ports()
        _SHOT["projects"] = load_projects()
    if force or now - _SHOT["ts"] > _TTL_DOCKER:
        _SHOT["docker"] = load_docker()
    _SHOT["ts"] = now
    return _SHOT


def app_from_path(text: str, apps: dict):
    if not text:
        return None
    for match in _APP_PATH_RE.finditer(text):
        name = match.group(1)
        if name in apps:
            return name
    return None


# ------------------------------------------------------------------ netns peek
_INNER = {"ts": {}, "data": {}}
_INNER_TTL = 180


def _parse_ss(text):
    procs = {}
    ports = set()
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 5:
            continue
        local = fields[4] if fields[0] in ("tcp", "udp") else fields[3]
        if ":" not in local:
            continue
        try:
            port = int(local.rsplit(":", 1)[1])
        except ValueError:
            continue
        ports.add(port)
        match = re.search(r'\("([^"]+)",pid=', line)
        if match:
            procs.setdefault(port, match.group(1))
    return ports, procs


def _parse_procnet(text):
    ports = set()
    for line in text.splitlines():
        fields = line.split()
        if len(fields) > 3 and fields[3] in ("0A", "07"):
            try:
                ports.add(int(fields[1].rsplit(":", 1)[1], 16))
            except (ValueError, IndexError):
                continue
    return ports


def container_listeners(pid):
    """Listening ports inside a container netns. Read-only, 2s timeout, cached."""
    if not pid or pid <= 0:
        return {"ports": set(), "procs": {}}
    now = time.time()
    cached = _INNER["ts"].get(pid)
    if cached and now - cached < _INNER_TTL:
        return _INNER["data"].get(pid, {"ports": set(), "procs": {}})

    result = {"ports": set(), "procs": {}}
    code, out = _run(["nsenter", "-t", str(pid), "-n", "ss", "-tulnH"], timeout=2)
    if code == 0 and out:
        ports, procs = _parse_ss(out)
        result = {"ports": ports, "procs": procs}
    else:
        code, out = _run(["nsenter", "-t", str(pid), "-n", "cat",
                          "/proc/net/tcp", "/proc/net/tcp6",
                          "/proc/net/udp", "/proc/net/udp6"], timeout=2)
        if code == 0 and out:
            result = {"ports": _parse_procnet(out), "procs": {}}

    _INNER["ts"][pid] = now
    _INNER["data"][pid] = result
    return result
