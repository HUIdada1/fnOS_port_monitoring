# -*- coding: utf-8 -*-
"""Hot update: pull the app payload from GitHub raw, verify it, swap files, self-restart.

Only the read-only app payload is touched (portguardd, pg_*.py, kb_ports.json, ui/).
Config, database and gateway socket are never overwritten, so a failed update
still leaves a working (old) installation; files are staged first and moved in
only after every download and syntax check passes.
"""

import os
import py_compile
import re
import shutil
import sys
import tempfile
import threading
import time
import urllib.request

DEFAULT_REPO = "HUIdada1/fnOS_port_monitoring"
DEFAULT_REF = "main"

UPDATE_FILES = [
    "portguardd",
    "pg_action.py", "pg_analyze.py", "pg_apps.py", "pg_collect.py",
    "pg_config.py", "pg_net.py", "pg_server.py", "pg_store.py", "pg_update.py",
    "kb_ports.json",
    "ui/index.html",
]

STATE = {"phase": "idle", "local": "", "remote": "", "available": False,
         "progress": "", "error": "", "ts": 0}
_LOCK = threading.Lock()


def _set(**kw):
    with _LOCK:
        STATE.update(kw)
        STATE["ts"] = time.time()


def snapshot():
    with _LOCK:
        return dict(STATE)


def _cmp(a, b):
    ka = [int(x) for x in re.findall(r"\d+", a or "0")]
    kb = [int(x) for x in re.findall(r"\d+", b or "0")]
    n = max(len(ka), len(kb))
    ka += [0] * (n - len(ka))
    kb += [0] * (n - len(kb))
    return (ka > kb) - (ka < kb)


def base_url(cfg):
    mirror = (cfg.get("update_mirror") or "").strip().rstrip("/") or "https://raw.githubusercontent.com"
    repo = (cfg.get("update_repo") or DEFAULT_REPO).strip()
    ref = (cfg.get("update_ref") or DEFAULT_REF).strip()
    return "%s/%s/%s/app/" % (mirror, repo, ref)


def _get(url, timeout=20):
    req = urllib.request.Request(url, headers={"User-Agent": "PortGuard-Updater"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def check(cfg, local_version):
    _set(phase="checking", error="", local=local_version)
    try:
        text = _get(base_url(cfg) + "portguardd", timeout=15).decode("utf-8", "replace")
        match = re.search(r'VERSION\s*=\s*["\']([\d.]+)["\']', text)
        if not match:
            raise ValueError("远端未找到版本号")
        remote = match.group(1)
        available = _cmp(remote, local_version) > 0
        _set(phase="idle", local=local_version, remote=remote, available=available)
        return {"local": local_version, "remote": remote, "available": available}
    except Exception as exc:
        _set(phase="idle", error=str(exc)[:200])
        raise


def apply_async(cfg, app_dir):
    if snapshot()["phase"] not in ("idle",):
        return False
    threading.Thread(target=_apply, args=(cfg, app_dir), daemon=True).start()
    return True


def _apply(cfg, app_dir):
    staged = tempfile.mkdtemp(prefix="pg-update-", dir=app_dir)
    try:
        _set(phase="downloading", error="", progress="")
        for rel in UPDATE_FILES:
            data = _get(base_url(cfg) + rel)
            if not data:
                raise ValueError("%s 下载内容为空" % rel)
            dst = os.path.join(staged, *rel.split("/"))
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            with open(dst, "wb") as fh:
                fh.write(data)
            _set(progress=rel)

        for rel in UPDATE_FILES:
            if rel.endswith(".py") or rel == "portguardd":
                py_compile.compile(os.path.join(staged, *rel.split("/")),
                                   cfile=os.devnull, doraise=True)

        _set(phase="installing", progress="")
        for rel in UPDATE_FILES:
            src = os.path.join(staged, *rel.split("/"))
            dst = os.path.join(app_dir, *rel.split("/"))
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            os.replace(src, dst)
        shutil.rmtree(staged, ignore_errors=True)

        _set(phase="restarting")
        time.sleep(1.0)
        sys.stdout.flush()
        os.execv(sys.executable, [sys.executable] + sys.argv)
    except Exception as exc:
        shutil.rmtree(staged, ignore_errors=True)
        _set(phase="idle", error=str(exc)[:200])
