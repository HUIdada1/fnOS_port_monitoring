# -*- coding: utf-8 -*-
"""DNAT / port-forward discovery with traffic counters (nftables first)."""

import re
import subprocess
import time

_CACHE = {"ts": 0, "rules": [], "tool": "", "error": ""}
_CACHE_TTL = 3

_DNAT_RE = re.compile(
    r"\b(tcp|udp)\s+dport\s+(\d+)\b[^\n]*?"
    r"(?:counter\s+packets\s+(\d+)\s+bytes\s+(\d+)\s+)?"
    r"dnat\s+(?:ip\s+)?to\s+([0-9a-fA-F.:]+):(\d+)"
)

_IPT_RE = re.compile(
    r"^\s*(\d+)\s+(\S+)\s+DNAT\s+(tcp|udp)\s+.*?dpt:(\d+)\s+to:([0-9.]+):(\d+)",
    re.MULTILINE,
)


def _run(cmd, timeout=3):
    try:
        proc = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=timeout, check=False,
        )
        return proc.returncode, proc.stdout.decode("utf-8", "replace")
    except (OSError, subprocess.SubprocessError):
        return 127, ""


def read_dnat(force=False) -> dict:
    """Return {'rules': [...], 'tool': 'nft'|'iptables'|'', 'error': str}."""
    now = time.time()
    if not force and now - _CACHE["ts"] < _CACHE_TTL:
        return _CACHE

    rules = []
    tool = ""
    error = ""

    code, out = _run(["nft", "-a", "list", "ruleset"])
    if code == 0 and out:
        tool = "nft"
        for line in out.splitlines():
            if "dnat" not in line:
                continue
            m = _DNAT_RE.search(line)
            if not m:
                continue
            rules.append({
                "proto": m.group(1),
                "host_port": int(m.group(2)),
                "packets": int(m.group(3) or 0),
                "bytes": int(m.group(4) or 0),
                "dest_ip": m.group(5),
                "dest_port": int(m.group(6)),
            })
    else:
        code, out = _run(["iptables", "-t", "nat", "-L", "-v", "-n"])
        if code == 0 and out:
            tool = "iptables"
            for m in _IPT_RE.finditer(out):
                rules.append({
                    "proto": m.group(3),
                    "host_port": int(m.group(4)),
                    "packets": int(m.group(1)),
                    "bytes": int(m.group(2)),
                    "dest_ip": m.group(5),
                    "dest_port": int(m.group(6)),
                })
        else:
            error = "nft/iptables 均不可用"

    # A host port mapped twice is a real conflict: the later rule never matches.
    seen = {}
    for rule in rules:
        key = (rule["proto"], rule["host_port"])
        rule["duplicate"] = key in seen
        seen[key] = rule

    _CACHE.update({"ts": now, "rules": rules, "tool": tool, "error": error})
    return _CACHE
