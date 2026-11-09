# -*- coding: utf-8 -*-
"""Configuration, password hashing and small helpers."""

import base64
import hashlib
import hmac
import json
import os
import secrets
import time

DEFAULTS = {
    "port": 18110,
    "bind": "0.0.0.0",
    "interval": 10,
    "window": 300,
    "idle_after": 1800,
    "retention_days": 90,
    "password": "",
    "lang": "zh",
    "show_kernel": True,
}

PBKDF2_ROUNDS = 120000


def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def hash_password(password: str) -> str:
    if not password:
        return ""
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ROUNDS)
    return "pbkdf2_sha256$%d$%s$%s" % (PBKDF2_ROUNDS, _b64e(salt), _b64e(digest))


def verify_password(password: str, stored: str) -> bool:
    if not stored or not password:
        return False
    try:
        algo, rounds, salt, digest = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        calc = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), _b64d(salt), int(rounds)
        )
        return hmac.compare_digest(calc, _b64d(digest))
    except Exception:
        return False


def config_path(data_dir: str) -> str:
    return os.path.join(data_dir, "config.json")


def load(data_dir: str) -> dict:
    cfg = dict(DEFAULTS)
    path = config_path(data_dir)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            saved = json.load(fh)
        if isinstance(saved, dict):
            cfg.update({k: v for k, v in saved.items() if k in DEFAULTS})
    except ValueError:
        # keep the broken file for diagnosis instead of silently overwriting it
        try:
            os.replace(path, "%s.bad-%d" % (path, int(time.time())))
        except OSError:
            pass
    except OSError:
        pass
    return cfg


def save(data_dir: str, cfg: dict) -> None:
    os.makedirs(data_dir, exist_ok=True)
    path = config_path(data_dir)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(cfg, fh, ensure_ascii=False, indent=2)
    os.replace(tmp, path)
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass


def now() -> int:
    return int(time.time())


def human_bytes(num) -> str:
    try:
        num = float(num)
    except Exception:
        return "0 B"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(num) < 1024.0:
            return "%.0f %s" % (num, unit) if unit == "B" else "%.1f %s" % (num, unit)
        num /= 1024.0
    return "%.1f PB" % num
