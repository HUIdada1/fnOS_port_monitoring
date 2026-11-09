# -*- coding: utf-8 -*-
"""Embedded HTTP server: JSON API + single-page UI + session auth."""

import csv
import io
import json
import os
import secrets
import socket
import threading
import time
from collections import deque
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

import pg_config

SESSION_TTL = 12 * 3600
MAX_BODY = 64 * 1024


class Sessions(object):
    def __init__(self):
        self._tokens = {}
        self._lock = threading.Lock()
        self._attempts = {}

    def _prune(self, now):
        for token, exp in list(self._tokens.items()):
            if exp < now:
                self._tokens.pop(token, None)
        if len(self._attempts) > 512:
            for ip, bucket in list(self._attempts.items()):
                if not bucket or now - bucket[-1] > 600:
                    self._attempts.pop(ip, None)

    def issue(self):
        token = secrets.token_urlsafe(32)
        now = time.time()
        with self._lock:
            self._prune(now)
            self._tokens[token] = now + SESSION_TTL
        return token

    def valid(self, token):
        if not token:
            return False
        with self._lock:
            exp = self._tokens.get(token)
            if not exp:
                return False
            if exp < time.time():
                self._tokens.pop(token, None)
                return False
            return True

    def drop(self, token):
        with self._lock:
            self._tokens.pop(token, None)

    def throttle(self, ip):
        now = time.time()
        with self._lock:
            bucket = self._attempts.setdefault(ip, deque())
            while bucket and now - bucket[0] > 300:
                bucket.popleft()
            if len(bucket) >= 8:
                return False
            bucket.append(now)
            return True


class Handler(BaseHTTPRequestHandler):
    server_version = "PortGuard"
    sys_version = ""

    # ------------------------------------------------------------------ utils
    @property
    def core(self):
        return self.server.core

    def log_message(self, fmt, *args):
        pass

    def _cookies(self):
        raw = self.headers.get("Cookie", "")
        jar = cookies.SimpleCookie()
        try:
            jar.load(raw)
        except cookies.CookieError:
            return {}
        return {k: v.value for k, v in jar.items()}

    def _authed(self):
        # No password configured means open access on the LAN.
        if not self.core.cfg.get("password"):
            return True
        return self.core.sessions.valid(self._cookies().get("pg_session", ""))

    def _path(self):
        """Strip the fnOS gateway prefix so one handler serves both entry points."""
        path = urlparse(self.path).path
        prefix = (self.core.cfg.get("gateway_prefix") or "").rstrip("/")
        if prefix and path.startswith(prefix):
            path = path[len(prefix):]
            if not path:
                path = "/"
        return path or "/"

    def _send(self, status, body, ctype="application/json; charset=utf-8", extra=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "SAMEORIGIN")
        self.send_header("Cache-Control", "no-store")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; "
            "style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; "
            "connect-src 'self'; frame-ancestors 'self'",
        )
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _json(self, obj, status=200, extra=None):
        self._send(status, json.dumps(obj, ensure_ascii=False), extra=extra)

    def _body_json(self):
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return {}
        if length <= 0 or length > MAX_BODY:
            return {}
        try:
            return json.loads(self.rfile.read(length).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return {}

    def _static(self, relpath):
        ui_dir = os.path.abspath(os.path.join(self.core.app_dir, "ui"))
        safe = os.path.normpath(relpath).lstrip("/\\")
        full = os.path.abspath(os.path.join(ui_dir, safe))
        try:
            inside = os.path.commonpath([ui_dir, full]) == ui_dir
        except ValueError:
            inside = False
        if not inside:
            return self._send(403, "forbidden", "text/plain; charset=utf-8")
        if not os.path.isfile(full):
            return self._send(404, "not found", "text/plain; charset=utf-8")
        ctype = "application/octet-stream"
        if full.endswith(".html"):
            ctype = "text/html; charset=utf-8"
        elif full.endswith(".png"):
            ctype = "image/png"
        elif full.endswith(".svg"):
            ctype = "image/svg+xml"
        elif full.endswith(".css"):
            ctype = "text/css; charset=utf-8"
        elif full.endswith(".js"):
            ctype = "application/javascript; charset=utf-8"
        with open(full, "rb") as fh:
            data = fh.read()
        self._send(200, data, ctype)

    # ------------------------------------------------------------------ routes
    def do_GET(self):
        try:
            self._handle_get()
        except Exception as exc:  # never leak a traceback to the client
            self._json({"error": "internal error", "detail": str(exc)[:200]}, 500)

    def do_POST(self):
        try:
            self._handle_post()
        except Exception as exc:
            self._json({"error": "internal error", "detail": str(exc)[:200]}, 500)

    def _handle_get(self):
        parsed = urlparse(self.path)
        path = self._path()
        query = parse_qs(parsed.query)

        if path == "/" or path == "/index.html":
            return self._static("index.html")
        if path.startswith("/images/") or path in ("/favicon.ico",):
            return self._static(path.lstrip("/") if path != "/favicon.ico" else "images/icon_64.png")

        if path == "/api/health":
            return self._json({"ok": True, "ts": int(time.time())})

        if path == "/api/session":
            cfg = self.core.cfg
            return self._json({
                "authed": self._authed(),
                "needs_setup": False,
                "version": self.core.version,
                "app": "portguard",
            })

        if path == "/api/export":
            if not self._authed():
                return self._json({"error": "unauthorized"}, 401)
            fmt = (query.get("format") or ["md"])[0]
            return self._export(fmt)

        if path.startswith("/api/"):
            if not self._authed():
                return self._json({"error": "unauthorized"}, 401)
            if path == "/api/overview":
                state = self.core.get_state()
                return self._json({"overview": state["overview"],
                                   "conflicts": state["conflicts"],
                                   "ts": state["overview"]["ts"]})
            if path == "/api/ports":
                state = self.core.get_state()
                return self._json(state)
            if path == "/api/timeline":
                try:
                    limit = int((query.get("limit") or ["120"])[0])
                except (TypeError, ValueError):
                    limit = 120
                limit = max(1, min(limit, 1000))
                return self._json({"events": self.core.store.timeline(limit)})
            if path == "/api/kb":
                return self._json({"kb": self.core.kb})
            return self._json({"error": "not found"}, 404)

        return self._send(404, "not found", "text/plain; charset=utf-8")

    def _handle_post(self):
        path = self._path()
        ip = self.client_address[0] if isinstance(self.client_address, tuple) else "127.0.0.1"

        if path == "/api/login":
            if not self.core.cfg.get("password"):
                return self._json({"ok": True})
            if not self.core.sessions.throttle(ip):
                return self._json({"error": "尝试过于频繁，请稍后再试"}, 429)
            data = self._body_json()
            if pg_config.verify_password(data.get("password", ""), self.core.cfg.get("password", "")):
                token = self.core.sessions.issue()
                return self._json({"ok": True}, extra={
                    "Set-Cookie": "pg_session=%s; Path=/; HttpOnly; SameSite=Strict; Max-Age=%d"
                                  % (token, SESSION_TTL)
                })
            time.sleep(0.4)
            return self._json({"error": "口令错误"}, 401)

        if path == "/api/setup":
            # Password is configured through the install/config wizard only.
            return self._json({"error": "请在应用中心「设置」中修改口令"}, 403)

        if not self._authed():
            return self._json({"error": "unauthorized"}, 401)

        if path == "/api/logout":
            self.core.sessions.drop(self._cookies().get("pg_session", ""))
            return self._json({"ok": True}, extra={
                "Set-Cookie": "pg_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"
            })

        if path == "/api/refresh":
            self.core.refresh(force=True)
            return self._json({"ok": True})

        if path == "/api/action":
            if self.headers.get("X-Requested-With") != "portguard":
                return self._json({"ok": False, "message": "请求来源校验失败"}, 403)
            data = self._body_json()
            action = (data.get("action") or "").strip()
            if action not in ("start", "stop"):
                return self._json({"ok": False, "message": "不支持的操作"}, 400)
            if data.get("confirm") != action:
                return self._json({"ok": False, "message": "缺少确认，操作未执行"}, 400)
            try:
                port = int(data.get("port"))
            except (TypeError, ValueError):
                return self._json({"ok": False, "message": "端口参数错误"}, 400)
            proto = (data.get("proto") or "tcp").lower()
            if proto not in ("tcp", "udp"):
                return self._json({"ok": False, "message": "协议参数错误"}, 400)
            result = self.core.act(port, proto, action)
            return self._json(result, 200 if result.get("ok") else 400)

        if path == "/api/label":
            data = self._body_json()
            try:
                port = int(data.get("port"))
            except (TypeError, ValueError):
                return self._json({"error": "bad port"}, 400)
            proto = data.get("proto") or "tcp"
            if proto not in ("tcp", "udp"):
                return self._json({"error": "bad proto"}, 400)
            alias = (data.get("alias") or "").strip()[:60]
            note = (data.get("note") or "").strip()[:200]
            self.core.store.set_label(port, proto, note,
                                      bool(data.get("accepted")), alias)
            self.core.refresh(force=False)
            return self._json({"ok": True, "alias": alias})

        return self._json({"error": "not found"}, 404)

    # ------------------------------------------------------------------ export
    def _export(self, fmt):
        state = self.core.get_state()
        records = state["ports"]
        ov = state["overview"]
        if fmt == "json":
            body = json.dumps(state, ensure_ascii=False, indent=2)
            return self._send(200, body, "application/json; charset=utf-8", {
                "Content-Disposition": 'attachment; filename="portguard.json"'
            })
        if fmt == "csv":
            buf = io.StringIO()
            writer = csv.writer(buf)
            writer.writerow(["端口", "协议", "状态", "服务", "归属", "绑定", "连接(内/外)",
                             "外部流量(包)", "风险", "等级"])
            for r in records:
                writer.writerow([r["port"], r["proto"], r["state_label"], r["service"],
                                 r["app_label"], ",".join(r["addrs"]) or "-",
                                 "%d/%d" % (r["conns_in"], r["conns_out"]),
                                 r["ext_packets"], r["risk"], r["risk_level"]])
            return self._send(200, "\ufeff" + buf.getvalue(), "text/csv; charset=utf-8", {
                "Content-Disposition": 'attachment; filename="portguard.csv"'
            })
        # markdown
        lines = ["# 端口态势报告", "",
                 "- 生成时间：%s" % time.strftime("%Y-%m-%d %H:%M:%S"),
                 "- 监听端口：%d，高风险：%d，闲置：%d，异常：%d" %
                 (ov["listening"], ov["high"], ov["idle"], ov["abnormal"]), "",
                 "| 端口 | 协议 | 状态 | 服务 | 归属 | 绑定 | 连接(内/外) | 风险 |",
                 "|---|---|---|---|---|---|---|---|"]
        for r in records:
            lines.append("| %d | %s | %s | %s | %s | %s | %d/%d | %d |" % (
                r["port"], r["proto"].upper(), r["state_label"], r["service"],
                r["app_label"], ",".join(r["addrs"]) or "-",
                r["conns_in"], r["conns_out"], r["risk"]))
        body = "\n".join(lines) + "\n"
        return self._send(200, body, "text/markdown; charset=utf-8", {
            "Content-Disposition": 'attachment; filename="portguard.md"'
        })


class UnixHTTPServer(ThreadingHTTPServer):
    """HTTP over a unix socket, used by the fnOS gateway (same-origin iframe)."""

    address_family = getattr(socket, "AF_UNIX", socket.AF_INET)
    allow_reuse_address = False
    daemon_threads = True

    def server_bind(self):
        try:
            if os.path.exists(self.server_address):
                os.unlink(self.server_address)
        except OSError:
            pass
        self.socket.bind(self.server_address)
        self.server_name = "localhost"
        self.server_port = 0
        try:
            os.chmod(self.server_address, 0o666)
        except OSError:
            pass


def serve(core):
    httpd = ThreadingHTTPServer((core.cfg.get("bind", "0.0.0.0"), int(core.cfg["port"])), Handler)
    httpd.core = core
    httpd.daemon_threads = True
    return httpd


def serve_gateway(core, path):
    if not hasattr(socket, "AF_UNIX"):
        raise OSError("当前系统不支持 Unix socket")
    httpd = UnixHTTPServer(path, Handler)
    httpd.core = core
    return httpd
