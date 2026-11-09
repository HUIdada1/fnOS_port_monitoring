# -*- coding: utf-8 -*-
"""Smoke tests: address parsing, state machine, conflicts, HTTP auth.

Run:  python3 tests/smoke.py
Works on any OS; all kernel data is synthetic.
"""

import http.cookiejar
import json
import os
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP = os.path.join(ROOT, "app")
sys.path.insert(0, APP)

import pg_action          # noqa: E402
import pg_analyze          # noqa: E402
import pg_apps             # noqa: E402
import pg_collect          # noqa: E402
import pg_config           # noqa: E402
import pg_server           # noqa: E402
import pg_store            # noqa: E402


class TestAddr(unittest.TestCase):
    def test_ipv4(self):
        self.assertEqual(pg_collect._hex_to_ip("0100007F"), "127.0.0.1")
        self.assertEqual(pg_collect._hex_to_ip("00000000"), "0.0.0.0")
        self.assertEqual(pg_collect._hex_to_ip("0D1F1FAC"), "172.31.31.13")

    def test_ipv6(self):
        self.assertEqual(pg_collect._hex_to_ip("0" * 32), "::")
        self.assertEqual(
            pg_collect._hex_to_ip("00000000000000000000000001000000"), "::1")

    def test_classify(self):
        self.assertEqual(pg_collect.classify_addr("127.0.0.1"), "loopback")
        self.assertEqual(pg_collect.classify_addr("0.0.0.0"), "any")
        self.assertEqual(pg_collect.classify_addr("::"), "any")
        self.assertEqual(pg_collect.classify_addr("192.168.1.2"), "private")
        self.assertEqual(pg_collect.classify_addr("172.20.0.3"), "private")
        self.assertEqual(pg_collect.classify_addr("172.32.0.3"), "public")
        self.assertEqual(pg_collect.classify_addr("240e:345::1"), "public")

    def test_exposure(self):
        self.assertEqual(pg_collect.exposure_of(["127.0.0.1"], True)["score"], 0)
        self.assertEqual(pg_collect.exposure_of(["0.0.0.0", "::"], True)["level"], "public_v6")
        self.assertEqual(pg_collect.exposure_of(["0.0.0.0"], False)["score"], 32)
        self.assertEqual(pg_collect.exposure_of(["192.168.1.5"], False)["score"], 20)

    def test_password(self):
        hashed = pg_config.hash_password("s3cret-pass")
        self.assertTrue(pg_config.verify_password("s3cret-pass", hashed))
        self.assertFalse(pg_config.verify_password("wrong", hashed))
        self.assertFalse(pg_config.verify_password("s3cret-pass", ""))


def sock(port, proto, ip, inode, pid=0, comm="", exe="", cgroup="", unit="",
         container="", uptime=99999):
    return {"port": port, "proto": proto, "ip": ip, "inode": inode, "pid": pid,
            "comm": comm, "exe": exe, "cmdline": exe, "cgroup": cgroup,
            "unit": unit, "container": container, "uptime": uptime, "uid": 0}


class TestAnalyze(unittest.TestCase):
    def setUp(self):
        self.snap = {
            "ts": int(time.time()), "elapsed_ms": 12, "pid_count": 10,
            "has_global_v6": False, "uptime": 1000,
            "sockets": [
                sock(3306, "tcp", "0.0.0.0", 1, 100, "docker-proxy",
                     "/usr/bin/docker-proxy", "system.slice/docker-abc.scope",
                     container="abc"),
                sock(3306, "tcp", "::", 2, 100, "docker-proxy",
                     "/usr/bin/docker-proxy", "system.slice/docker-abc.scope",
                     container="abc"),
                sock(5432, "tcp", "127.0.0.1", 3, 200, "postgres",
                     "/usr/lib/postgresql/15/bin/postgres",
                     "system.slice/postgresql@15-main.service",
                     "postgresql@15-main"),
                sock(2049, "tcp", "0.0.0.0", 4),
                sock(41750, "tcp", "0.0.0.0", 5),
                sock(5353, "udp", "0.0.0.0", 6, 300, "avahi-daemon", "/usr/sbin/avahi-daemon"),
                sock(5353, "udp", "0.0.0.0", 7, 301, "trim-media", "/usr/local/apps/@appcenter/trim.media/trim-media"),
                sock(30019, "tcp", "0.0.0.0", 8, 400, "nginx", "/usr/sbin/nginx",
                     "system.slice/trim_nginx.service", "trim_nginx"),
                sock(30019, "udp", "0.0.0.0", 9, 401, "pxy", "/usr/bin/pxy",
                     "system.slice/trim_connect.service", "trim_connect"),
            ],
        }
        self.meta = {
            "apps": {"trim.media": {"appname": "trim.media", "display_name": "影视"},
                     "portguard_dummy": {"appname": "portguard_dummy",
                                         "display_name": "Dummy", "service_port": "18110"}},
            "docker": {"by_id": {"abc": {"id": "abc", "name": "mysql",
                                          "image": "mysql:latest", "ips": ["172.17.0.3"]}},
                       "by_ip": {"172.17.0.3": {"id": "abc", "name": "mysql",
                                                 "image": "mysql:latest", "ips": ["172.17.0.3"]}},
                       "by_name": {}},
            "fw": {8000},
        }
        self.dnat = {"tool": "nft", "error": "", "rules": [
            {"proto": "tcp", "host_port": 3306, "packets": 120, "bytes": 900,
             "dest_ip": "172.17.0.3", "dest_port": 3306, "duplicate": False},
            {"proto": "tcp", "host_port": 9999, "packets": 0, "bytes": 0,
             "dest_ip": "172.17.0.9", "dest_port": 80, "duplicate": False},
        ]}

    def build(self):
        usage = pg_analyze.Usage(window=300)
        usage.update(self.snap["ts"], {
            (3306, "tcp"): {"in": 0, "out": 6},
            (5432, "tcp"): {"in": 0, "out": 0},
        }, self.dnat["rules"])
        return pg_analyze.analyze(self.snap, usage, self.meta, self.dnat)

    def test_states(self):
        records, overview, conflicts = self.build()
        by = {(r["port"], r["proto"]): r for r in records}
        self.assertEqual(by[(3306, "tcp")]["state"], "ACTIVE")
        self.assertEqual(by[(3306, "tcp")]["app"], "mysql")
        self.assertEqual(by[(3306, "tcp")]["risk_level"], "high")
        self.assertEqual(by[(5432, "tcp")]["state"], "IDLE")
        self.assertEqual(by[(2049, "tcp")]["state"], "KERNEL")
        self.assertEqual(by[(41750, "tcp")]["state"], "ORPHAN")
        self.assertEqual(by[(8000, "tcp")]["state"], "GHOST_SOFT")
        self.assertEqual(by[(9999, "tcp")]["state"], "GHOST")

    def test_conflicts(self):
        records, _, _ = self.build()
        by = {(r["port"], r["proto"]): r for r in records}
        codes = lambda rec: {c["code"] for c in rec["conflicts"]}
        self.assertIn("SHARED", codes(by[(5353, "udp")]))
        self.assertIn("DUAL_PROTO", codes(by[(30019, "tcp")]))
        self.assertIn("DUAL_PROTO", codes(by[(30019, "udp")]))

    def test_owner_path(self):
        records, _, _ = self.build()
        by = {(r["port"], r["proto"]): r for r in records}
        # 5353 的持有者是 /usr/local/apps/@appcenter/trim.media/... → 应用路径归因
        self.assertEqual(by[(5353, "udp")]["app"], "影视")
        self.assertEqual(by[(5353, "udp")]["app_kind"], "fnos")
        # 30019 UDP 的 pxy 属于 trim_connect.service → systemd 归因
        self.assertEqual(by[(30019, "udp")]["app"], "fnOS 连接服务")
        self.assertEqual(by[(30019, "udp")]["app_kind"], "system")

    def test_overview(self):
        _, ov, conflicts = self.build()
        self.assertGreaterEqual(ov["total"], 8)
        self.assertGreaterEqual(ov["high"], 1)
        self.assertGreaterEqual(ov["abnormal"], 2)
        self.assertTrue(any(c["code"] == "SHARED" for c in conflicts))


class TestContainerParsers(unittest.TestCase):
    def test_ss(self):
        text = ('tcp   LISTEN 0 4096 *:3306 *:*    users:(("mysqld",pid=1,fd=28))\n'
                'udp   UNCONN 0 0     *:5353 *:*    users:(("avahi-daemon",pid=9,fd=12))\n')
        ports, procs = pg_apps._parse_ss(text)
        self.assertEqual(ports, {3306, 5353})
        self.assertEqual(procs[3306], "mysqld")

    def test_procnet(self):
        text = ("  sl  local_address rem_address   st ...\n"
                "   5: 00000000:A316 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 10519\n")
        self.assertEqual(pg_apps._parse_procnet(text), {41750})


class TestControl(unittest.TestCase):
    def rec(self, **kw):
        base = {"port": 3306, "proto": "tcp", "state": "ACTIVE",
                "app_kind": "docker", "container": "mysql",
                "unit": "", "app_raw": "", "conflicts": [], "pids": [1]}
        base.update(kw)
        return base

    def test_docker_allowed(self):
        ctl = pg_action.build_control(self.rec())
        self.assertTrue(ctl["allowed"])
        self.assertEqual(ctl["target"], "mysql")

    def test_protected_ports(self):
        for port in (22, 80, 443, 30018, 30019, 18110):
            ctl = pg_action.build_control(self.rec(port=port))
            self.assertFalse(ctl["allowed"], port)

    def test_protected_units(self):
        ctl = pg_action.build_control(self.rec(
            port=8005, app_kind="system", unit="trim_nginx"))
        self.assertFalse(ctl["allowed"])

    def test_self_app(self):
        ctl = pg_action.build_control(self.rec(
            port=18111, app_kind="fnos", app_raw="portguard"))
        self.assertFalse(ctl["allowed"])

    def test_shared_denied(self):
        ctl = pg_action.build_control(self.rec(
            conflicts=[{"code": "SHARED", "level": "info", "detail": ""}]))
        self.assertFalse(ctl["allowed"])

    def test_ghost_denied(self):
        ctl = pg_action.build_control(self.rec(state="GHOST_SOFT"))
        self.assertFalse(ctl["allowed"])

    def test_unknown_denied(self):
        ctl = pg_action.build_control(self.rec(app_kind="unknown", container=""))
        self.assertFalse(ctl["allowed"])

    def test_disabled(self):
        ctl = pg_action.build_control(self.rec(), enabled=False)
        self.assertFalse(ctl["allowed"])

    def test_execute_refuses_denied(self):
        out = pg_action.execute(self.rec(port=22), "stop")
        self.assertFalse(out["ok"])


class TestStore(unittest.TestCase):
    def test_alias_roundtrip(self):
        tmp = tempfile.mkdtemp(prefix="pgstore-")
        store = pg_store.Store(tmp)
        store.set_label(8080, "tcp", "自己写的服务", False, "我的博客 API")
        got = store.labels()[(8080, "tcp")]
        self.assertEqual(got["alias"], "我的博客 API")
        self.assertEqual(got["note"], "自己写的服务")
        # reopening keeps the value (persisted, not cached in memory)
        again = pg_store.Store(tmp)
        self.assertEqual(again.labels()[(8080, "tcp")]["alias"], "我的博客 API")
        again.set_label(8080, "tcp", "", False, "")
        self.assertEqual(again.labels()[(8080, "tcp")]["alias"], "")


class FakeCore(object):
    def __init__(self, data_dir):
        self.app_dir = APP
        self.version = "test"
        self.started = time.time()
        self.cfg = dict(pg_config.DEFAULTS)
        self.cfg.update({"port": 0, "bind": "127.0.0.1", "password": ""})
        self.sessions = pg_server.Sessions()
        self.store = pg_store.Store(data_dir)
        self.kb = {}
        self._state = {"overview": {"total": 0, "ts": int(time.time())},
                       "ports": [], "conflicts": [], "labels": {}}

    def get_state(self):
        return self._state

    def refresh(self, force=False):
        pass

    def act(self, port, proto, action):
        return {"ok": False, "message": "test stub"}

    def set_password(self, password):
        self.cfg["password"] = pg_config.hash_password(password)


class TestServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="pgtest-")
        cls.core = FakeCore(cls.tmp)
        cls.httpd = pg_server.serve(cls.core)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    def setUp(self):
        # each test starts from a clean auth state
        self.core.cfg["password"] = ""
        self.core.sessions = pg_server.Sessions()
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar))

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def call(self, path, payload=None, headers=None):
        url = "http://127.0.0.1:%d%s" % (self.port, path)
        data = None
        hdrs = dict(headers or {})
        if payload is not None:
            data = json.dumps(payload).encode()
            hdrs["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, headers=hdrs)
        try:
            with self.opener.open(req, timeout=5) as resp:
                return resp.status, json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            body = exc.read().decode()
            try:
                return exc.code, json.loads(body)
            except ValueError:
                return exc.code, {"raw": body}

    def test_flow(self):
        # no password configured -> open access
        status, data = self.call("/api/session")
        self.assertEqual(status, 200)
        self.assertTrue(data["authed"])
        self.assertFalse(data["needs_setup"])

        status, data = self.call("/api/ports")
        self.assertEqual(status, 200)
        self.assertIn("ports", data)

        # setup endpoint is closed: password comes from the install wizard
        status, data = self.call("/api/setup", {"password": "good-pass-123"})
        self.assertEqual(status, 403)

        # enabling a password requires auth again
        self.core.set_password("good-pass-123")
        self.core.sessions = pg_server.Sessions()
        self.jar.clear()
        status, data = self.call("/api/ports")
        self.assertEqual(status, 401)

        status, data = self.call("/api/login", {"password": "wrong"})
        self.assertEqual(status, 401)
        status, data = self.call("/api/login", {"password": "good-pass-123"})
        self.assertEqual(status, 200)
        status, data = self.call("/api/ports")
        self.assertEqual(status, 200)

        status, data = self.call("/api/health")
        self.assertEqual(status, 200)
        self.assertTrue(data["ok"])

    def test_action_guards(self):
        payload = {"port": 3306, "proto": "tcp", "action": "stop", "confirm": "stop"}
        status, data = self.call("/api/action", payload)
        self.assertEqual(status, 403)  # missing X-Requested-With

        status, data = self.call("/api/action", {"port": 3306, "proto": "tcp",
                                                 "action": "stop", "confirm": "yes"},
                                 {"X-Requested-With": "portguard"})
        self.assertEqual(status, 400)
        self.assertIn("确认", data.get("message", ""))

        status, data = self.call("/api/action", {"port": 3306, "proto": "tcp",
                                                 "action": "drop", "confirm": "drop"},
                                 {"X-Requested-With": "portguard"})
        self.assertEqual(status, 400)

        status, data = self.call("/api/action", payload, {"X-Requested-With": "portguard"})
        self.assertEqual(status, 400)
        self.assertFalse(data["ok"])

    def test_gateway_prefix(self):
        # the fnOS gateway proxies /app/portguard/* to the same handler
        status, data = self.call("/app/portguard/api/session")
        self.assertEqual(status, 200)
        self.assertTrue(data["authed"])
        status, data = self.call("/app/portguard/api/ports")
        self.assertEqual(status, 200)
        self.assertIn("ports", data)


if __name__ == "__main__":
    unittest.main(verbosity=2)
