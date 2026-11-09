# -*- coding: utf-8 -*-
"""SQLite persistence: snapshots, change events, labels, metrics."""

import json
import os
import sqlite3
import threading
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS snapshot (
  port INTEGER, proto TEXT, state TEXT, service TEXT, app TEXT,
  risk INTEGER, risk_level TEXT, exposure TEXT, payload TEXT,
  first_seen INTEGER, last_seen INTEGER,
  PRIMARY KEY (port, proto)
);
CREATE TABLE IF NOT EXISTS event (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER, port INTEGER, proto TEXT, kind TEXT, detail TEXT
);
CREATE INDEX IF NOT EXISTS idx_event_ts ON event(ts DESC);
CREATE TABLE IF NOT EXISTS label (
  port INTEGER, proto TEXT, note TEXT, accepted INTEGER DEFAULT 0,
  PRIMARY KEY (port, proto)
);
CREATE TABLE IF NOT EXISTS metric (
  ts INTEGER, port INTEGER, proto TEXT, conns_peak INTEGER, external_delta INTEGER
);
CREATE INDEX IF NOT EXISTS idx_metric_ts ON metric(ts DESC);
"""


class Store(object):
    def __init__(self, data_dir):
        os.makedirs(data_dir, exist_ok=True)
        self.path = os.path.join(data_dir, "portguard.db")
        self.lock = threading.Lock()
        self.db = self._open(self.path)
        with self.lock:
            self.db.executescript(SCHEMA)
            try:
                self.db.execute("PRAGMA journal_mode=WAL")
            except sqlite3.Error:
                pass
            self.db.commit()

    def _open(self, path):
        """Open the database; move a corrupt file aside instead of refusing to start."""
        try:
            db = sqlite3.connect(path, check_same_thread=False)
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA schema_version").fetchone()
            return db
        except sqlite3.DatabaseError:
            try:
                db.close()
            except Exception:
                pass
            backup = "%s.corrupt-%d" % (path, int(time.time()))
            try:
                os.replace(path, backup)
                for suffix in ("-wal", "-shm"):
                    if os.path.exists(path + suffix):
                        os.replace(path + suffix, backup + suffix)
            except OSError:
                pass
            db = sqlite3.connect(path, check_same_thread=False)
            db.row_factory = sqlite3.Row
            return db

    # ---------------------------------------------------------------- snapshot
    def previous(self):
        with self.lock:
            rows = self.db.execute("SELECT port, proto, state, risk_level FROM snapshot").fetchall()
        return {(r["port"], r["proto"]): (r["state"], r["risk_level"]) for r in rows}

    def save_snapshot(self, records, ts, write_metrics=True):
        prev = self.previous()
        with self.lock:
            first_map = {
                (r["port"], r["proto"]): r["first_seen"]
                for r in self.db.execute("SELECT port,proto,first_seen FROM snapshot").fetchall()
            }
        current = {}
        now = int(ts)
        events = []
        for rec in records:
            key = (rec["port"], rec["proto"])
            current[key] = (rec["state"], rec["risk_level"])
            first = first_map.get(key) or now

            if key not in prev:
                events.append((now, rec["port"], rec["proto"], "OPEN",
                               "%s %s 开始监听（%s）" % (rec["proto"].upper(), rec["port"],
                                                      rec.get("service", ""))))
            else:
                old_state, old_risk = prev[key]
                if old_state != rec["state"]:
                    events.append((now, rec["port"], rec["proto"], "STATE",
                                   "%s → %s" % (old_state, rec["state"])))
                if old_risk != rec["risk_level"]:
                    events.append((now, rec["port"], rec["proto"], "RISK",
                                   "风险 %s → %s" % (old_risk, rec["risk_level"])))

            payload = json.dumps(rec, ensure_ascii=False)
            with self.lock:
                self.db.execute(
                    "INSERT INTO snapshot(port,proto,state,service,app,risk,risk_level,"
                    "exposure,payload,first_seen,last_seen) VALUES(?,?,?,?,?,?,?,?,?,?,?) "
                    "ON CONFLICT(port,proto) DO UPDATE SET state=excluded.state,"
                    "service=excluded.service,app=excluded.app,risk=excluded.risk,"
                    "risk_level=excluded.risk_level,exposure=excluded.exposure,"
                    "payload=excluded.payload,last_seen=excluded.last_seen",
                    (rec["port"], rec["proto"], rec["state"], rec.get("service", ""),
                     rec.get("app", ""), rec["risk"], rec["risk_level"],
                     rec.get("exposure", ""), payload, first, now),
                )

        for key in prev:
            if key not in current:
                events.append((now, key[0], key[1], "CLOSE", "端口不再监听"))

        if events:
            with self.lock:
                self.db.executemany(
                    "INSERT INTO event(ts,port,proto,kind,detail) VALUES(?,?,?,?,?)",
                    events,
                )
                for key in prev:
                    if key not in current:
                        self.db.execute("DELETE FROM snapshot WHERE port=? AND proto=?", key)
                self.db.commit()
        else:
            with self.lock:
                self.db.commit()

        if write_metrics:
            with self.lock:
                self.db.executemany(
                    "INSERT INTO metric(ts,port,proto,conns_peak,external_delta) VALUES(?,?,?,?,?)",
                    [(now, r["port"], r["proto"], r.get("conns_in", 0) + r.get("conns_out", 0),
                      r.get("ext_packets", 0)) for r in records],
                )
                self.db.commit()
        return events

    def add_event(self, port, proto, kind, detail, ts=None):
        with self.lock:
            self.db.execute(
                "INSERT INTO event(ts,port,proto,kind,detail) VALUES(?,?,?,?,?)",
                (int(ts or time.time()), int(port), proto, kind, detail),
            )
            self.db.commit()

    def timeline(self, limit=120):
        with self.lock:
            rows = self.db.execute(
                "SELECT ts,port,proto,kind,detail FROM event ORDER BY id DESC LIMIT ?",
                (int(limit),),
            ).fetchall()
        return [dict(r) for r in rows]

    # ---------------------------------------------------------------- labels
    def labels(self):
        with self.lock:
            rows = self.db.execute("SELECT port,proto,note,accepted FROM label").fetchall()
        return {(r["port"], r["proto"]): {"note": r["note"] or "",
                                          "accepted": bool(r["accepted"])} for r in rows}

    def set_label(self, port, proto, note="", accepted=False):
        with self.lock:
            self.db.execute(
                "INSERT INTO label(port,proto,note,accepted) VALUES(?,?,?,?) "
                "ON CONFLICT(port,proto) DO UPDATE SET note=excluded.note,"
                "accepted=excluded.accepted",
                (int(port), proto, note or "", 1 if accepted else 0),
            )
            self.db.commit()

    def prune(self, retention_days=90, metric_days=7):
        event_cutoff = int(time.time()) - int(retention_days) * 86400
        metric_cutoff = int(time.time()) - int(metric_days) * 86400
        with self.lock:
            self.db.execute("DELETE FROM event WHERE ts < ?", (event_cutoff,))
            self.db.execute("DELETE FROM metric WHERE ts < ?", (metric_cutoff,))
            self.db.commit()
