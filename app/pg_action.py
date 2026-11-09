# -*- coding: utf-8 -*-
"""Port control: stop/start the owning unit behind a listening port.

Only three target types are allowed: docker container, fnOS app, systemd unit.
Everything else is refused. Protected targets (panel, ssh, gateway, self) can
never be controlled from here.
"""

import re
import subprocess

# Ports that must stay reachable even if a user asks to close them.
PROTECTED_PORTS = {
    22: "SSH 管理端口",
    80: "飞牛管理面板",
    443: "飞牛管理面板",
    30018: "飞牛应用网关",
    30019: "飞牛应用网关",
    18110: "PortGuard 自身",
}

PROTECTED_UNITS = {
    "ssh", "sshd", "trim_nginx", "trim_app_center", "trim_connect",
    "docker", "containerd", "NetworkManager", "dbus-broker", "rsyslog",
}

PROTECTED_APPS = {"portguard"}

_SAFE_NAME = re.compile(r"^[A-Za-z0-9_.@:-]{1,128}$")


def _denied(reason, kind="none", target="", label=""):
    return {"allowed": False, "reason": reason, "kind": kind,
            "target": target, "label": label}


def build_control(rec, enabled=True):
    """Describe whether this port can be controlled and by what."""
    if not enabled:
        return _denied("已在配置中关闭端口控制功能")

    port = rec.get("port")
    if port in PROTECTED_PORTS:
        return _denied("%s 属于受保护端口（%s），不提供控制" % (port, PROTECTED_PORTS[port]))

    if rec.get("state") in ("GHOST", "GHOST_SOFT"):
        return _denied("该端口没有监听，没有可停止的对象")

    for item in rec.get("conflicts") or []:
        if item.get("code") == "SHARED":
            return _denied("端口被多个进程共享，停止其中一个会影响其他服务")

    kind = rec.get("app_kind")
    if kind == "docker":
        name = rec.get("container") or ""
        if not name:
            return _denied("识别到容器端口，但没能确定容器名")
        if not _SAFE_NAME.match(name):
            return _denied("容器名包含不支持的字符")
        return {"allowed": True, "reason": "", "kind": "docker",
                "target": name, "label": "容器 %s" % name}

    if kind == "fnos":
        app = rec.get("app_raw") or ""
        label = rec.get("app") or app
        if not app:
            return _denied("识别到飞牛应用，但没能确定应用名")
        if app in PROTECTED_APPS:
            return _denied("不能从自身界面停止 PortGuard")
        if not _SAFE_NAME.match(app):
            return _denied("应用名包含不支持的字符")
        return {"allowed": True, "reason": "", "kind": "fnos",
                "target": app, "label": "飞牛应用 %s" % label}

    if kind == "system":
        unit = rec.get("unit") or ""
        if not unit:
            return _denied("识别到系统服务，但没能确定 unit 名")
        if unit in PROTECTED_UNITS or unit.startswith("systemd-"):
            return _denied("系统关键服务（%s）不提供控制" % unit)
        if not _SAFE_NAME.match(unit):
            return _denied("unit 名包含不支持的字符")
        return {"allowed": True, "reason": "", "kind": "system",
                "target": unit, "label": "系统服务 %s" % unit}

    return _denied("未识别到可控制的服务/容器，出于安全考虑不提供停止操作")


def _run(cmd, timeout):
    try:
        proc = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=timeout, check=False,
        )
        out = proc.stdout.decode("utf-8", "replace").strip()
        return proc.returncode, out
    except FileNotFoundError:
        return 127, "命令不存在：%s" % cmd[0]
    except subprocess.TimeoutExpired:
        return 124, "执行超时（%ds）：%s" % (timeout, " ".join(cmd))
    except OSError as exc:
        return 126, "无法执行：%s" % exc


def execute(rec, action, enabled=True):
    """Run the stop/start command for a port. Returns a result dict."""
    if action not in ("stop", "start"):
        return {"ok": False, "message": "不支持的操作"}

    control = rec.get("control") or build_control(rec, enabled)
    if not control.get("allowed"):
        return {"ok": False, "message": control.get("reason") or "不允许控制"}

    kind = control["kind"]
    target = control["target"]
    if kind == "docker":
        cmd = ["docker", action, target]
        timeout = 90
    elif kind == "fnos":
        cmd = ["appcenter-cli", action, target]
        timeout = 90
    else:
        cmd = ["systemctl", action, target]
        timeout = 60

    code, output = _run(cmd, timeout)
    verb = "停止" if action == "stop" else "启动"
    tail = output[-800:] if output else ""
    if code != 0:
        return {"ok": False, "message": "%s %s 失败（退出码 %d）" % (verb, control["label"], code),
                "output": tail}
    return {"ok": True, "message": "%s %s 成功" % (verb, control["label"]),
            "output": tail}
