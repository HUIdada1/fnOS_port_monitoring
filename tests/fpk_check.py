# -*- coding: utf-8 -*-
"""Static checks for the fpk package layout (no fnpack required).

Run: python3 tests/fpk_check.py
"""

import io
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
problems = []
notes = []


def check(cond, msg):
    if not cond:
        problems.append(msg)


def load_json(path):
    try:
        with io.open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception as exc:
        problems.append("%s 不是合法 JSON: %s" % (os.path.relpath(path, ROOT), exc))
        return None


def read_manifest(path):
    data = {}
    with io.open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            data[key.strip()] = value.strip().strip('"')
    return data


def main():
    for rel in ("manifest", "ICON.PNG", "ICON_256.PNG"):
        check(os.path.isfile(os.path.join(ROOT, rel)), "缺少文件: %s" % rel)

    for rel in ("app", "cmd", "config", "wizard"):
        check(os.path.isdir(os.path.join(ROOT, rel)), "缺少目录: %s" % rel)

    manifest = read_manifest(os.path.join(ROOT, "manifest"))
    for key in ("appname", "version", "display_name", "source", "platform",
                "desktop_uidir", "desktop_applaunchname"):
        check(bool(manifest.get(key)), "manifest 缺少必填字段: %s" % key)

    port = manifest.get("service_port", "")
    check(port.isdigit(), "manifest service_port 必须是数字")
    check(manifest.get("source") == "thirdparty", "manifest source 应为 thirdparty")

    # cmd scripts
    for name in ("main", "install_init", "install_callback", "upgrade_init",
                 "upgrade_callback", "uninstall_init", "uninstall_callback",
                 "config_init", "config_callback"):
        path = os.path.join(ROOT, "cmd", name)
        check(os.path.isfile(path), "缺少生命周期脚本: cmd/%s" % name)
        if os.path.isfile(path):
            with io.open(path, encoding="utf-8") as fh:
                head = fh.readline()
            check(head.startswith("#!"), "cmd/%s 缺少 shebang" % name)
            check(os.access(path, os.X_OK) or os.name == "nt",
                  "cmd/%s 没有可执行权限（chmod +x）" % name)

    # privilege / resource
    privilege = load_json(os.path.join(ROOT, "config", "privilege"))
    if privilege is not None:
        check(isinstance(privilege.get("defaults"), dict), "privilege 缺少 defaults")
        check(privilege.get("defaults", {}).get("run-as") in ("root", "package"),
              "privilege.run-as 取值异常")

    resource = load_json(os.path.join(ROOT, "config", "resource"))
    check(resource == {}, "原生应用的 config/resource 应为空对象 {}")

    # desktop entry
    ui = load_json(os.path.join(ROOT, "app", "ui", "config"))
    if ui is not None:
        entries = ui.get(".url", {})
        check(bool(entries), "app/ui/config 缺少 .url")
        launch = manifest.get("desktop_applaunchname")
        check(launch in entries, "desktop_applaunchname 与 ui/config 的 key 不一致")
        entry = entries.get(launch, {})
        if entry:
            check(entry.get("port") == port,
                  "ui/config 的 port 与 manifest service_port 不一致")
            icon = entry.get("icon", "")
            check("{0}" in icon, "ui/config icon 应使用 {0} 尺寸占位符")
            icon_dir = os.path.join(ROOT, "app", "ui", "images")
            for size in (64, 256):
                check(os.path.isfile(os.path.join(icon_dir, "icon_%d.png" % size)),
                      "缺少图标: app/ui/images/icon_%d.png" % size)

    # wizard json
    for name in ("install", "config"):
        data = load_json(os.path.join(ROOT, "wizard", name))
        if data is not None:
            check(isinstance(data, list) and data, "wizard/%s 应为非空数组" % name)

    # knowledge base
    kb_path = os.path.join(ROOT, "app", "kb_ports.json")
    kb = load_json(kb_path)
    if kb is not None:
        check(len(kb) >= 200, "知识库条目不足 200（当前 %d）" % len(kb))
        for key, item in list(kb.items())[:50]:
            check(key.isdigit(), "知识库 key 必须是端口号字符串: %s" % key)
            check(bool(item.get("service")), "知识库 %s 缺少 service" % key)
        notes.append("知识库条目: %d" % len(kb))

    # ui index exists
    check(os.path.isfile(os.path.join(ROOT, "app", "ui", "index.html")),
          "缺少 app/ui/index.html")

    for note in notes:
        print("[note]", note)
    if problems:
        print("\n发现 %d 个问题:" % len(problems))
        for item in problems:
            print(" -", item)
        return 1
    print("\nOK: fpk 包结构校验通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
