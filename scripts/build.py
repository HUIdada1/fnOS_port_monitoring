#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Clean and build portguard.fpk.

Usage:
    python3 scripts/build.py [--fnpack /path/to/fnpack]

fnpack lookup order: --fnpack, $FNPACK_BIN, ./fnpack[.exe], ./tools/fnpack[.exe], PATH.
"""

import argparse
import os
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def find_fnpack(explicit=None):
    candidates = []
    if explicit:
        candidates.append(explicit)
    env = os.environ.get("FNPACK_BIN")
    if env:
        candidates.append(env)
    for name in ("fnpack", "fnpack.exe"):
        candidates.append(os.path.join(ROOT, name))
        candidates.append(os.path.join(ROOT, "tools", name))
    for name in ("fnpack", "fnpack.exe"):
        found = shutil.which(name)
        if found:
            candidates.append(found)
    for path in candidates:
        if path and os.path.isfile(path):
            return path
    return None


def clean():
    removed = 0
    for base, dirs, files in os.walk(ROOT):
        if ".git" in dirs:
            dirs.remove(".git")
        for name in list(dirs):
            if name == "__pycache__":
                shutil.rmtree(os.path.join(base, name), ignore_errors=True)
                dirs.remove(name)
                removed += 1
        for name in files:
            if name.endswith((".pyc", ".pyo")):
                try:
                    os.remove(os.path.join(base, name))
                    removed += 1
                except OSError:
                    pass
    return removed


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--fnpack", default=None)
    args = parser.parse_args()

    fnpack = find_fnpack(args.fnpack)
    if not fnpack:
        print("找不到 fnpack。下载对应平台版本后放到 tools/ 或设置 FNPACK_BIN。")
        print("官方下载：https://static2.fnnas.com/fnpack/fnpack-1.2.3-{os}-{arch}")
        return 2

    removed = clean()
    if removed:
        print("清理缓存文件 %d 个" % removed)

    output = os.path.join(ROOT, "portguard.fpk")
    if os.path.exists(output):
        os.remove(output)

    print("使用 %s" % fnpack)
    proc = subprocess.run([fnpack, "build", "-d", "."], cwd=ROOT)
    if proc.returncode != 0:
        print("构建失败，退出码 %d" % proc.returncode)
        return proc.returncode

    if not os.path.isfile(output):
        print("构建结束但未找到 portguard.fpk")
        return 1

    print("完成：%s（%.1f KB）" % (output, os.path.getsize(output) / 1024.0))
    return 0


if __name__ == "__main__":
    sys.exit(main())
