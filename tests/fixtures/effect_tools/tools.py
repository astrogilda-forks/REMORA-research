# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Fixture tool implementations, one per effect class the observer reports.

Each takes the case's arguments, as a registered tool would. Paths come from
the case so the tests own every file they cause.
"""
from __future__ import annotations

import os
import socket
import subprocess
import sys


def clean_read(args):
    with open(args["path"], encoding="utf-8") as fh:
        return fh.read()


def writes_temp_file(args):
    with open(os.path.join(args["dir"], "scratch.txt"), "w", encoding="utf-8") as fh:
        fh.write("x")


def writes_only_for_one_value(args):
    if args.get("mode") == "write":
        writes_temp_file(args)


def deletes_and_renames(args):
    a = os.path.join(args["dir"], "a")
    with open(a, "w", encoding="utf-8"):
        pass
    os.rename(a, a + ".b")
    os.remove(a + ".b")
    os.mkdir(os.path.join(args["dir"], "sub"))


def spawns_process(args):
    subprocess.run([sys.executable, "-c", "pass"], check=True)


def connects_socket(args):
    s = socket.socket()
    try:
        s.settimeout(0.5)
        s.connect(("127.0.0.1", args["port"]))
    except OSError:
        # The port is closed on purpose: the attempt is the effect under test.
        pass
    finally:
        s.close()


def resolves_name(args):
    try:
        socket.getaddrinfo("localhost", 80)
    except OSError:
        # A host without a resolver still made the lookup the observer reports.
        pass


def writes_environment(args):
    os.environ["REMORA_EFFECT_FIXTURE"] = "1"


def uses_ctypes(args):
    import ctypes
    import ctypes.util

    name = "kernel32" if os.name == "nt" else ctypes.util.find_library("c")
    if os.name == "nt":
        ctypes.WinDLL(name)
    else:
        ctypes.CDLL(name)


def installs_audit_hook(args):
    sys.addaudithook(lambda *a: None)


def raises(args):
    raise RuntimeError("tool failed")


def sleeps(args):
    import time

    time.sleep(args["seconds"])
