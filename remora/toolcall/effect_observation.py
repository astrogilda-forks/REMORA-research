# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Observe what a tool implementation reaches, in a fresh interpreter.

Slice 1 of effect contract verification
(``docs/design/effect-contract-verification-v1.md``). A signed ToolSpec says
what an implementation reaches; this module watches what it does, for bounded
calls, under Python's audit hooks (PEP 578), and reports the effects in a
normalised vocabulary. It does not compare them with a spec and gives no
verdict: that is slice 2.

How it observes
---------------
Each observation runs in a new interpreter, because an audit hook cannot be
removed. The hook is installed before the tool's module is imported, so the
``load`` phase (the import) and the ``call`` phase (each case) are recorded
apart. An effect performed at import time is an effect.

What it cannot see
------------------
An audit hook sees Python calling the standard library and nothing lower.
These are reported as ``blinding`` events, never silently dropped, and a case
that has one cannot support "no undeclared effect" later:

- ``native_code``: ``ctypes`` loading a library, or a non-standard-library
  extension module imported during the observation;
- ``observer_tampering``: the tool installing an audit hook of its own;
- ``timeout`` and ``crash``: the case did not complete.

A process the tool starts is observed as ``process.spawn``; what that child
does is outside this vantage. Reads are counted, not reported as effects:
reading is not reaching.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

__all__ = ["EFFECT_CLASSES", "BLINDING", "CaseObservation", "Observation", "observe"]

#: The normalised effect vocabulary. ``fs.write`` covers create, truncate and append.
EFFECT_CLASSES = ("fs.write", "fs.delete", "fs.rename", "fs.mkdir", "process.spawn",
                  "net.connect", "net.resolve", "env.write")
BLINDING = ("native_code", "observer_tampering", "timeout", "crash")

# The harness runs in the child. It is source, not an import, so the child
# loads nothing from REMORA before the hook is installed.
_HARNESS = r'''
import json, os, sys, sysconfig, time
spec = json.loads(sys.stdin.read())
sys.path[:0] = spec["path"]
records = []
phase = {"name": "load"}
reads = {"load": 0}
_STD = tuple(os.path.normcase(os.path.abspath(p)) for p in {
    sysconfig.get_paths()["stdlib"], sysconfig.get_paths()["platstdlib"]} if p)
_WRITE_FLAGS = os.O_WRONLY | os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_TRUNC

def _note(cls, detail, kind="effect"):
    records.append({"phase": phase["name"], "kind": kind, "class": cls, "detail": detail})

def _hook(event, args):
    try:
        if event == "open":
            path, mode, flags = (list(args) + [None, None, None])[:3]
            writes = (isinstance(mode, str) and any(c in mode for c in "wax+")) or (
                isinstance(flags, int) and flags & _WRITE_FLAGS)
            if writes:
                _note("fs.write", str(path))
            else:
                reads[phase["name"]] = reads.get(phase["name"], 0) + 1
        elif event in ("os.remove", "os.rmdir", "shutil.rmtree"):
            _note("fs.delete", str(args[0]))
        elif event in ("os.rename",):
            _note("fs.rename", f"{args[0]} -> {args[1]}")
        elif event == "os.mkdir":
            _note("fs.mkdir", str(args[0]))
        elif event in ("subprocess.Popen", "os.system", "os.exec", "os.posix_spawn",
                       "os.spawn", "os.fork", "os.forkpty", "os.startfile"):
            _note("process.spawn", str(args[0])[:200])
        elif event in ("socket.connect", "socket.sendto", "http.client.connect"):
            _note("net.connect", str(args[1] if event != "http.client.connect" else args[1:3])[:200])
        elif event == "urllib.Request":
            _note("net.connect", str(args[0])[:200])
        elif event in ("socket.getaddrinfo", "socket.gethostbyname"):
            _note("net.resolve", str(args[0])[:200])
        elif event in ("os.putenv", "os.unsetenv"):
            _note("env.write", str(args[0]))
        elif event.startswith("ctypes.dlopen"):
            _note("native_code", str(args[0])[:200], "blinding")
        elif event == "sys.addaudithook":
            _note("observer_tampering", "the tool installed an audit hook", "blinding")
        elif event == "import":
            filename = args[1] if len(args) > 1 else None
            if isinstance(filename, str) and filename.lower().endswith((".so", ".pyd", ".dylib")):
                where = os.path.normcase(os.path.abspath(filename))
                if not where.startswith(_STD):
                    _note("native_code", where, "blinding")
    except Exception as exc:  # the hook must never raise into the tool
        records.append({"phase": phase["name"], "kind": "blinding", "class": "crash",
                        "detail": f"observer error: {type(exc).__name__}"})

sys.addaudithook(_hook)
out = {"cases": [], "load": None}
try:
    import importlib
    module = importlib.import_module(spec["module"])
    fn = getattr(module, spec["function"])
    out["load"] = {"completed": True}
except BaseException as exc:
    out["load"] = {"completed": False, "error": f"{type(exc).__name__}: {exc}"[:300]}
    fn = None
out["load"]["records"] = [r for r in records if r["phase"] == "load"]
out["load"]["reads"] = reads.get("load", 0)
for index, case in enumerate(spec["cases"] if fn is not None else []):
    phase["name"] = f"call:{index}"
    reads[phase["name"]] = 0
    started = len(records)
    entry = {"index": index}
    try:
        fn(case)
        entry["completed"] = True
    except BaseException as exc:
        entry["completed"] = True
        entry["raised"] = f"{type(exc).__name__}"
    entry["records"] = records[started:]
    entry["reads"] = reads[phase["name"]]
    out["cases"].append(entry)
sys.stdout.write("\n@@OBSERVATION@@" + json.dumps(out))
sys.stdout.flush()
'''


@dataclass(frozen=True)
class CaseObservation:
    """What one phase did. ``effects`` and ``blinding`` are (class, detail) pairs."""

    phase: str
    completed: bool
    effects: tuple[tuple[str, str], ...] = ()
    blinding: tuple[tuple[str, str], ...] = ()
    reads: int = 0
    raised: str = ""

    @property
    def effect_classes(self) -> frozenset[str]:
        return frozenset(c for c, _ in self.effects)

    @property
    def blinded(self) -> bool:
        return bool(self.blinding) or not self.completed


@dataclass(frozen=True)
class Observation:
    """One observer run over one callable: the import, then each case."""

    module: str
    function: str
    vantage: str
    interpreter: str
    platform: str
    load: CaseObservation
    cases: tuple[CaseObservation, ...] = field(default_factory=tuple)

    def as_dict(self) -> dict[str, Any]:
        def one(c: CaseObservation) -> dict[str, Any]:
            return {"phase": c.phase, "completed": c.completed, "effects": [list(e) for e in c.effects],
                    "blinding": [list(b) for b in c.blinding], "reads": c.reads, "raised": c.raised}
        return {"module": self.module, "function": self.function, "vantage": self.vantage,
                "interpreter": self.interpreter, "platform": self.platform,
                "load": one(self.load), "cases": [one(c) for c in self.cases]}


def _phase(raw: Mapping[str, Any], name: str) -> CaseObservation:
    records = raw.get("records", [])
    return CaseObservation(
        phase=name, completed=bool(raw.get("completed")),
        effects=tuple((r["class"], r["detail"]) for r in records if r["kind"] == "effect"),
        blinding=tuple((r["class"], r["detail"]) for r in records if r["kind"] == "blinding"),
        reads=int(raw.get("reads", 0)), raised=str(raw.get("raised", "")))


def observe(module: str, function: str, cases: Sequence[Any], *, timeout_s: float = 30.0,
            path: Sequence[str] = (), env: Mapping[str, str] | None = None) -> Observation:
    """Import ``module`` and call ``function(case)`` for each case, under observation.

    Runs in a fresh interpreter with ``path`` prepended to ``sys.path``. A
    timeout or a crash of that interpreter is reported as blinding on the
    phases that did not report, never as a clean run.
    """
    spec = json.dumps({"module": module, "function": function, "cases": list(cases),
                       "path": [os.path.abspath(p) for p in path]})
    child_env = dict(os.environ if env is None else env)
    child_env.pop("PYTHONSTARTUP", None)
    platform = f"{sys.platform}"
    interpreter = f"{sys.implementation.name} {sys.version.split()[0]}"
    try:
        proc = subprocess.run([sys.executable, "-c", _HARNESS], input=spec, capture_output=True,
                              text=True, timeout=timeout_s, env=child_env)
    except subprocess.TimeoutExpired:
        timed_out = CaseObservation(phase="load", completed=False,
                                    blinding=(("timeout", f"no result within {timeout_s}s"),))
        return Observation(module, function, "python_audit_hook", interpreter, platform, timed_out,
                           tuple(CaseObservation(phase=f"call:{i}", completed=False,
                                                 blinding=(("timeout", "not reached"),))
                                 for i in range(len(cases))))
    marker = proc.stdout.rfind("\n@@OBSERVATION@@")
    if marker < 0:
        crashed = CaseObservation(phase="load", completed=False,
                                  blinding=(("crash", f"exit {proc.returncode}: "
                                             f"{proc.stderr.strip()[-200:]}"),))
        return Observation(module, function, "python_audit_hook", interpreter, platform, crashed,
                           tuple(CaseObservation(phase=f"call:{i}", completed=False,
                                                 blinding=(("crash", "not reached"),))
                                 for i in range(len(cases))))
    raw = json.loads(proc.stdout[marker + len("\n@@OBSERVATION@@"):])
    load = _phase(raw["load"], "load")
    observed = tuple(_phase(c, f"call:{c['index']}") for c in raw["cases"])
    if len(observed) < len(cases):
        observed += tuple(CaseObservation(phase=f"call:{i}", completed=False,
                                          blinding=(("crash", "the module did not load"),))
                          for i in range(len(observed), len(cases)))
    return Observation(module, function, "python_audit_hook", interpreter, platform, load, observed)
