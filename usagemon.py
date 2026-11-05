#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""mac-usage-monitor: a low-overhead CPU/GPU usage logger for macOS, plus reports.

  usagemon.py run                 run the sampler in the foreground (launchd runs this)
  usagemon.py install             install and start the launchd user agent
  usagemon.py uninstall           stop and remove the launchd agent (keeps the database)
  usagemon.py status              agent state, database size, sampler's own cost
  usagemon.py report [options]    top apps, hourly, docker, GPU, spikes (see --help)

See README.md for how sampling and attribution work.
"""
from __future__ import annotations

import argparse
import csv
import ctypes
import ctypes.util
import datetime as dt
import http.client
import json
import os
import plistlib
import re
import resource
import signal
import socket
import sqlite3
import statistics
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path

# ---------------------------------------------------------------- settings

DATA_DIR = Path.home() / "Library/Application Support/mac-usage-monitor"
DB_PATH = Path(os.environ.get("USAGEMON_DB", DATA_DIR / "usage.db"))
LOG_PATH = Path.home() / "Library/Logs/mac-usage-monitor.log"
LABEL = "local.mac-usage-monitor"
PLIST_PATH = Path.home() / f"Library/LaunchAgents/{LABEL}.plist"

FAST_INTERVAL = 10.0       # s: libproc poll of your own processes (catches short-lived ones)
SAMPLE_INTERVAL = 15.0     # s: GPU (IOKit), machine CPU, one DB write
PS_INTERVAL = 30.0         # s: other users' processes via ps (mostly long-lived daemons)
DOCKER_INTERVAL = 60.0     # s: per-container CPU from the Docker socket
MEM_INTERVAL = 60.0        # s: footprint snapshot of every app (system memory is read every sample)
RAW_DAYS = 30              # raw rows kept this long; hourly rollups kept ROLLUP_DAYS
ROLLUP_DAYS = 400
PROC_MIN_CPU = 0.10        # cpu-s per sample for a per-process row (~0.7% of a core)
APP_MIN_CPU = 0.05         # cpu-s per sample for a per-app row; the rest go into "(other)"
BUDGET_PCT = 0.5           # the sampler's own CPU budget, % of one core (rolling average)
BUDGET_WINDOW = 20         # samples in the rolling average
MAX_SCALE = 4.0            # intervals stretch at most this much when over budget

INTERPRETERS = {"node", "bun", "deno", "python", "python3", "ruby", "java", "perl",
                "sh", "bash", "zsh", "fish", "uv", "npx", "npm", "pnpm", "yarn", "tsx"}

# ---------------------------------------------------------------- libproc / mach via ctypes

libc = ctypes.CDLL(None, use_errno=True)
libproc = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)


class _Timebase(ctypes.Structure):
    _fields_ = [("numer", ctypes.c_uint32), ("denom", ctypes.c_uint32)]


_tb = _Timebase()
libc.mach_timebase_info(ctypes.byref(_tb))
MACH_TO_S = _tb.numer / _tb.denom / 1e9   # mach absolute time units -> seconds


class BSDInfo(ctypes.Structure):  # struct proc_bsdinfo (PROC_PIDTBSDINFO = 3)
    _fields_ = [("flags", ctypes.c_uint32), ("status", ctypes.c_uint32), ("xstatus", ctypes.c_uint32),
                ("pid", ctypes.c_uint32), ("ppid", ctypes.c_uint32),
                ("uid", ctypes.c_uint32), ("gid", ctypes.c_uint32), ("ruid", ctypes.c_uint32),
                ("rgid", ctypes.c_uint32), ("svuid", ctypes.c_uint32), ("svgid", ctypes.c_uint32),
                ("rfu", ctypes.c_uint32), ("comm", ctypes.c_char * 16), ("name", ctypes.c_char * 32),
                ("nfiles", ctypes.c_uint32), ("pgid", ctypes.c_uint32), ("pjobc", ctypes.c_uint32),
                ("tdev", ctypes.c_uint32), ("tpgid", ctypes.c_uint32), ("nice", ctypes.c_int32),
                ("start_s", ctypes.c_uint64), ("start_us", ctypes.c_uint64)]


class RusageV2(ctypes.Structure):  # struct rusage_info_v2 (RUSAGE_INFO_V2 = 2)
    _fields_ = [("uuid", ctypes.c_uint8 * 16), ("user", ctypes.c_uint64), ("system", ctypes.c_uint64),
                ("pkg_idle_wkups", ctypes.c_uint64), ("interrupt_wkups", ctypes.c_uint64),
                ("pageins", ctypes.c_uint64), ("wired", ctypes.c_uint64), ("resident", ctypes.c_uint64),
                ("footprint", ctypes.c_uint64), ("start_abstime", ctypes.c_uint64),
                ("exit_abstime", ctypes.c_uint64), ("child_user", ctypes.c_uint64),
                ("child_system", ctypes.c_uint64), ("child_pkg_idle", ctypes.c_uint64),
                ("child_intr", ctypes.c_uint64), ("child_pageins", ctypes.c_uint64),
                ("child_elapsed", ctypes.c_uint64), ("disk_read", ctypes.c_uint64),
                ("disk_written", ctypes.c_uint64)]


class ShortBSD(ctypes.Structure):  # struct proc_bsdshortinfo (PROC_PIDT_SHORTBSDINFO = 13), any user
    _fields_ = [("pid", ctypes.c_uint32), ("ppid", ctypes.c_uint32), ("pgid", ctypes.c_uint32),
                ("status", ctypes.c_uint32), ("comm", ctypes.c_char * 16), ("flags", ctypes.c_uint32),
                ("uid", ctypes.c_uint32), ("gid", ctypes.c_uint32), ("ruid", ctypes.c_uint32),
                ("rgid", ctypes.c_uint32), ("svuid", ctypes.c_uint32), ("svgid", ctypes.c_uint32),
                ("rfu", ctypes.c_uint32)]


libc.proc_pid_rusage.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
libproc.proc_pidinfo.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int]
libproc.proc_pidpath.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
libproc.proc_listallpids.argtypes = [ctypes.c_void_p, ctypes.c_int]
libc.sysctl.argtypes = [ctypes.POINTER(ctypes.c_int), ctypes.c_uint, ctypes.c_void_p,
                        ctypes.POINTER(ctypes.c_size_t), ctypes.c_void_p, ctypes.c_size_t]
libc.mach_host_self.restype = ctypes.c_uint32
libc.host_statistics.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]

_pidbuf = (ctypes.c_int * 8192)()
_pathbuf = ctypes.create_string_buffer(4096)
_ru = RusageV2()
_ru_ref = ctypes.byref(_ru)
_bsd = BSDInfo()
_sbsd = ShortBSD()
_HOST = libc.mach_host_self()
CLK_TCK = os.sysconf("SC_CLK_TCK")
NCPU = os.cpu_count() or 1
libc.mach_absolute_time.restype = ctypes.c_uint64
mach_abs = libc.mach_absolute_time


def list_pids() -> list[int]:
    n = libproc.proc_listallpids(_pidbuf, ctypes.sizeof(_pidbuf))
    return [p for p in _pidbuf[:max(n, 0)] if p > 0]


def rusage(pid: int):
    """(cpu_s, child_cpu_s, rss_bytes, start_abstime) or None if not permitted."""
    if libc.proc_pid_rusage(pid, 2, ctypes.byref(_ru)) != 0:
        return None
    r = _ru
    return ((r.user + r.system) * MACH_TO_S, (r.child_user + r.child_system) * MACH_TO_S,
            r.resident, r.start_abstime)


def bsdinfo(pid: int):
    if libproc.proc_pidinfo(pid, 3, 0, ctypes.byref(_bsd), ctypes.sizeof(_bsd)) <= 0:
        return None
    return _bsd.ppid, _bsd.comm.decode(errors="replace")


def shortinfo(pid: int):
    """(ppid, uid, comm) for any process, or None."""
    if libproc.proc_pidinfo(pid, 13, 0, ctypes.byref(_sbsd), ctypes.sizeof(_sbsd)) <= 0:
        return None
    return _sbsd.ppid, _sbsd.uid, _sbsd.comm.decode(errors="replace")


def pidpath(pid: int) -> str:
    n = libproc.proc_pidpath(pid, _pathbuf, 4096)
    return _pathbuf.value.decode(errors="replace") if n > 0 else ""


def procargs(pid: int) -> list[str]:
    """argv via sysctl KERN_PROCARGS2 (own processes only)."""
    mib = (ctypes.c_int * 3)(1, 49, pid)
    size = ctypes.c_size_t(65536)
    buf = ctypes.create_string_buffer(size.value)
    if libc.sysctl(mib, 3, buf, ctypes.byref(size), None, 0) != 0:
        return []
    raw = buf.raw[:size.value]
    argc = int.from_bytes(raw[:4], "little")
    parts = raw[4:].split(b"\0")
    parts = [p for p in parts[1:] if p]  # skip exec path, then padding
    return [p.decode(errors="replace") for p in parts[:argc]]


def host_cpu_ticks() -> int:
    """Busy CPU ticks (user+system+nice) summed over all cores."""
    arr = (ctypes.c_uint32 * 4)()
    cnt = ctypes.c_uint32(4)
    if libc.host_statistics(_HOST, 3, arr, ctypes.byref(cnt)) != 0:
        return 0
    return arr[0] + arr[1] + arr[3]


# ---------------------------------------------------------------- system memory (no subprocess)

class VMStat64(ctypes.Structure):  # struct vm_statistics64 (HOST_VM_INFO64 = 4)
    _fields_ = [("free", ctypes.c_uint32), ("active", ctypes.c_uint32), ("inactive", ctypes.c_uint32),
                ("wire", ctypes.c_uint32), ("zero_fill", ctypes.c_uint64), ("reactivations", ctypes.c_uint64),
                ("pageins", ctypes.c_uint64), ("pageouts", ctypes.c_uint64), ("faults", ctypes.c_uint64),
                ("cow_faults", ctypes.c_uint64), ("lookups", ctypes.c_uint64), ("hits", ctypes.c_uint64),
                ("purges", ctypes.c_uint64), ("purgeable", ctypes.c_uint32), ("speculative", ctypes.c_uint32),
                ("decompressions", ctypes.c_uint64), ("compressions", ctypes.c_uint64),
                ("swapins", ctypes.c_uint64), ("swapouts", ctypes.c_uint64), ("compressor", ctypes.c_uint32),
                ("throttled", ctypes.c_uint32), ("external", ctypes.c_uint32), ("internal", ctypes.c_uint32),
                ("uncompressed", ctypes.c_uint64)]


class XswUsage(ctypes.Structure):  # struct xsw_usage (vm.swapusage)
    _fields_ = [("total", ctypes.c_uint64), ("avail", ctypes.c_uint64), ("used", ctypes.c_uint64),
                ("pagesize", ctypes.c_uint32), ("encrypted", ctypes.c_int32)]


libc.host_statistics64.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
libc.sysctlbyname.argtypes = [ctypes.c_char_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t),
                              ctypes.c_void_p, ctypes.c_size_t]
_vm = VMStat64()
_xsw = XswUsage()
_i32 = ctypes.c_int32()
_u64 = ctypes.c_uint64()


def _sysctl(name: bytes, buf) -> bool:
    n = ctypes.c_size_t(ctypes.sizeof(buf))
    return libc.sysctlbyname(name, ctypes.byref(buf), ctypes.byref(n), None, 0) == 0


PAGE = _i32.value if _sysctl(b"vm.pagesize", _i32) else 16384
MEM_TOTAL = _u64.value if _sysctl(b"hw.memsize", _u64) else 0
PRESSURE = {1: "normal", 2: "warn", 4: "critical"}


def read_sysmem():
    """Activity Monitor's breakdown, in MB, plus cumulative swap/pageout counters (pages).
    Used = app + wired + compressed; cached = file-backed + purgeable."""
    cnt = ctypes.c_uint32(ctypes.sizeof(_vm) // 4)
    if libc.host_statistics64(_HOST, 4, ctypes.byref(_vm), ctypes.byref(cnt)) != 0:
        return None
    mb = PAGE / 2**20
    app = max(_vm.internal - _vm.purgeable, 0) * mb
    wired, comp = _vm.wire * mb, _vm.compressor * mb
    pressure = _i32.value if _sysctl(b"kern.memorystatus_vm_pressure_level", _i32) else 0
    swap_used = swap_total = 0.0
    if _sysctl(b"vm.swapusage", _xsw):
        swap_used, swap_total = _xsw.used / 2**20, _xsw.total / 2**20
    return {"pressure": pressure, "used": app + wired + comp, "app": app, "wired": wired, "compressed": comp,
            "cached": (_vm.external + _vm.purgeable) * mb, "free": _vm.free * mb,
            "swap_used": swap_used, "swap_total": swap_total,
            "counters": (_vm.swapins, _vm.swapouts, _vm.pageouts)}


# ---------------------------------------------------------------- GPU via IOKit (no ioreg fork)

_iok = ctypes.CDLL("/System/Library/Frameworks/IOKit.framework/IOKit")
_cf = ctypes.CDLL("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
_vp, _u32 = ctypes.c_void_p, ctypes.c_uint32
_iok.IOServiceMatching.restype = _vp
_iok.IOServiceMatching.argtypes = [ctypes.c_char_p]
_iok.IOServiceGetMatchingServices.argtypes = [_u32, _vp, ctypes.POINTER(_u32)]
_iok.IOIteratorNext.restype = _u32
_iok.IOIteratorNext.argtypes = [_u32]
_iok.IOObjectRelease.argtypes = [_u32]
_iok.IORegistryEntryCreateCFProperty.restype = _vp
_iok.IORegistryEntryCreateCFProperty.argtypes = [_u32, _vp, _vp, _u32]
_iok.IORegistryEntryGetChildIterator.argtypes = [_u32, ctypes.c_char_p, ctypes.POINTER(_u32)]
_cf.CFStringCreateWithCString.restype = _vp
_cf.CFStringCreateWithCString.argtypes = [_vp, ctypes.c_char_p, _u32]
_cf.CFDictionaryGetValue.restype = _vp
_cf.CFDictionaryGetValue.argtypes = [_vp, _vp]
_cf.CFNumberGetValue.argtypes = [_vp, ctypes.c_int, _vp]
_cf.CFArrayGetCount.restype = ctypes.c_long
_cf.CFArrayGetCount.argtypes = [_vp]
_cf.CFArrayGetValueAtIndex.restype = _vp
_cf.CFArrayGetValueAtIndex.argtypes = [_vp, ctypes.c_long]
_cf.CFStringGetCString.argtypes = [_vp, ctypes.c_char_p, ctypes.c_long, _u32]
_cf.CFRelease.argtypes = [_vp]
_UTF8 = 0x08000100
_K = {k: _cf.CFStringCreateWithCString(None, k.encode(), _UTF8) for k in (
    "PerformanceStatistics", "Device Utilization %", "Renderer Utilization %", "Tiler Utilization %",
    "IOUserClientCreator", "AppUsage", "accumulatedGPUTime")}
_cfbuf = ctypes.create_string_buffer(256)


def _cfnum(v):
    if not v:
        return None
    x = ctypes.c_int64()
    _cf.CFNumberGetValue(v, 4, ctypes.byref(x))  # kCFNumberSInt64Type
    return x.value


def read_gpu():
    """((device %, renderer %, tiler %), {pid: accumulated GPU ns}) from the IOAccelerator
    services and their AGX user clients, the same data `ioreg` prints."""
    util = [None, None, None]
    per_pid: dict[int, int] = defaultdict(int)
    it = _u32()
    if _iok.IOServiceGetMatchingServices(0, _iok.IOServiceMatching(b"IOAccelerator"), ctypes.byref(it)) != 0:
        return tuple(util), per_pid
    while (acc := _iok.IOIteratorNext(it.value)):
        d = _iok.IORegistryEntryCreateCFProperty(acc, _K["PerformanceStatistics"], None, 0)
        if d:
            for i, k in enumerate(("Device Utilization %", "Renderer Utilization %", "Tiler Utilization %")):
                v = _cfnum(_cf.CFDictionaryGetValue(d, _K[k]))
                if v is not None:
                    util[i] = max(util[i] or 0, v)
            _cf.CFRelease(d)
        ci = _u32()
        if _iok.IORegistryEntryGetChildIterator(acc, b"IOService", ctypes.byref(ci)) == 0:
            while (c := _iok.IOIteratorNext(ci.value)):
                cr = _iok.IORegistryEntryCreateCFProperty(c, _K["IOUserClientCreator"], None, 0)
                if cr:
                    _cf.CFStringGetCString(cr, _cfbuf, 256, _UTF8)
                    _cf.CFRelease(cr)
                    txt = _cfbuf.value.decode(errors="replace")
                    if txt.startswith("pid ") and "," in txt:
                        au = _iok.IORegistryEntryCreateCFProperty(c, _K["AppUsage"], None, 0)
                        if au:
                            tot = 0
                            for i in range(_cf.CFArrayGetCount(au)):
                                tot += _cfnum(_cf.CFDictionaryGetValue(_cf.CFArrayGetValueAtIndex(au, i),
                                                                       _K["accumulatedGPUTime"])) or 0
                            _cf.CFRelease(au)
                            per_pid[int(txt[4:txt.index(",")])] += tot
                _iok.IOObjectRelease(c)
            _iok.IOObjectRelease(ci.value)
        _iok.IOObjectRelease(acc)
    _iok.IOObjectRelease(it.value)
    return tuple(util), per_pid


# ---------------------------------------------------------------- app attribution

_SIM_APP = re.compile(r"/CoreSimulator/Devices/[^/]+/data/Containers/Bundle/Application/[^/]+/([^/]+)\.app/")
_DEV_APP = re.compile(r"/Contents/Developer/Applications/([^/]+)\.app/")


def app_of(path: str, comm: str, args: list[str] | None) -> tuple[str, bool]:
    """Return (app name, is_bundle)."""
    if path:
        m = _SIM_APP.search(path)
        if m:
            return f"Simulator: {m.group(1)}", True
        if "/CoreSimulator" in path:
            return "iOS Simulator runtime", True
        m = _DEV_APP.search(path)
        if m:
            return m.group(1), True
        i = path.find(".app/")
        if i >= 0:
            return path[path.rfind("/", 0, i) + 1:i], True
    base = os.path.basename(path) if path else comm
    base = base or comm or "?"
    if args and (base in INTERPRETERS or base.startswith("python")):
        return cli_hint(base, args[1:]), False
    return base, False


def cli_hint(base: str, args: list[str]) -> str:
    joined = " ".join(args)
    if "claude-agent-sdk" in joined:
        return "claude-agent-sdk"
    if "--test" in args:
        return f"{base} --test"
    for a in args:
        if a.startswith("-"):
            continue
        m = re.search(r"node_modules/((?:@[^/]+/)?[^/]+)", a)
        if m:
            return f"{base} {m.group(1)}"
        if "/" in a or "." in a:
            return f"{base} {os.path.basename(a.rstrip('/'))[:40]}"
        return f"{base} {a[:40]}"
    return base


# ---------------------------------------------------------------- sampler

class Proc:
    __slots__ = ("pid", "ppid", "comm", "app", "bundle", "start", "cpu", "child", "child_new", "rss", "fp", "via", "uid")

    def __init__(self, pid, ppid, comm, app, bundle, start):
        self.pid, self.ppid, self.comm, self.app, self.bundle, self.start = pid, ppid, comm, app, bundle, start
        self.cpu = self.child = 0.0
        self.child_new = 0.0
        self.rss = self.fp = 0   # fp: phys_footprint (Activity Monitor's Memory); RSS for other users
        self.via = ""
        self.uid = -1


class Sampler:
    def __init__(self, db: sqlite3.Connection):
        self.db = db
        self.own: dict[int, Proc] = {}        # processes readable via libproc
        self.foreign: dict[int, Proc] = {}    # other users' processes, read via ps
        self.foreign_pids: set[int] = set()
        self.first_fast = True
        self.first_ps = True
        self.poll_abs = mach_abs()            # mach time of the previous fast poll
        self.fast_host_prev = host_cpu_ticks()
        self.last_ps_mono = time.monotonic()
        self.headroom = 0.0                   # machine CPU not yet matched by attributed CPU
        # accumulators for the current sample period
        self.acc_cpu: dict[int, float] = defaultdict(float)
        self.acc_meta: dict[int, tuple] = {}
        self.gpu_prev: dict[int, int] = {}
        # CPU of exited children not yet seen in their parent's reaped-children
        # time (a zombie is reaped later): ppid -> [cpu_s, time added]
        self.pending_reap: dict[int, list] = {}
        self.docker_prev: dict[str, tuple[int, float]] = {}
        self.host_prev = host_cpu_ticks()
        self.last_sample = time.time()
        self.last_docker = 0.0
        self.last_ps = 0.0
        self.last_mem = 0.0
        self.vm_prev = None
        self.last_rollup = 0.0
        self.self_prev = self_cpu()
        self.costs: list[tuple[float, float]] = []
        self.scale = 1.0

    # -- metadata
    def via_of(self, ppid: int) -> str:
        seen = 0
        while ppid > 1 and seen < 20:
            p = self.own.get(ppid) or self.foreign.get(ppid)
            if p is None:
                return ""
            if p.bundle:
                return p.app
            ppid, seen = p.ppid, seen + 1
        return ""

    def credit(self, p: Proc, cpu: float, name: str | None = None):
        if cpu <= 0:
            return
        key = p.pid if name is None else -p.pid
        self.acc_cpu[key] += cpu
        self.acc_meta[key] = (p.pid, p.ppid, p.app, name or p.comm, p.via, p.rss)

    # -- 10 s poll of own processes via libproc. This is the hot loop: keep it lean.
    def fast_poll(self):
        n = libproc.proc_listallpids(_pidbuf, ctypes.sizeof(_pidbuf))
        pids = _pidbuf[:max(n, 0)]
        own, foreign_pids, credit = self.own, self.foreign_pids, self.credit
        pid_rusage, ru_ref, ru, k = libc.proc_pid_rusage, _ru_ref, _ru, MACH_TO_S
        first = self.first_fast
        prev_abs, self.poll_abs = self.poll_abs, mach_abs()
        host = host_cpu_ticks()
        host_dt = (host - self.fast_host_prev) / CLK_TCK if host >= self.fast_host_prev else 0.0
        self.fast_host_prev = host
        pid_cpu = 0.0
        alive = []
        new_foreign = set()
        for pid in pids:
            if pid <= 0:
                continue
            if pid in foreign_pids:           # known other-user process: ps reads it
                new_foreign.add(pid)
                continue
            if pid_rusage(pid, 2, ru_ref) != 0:
                if pid not in own:            # an own process that stops answering is exiting
                    new_foreign.add(pid)
                continue
            cpu = (ru.user + ru.system) * k
            child = (ru.child_user + ru.child_system) * k
            p = own.get(pid)
            if p is None or p.start != ru.start_abstime:
                p = self.new_proc(pid, ru.start_abstime)
                if p is None:
                    continue
                # A process already running at the previous poll (or at startup) is
                # baselined; only one started since then counts from zero.
                if first or ru.start_abstime < prev_abs:
                    p.cpu, p.child = cpu, child
            if cpu > p.cpu:
                credit(p, cpu - p.cpu)
                pid_cpu += cpu - p.cpu
                p.cpu = cpu
            p.rss = ru.resident
            p.fp = ru.footprint
            p.child_new = child
            alive.append(p)
        # processes that exited since the last poll
        now = time.monotonic()
        if len(alive) != len(own):
            live = {p.pid for p in alive}
            for pid in [x for x in own if x not in live]:
                p = own.pop(pid)
                ent = self.pending_reap.setdefault(p.ppid, [0.0, now])
                ent[0] += p.cpu + p.child
                ent[1] = now
        # CPU of children that lived and died between polls shows up only in the
        # parent's reaped-children time: credit the part not already seen.
        pending = self.pending_reap
        extra = []
        for p in alive:
            dchild = p.child_new - p.child
            if dchild <= 0:
                continue
            p.child = p.child_new
            ent = pending.get(p.pid)
            if ent:
                used = min(dchild, ent[0])
                ent[0] -= used
                dchild -= used
            if dchild > 0.005 and not first:
                extra.append((p, dchild))
        if extra:
            # Children that lived and died between polls ran during this poll's
            # interval, so together they cannot exceed the machine's busy CPU left
            # over after the per-PID deltas. A larger jump is the lifetime of a child
            # that was never tracked (or already counted): scale it down to fit.
            total = sum(d for _, d in extra)
            budget = max(0.0, host_dt - pid_cpu)
            f = min(1.0, budget / total) if total > 0 else 0.0
            if total - budget > 30:
                big = max(extra, key=lambda x: x[1])
                log(f"children CPU {total:.0f}s over the machine's {budget:.0f}s spare; "
                    f"scaled x{f:.3f} (largest: {big[0].comm} pid {big[0].pid} {big[1]:.0f}s)")
            for p, d in extra:
                credit(p, d * f, name=f"(children of {p.comm})")
        if pending:
            for key in [x for x, v in pending.items() if v[0] <= 0 or now - v[1] > 60 or x not in own]:
                del pending[key]
        self.foreign_pids = new_foreign
        self.first_fast = False

    def new_proc(self, pid: int, start: int):
        bi = bsdinfo(pid)
        if bi is None:
            return None
        ppid, comm = bi
        path = pidpath(pid)
        base = os.path.basename(path) or comm
        args = procargs(pid) if (base in INTERPRETERS or base.startswith("python")) else None
        app, bundle = app_of(path, comm, args)
        p = Proc(pid, ppid, app if args else base[:60], app, bundle, start)
        p.via = "" if bundle else self.via_of(ppid)
        self.own[pid] = p
        return p

    # -- other users' processes: setuid /bin/ps limited to their users (-u is ~8 ms;
    #    a full `ps -A` with comm is ~90 ms). Path and ppid come from libproc.
    def ps_poll(self):
        users = set()
        for pid in self.foreign_pids:
            p = self.foreign.get(pid)
            if p is None:
                si = shortinfo(pid)
                if si is None:
                    continue
                ppid, uid, comm = si
                path = pidpath(pid)
                app, bundle = app_of(path, comm, None)
                p = Proc(pid, ppid, (os.path.basename(path) or comm)[:60], app, bundle, -1)
                p.via = "" if bundle else self.via_of(ppid)
                p.uid = uid
                self.foreign[pid] = p
            users.add(p.uid)
        for pid in [x for x in self.foreign if x not in self.foreign_pids]:
            del self.foreign[pid]
        names = sorted(n for n in (user_name(u) for u in users) if n)
        if not names:
            return
        try:
            out = subprocess.run(["/bin/ps", "-x", "-o", "pid=,time=,rss=,etime=", "-u", ",".join(names)],
                                 capture_output=True, text=True, timeout=20).stdout
        except Exception as e:  # noqa: BLE001
            log(f"ps failed: {e}")
            return
        seen = set()
        now = time.monotonic()
        since_last = now - self.last_ps_mono
        self.last_ps_mono = now
        for line in out.splitlines():
            parts = line.split()
            if len(parts) != 4:
                continue
            p = self.foreign.get(int(parts[0]))
            if p is None:
                continue
            seen.add(p.pid)
            cpu, rss = parse_time(parts[1]), int(parts[2]) * 1024
            if p.start == -1:   # first read: count from zero only if it started since the last ps
                p.start = 0
                started_since = not self.first_ps and parse_time(parts[3]) <= since_last + 2
                p.cpu = 0.0 if started_since else cpu
            if cpu >= p.cpu:
                self.credit(p, cpu - p.cpu)
            p.cpu, p.rss, p.fp = cpu, rss, rss   # no footprint without root: RSS stands in
        for pid in [x for x in self.foreign if x not in seen]:   # exited, or pid reused
            p = self.foreign.pop(pid)
            if p.ppid in self.own:     # its parent's reaped-children time will include it
                ent = self.pending_reap.setdefault(p.ppid, [0.0, now])
                ent[0] += p.cpu
                ent[1] = now
            self.foreign_pids.discard(pid)
        self.first_ps = False

    # -- per-process GPU time from the AGX user clients (IOKit, in process)
    def gpu_poll(self):
        try:
            (dev, ren, til), per_pid = read_gpu()
        except Exception as e:  # noqa: BLE001
            log(f"gpu read failed: {e!r}")
            return None, None, None, {}
        gpu_s: dict[int, float] = {}
        for pid, ns in per_pid.items():
            prev = self.gpu_prev.get(pid)
            if prev is not None and ns >= prev:
                gpu_s[pid] = (ns - prev) / 1e9
        self.gpu_prev = dict(per_pid)
        return dev, ren, til, gpu_s

    # -- per-container CPU from the Docker Engine API
    def docker_poll(self, ts: float):
        sock = docker_socket()
        if not sock:
            return []
        rows = []
        try:
            containers = docker_get(sock, "/containers/json")
            now_ids = set()
            for c in containers:
                cid = c["Id"]
                name = (c.get("Names") or [cid[:12]])[0].lstrip("/")
                st = docker_get(sock, f"/containers/{cid}/stats?stream=false&one-shot=true")
                total = st.get("cpu_stats", {}).get("cpu_usage", {}).get("total_usage", 0)
                mem = st.get("memory_stats", {})
                mem_b = mem.get("usage", 0) - mem.get("stats", {}).get("inactive_file", 0)
                now_ids.add(cid)
                prev = self.docker_prev.get(cid)
                self.docker_prev[cid] = (total, ts)
                if prev and total >= prev[0]:
                    rows.append((ts, name, (total - prev[0]) / 1e9, ts - prev[1], mem_b / 2**20))
            for cid in [x for x in self.docker_prev if x not in now_ids]:
                del self.docker_prev[cid]
        except (ConnectionRefusedError, FileNotFoundError):
            pass   # Docker / OrbStack not running
        except Exception as e:  # noqa: BLE001
            log(f"docker poll failed: {e!r}")
        return rows

    # -- one 15 s sample: collect, write
    def sample(self):
        ts = time.time()
        dur = ts - self.last_sample
        self.last_sample = ts
        if ts - self.last_ps >= PS_INTERVAL * self.scale - 1:
            self.last_ps = ts
            self.ps_poll()
        dev, ren, til, gpu_s = self.gpu_poll()
        host = host_cpu_ticks()
        host_cpu = (host - self.host_prev) / CLK_TCK if host >= self.host_prev else 0.0
        self.host_prev = host

        self.cap_attributed(host_cpu, dur)

        # group by app
        apps: dict[tuple[str, str], list] = defaultdict(lambda: [0.0, 0.0, 0, set()])
        procs = []
        for key, cpu in self.acc_cpu.items():
            pid, ppid, app, name, via, rss = self.acc_meta[key]
            a = apps[(app, via)]
            a[0] += cpu
            if cpu >= PROC_MIN_CPU:
                procs.append((ts, pid, ppid, app, via, name, cpu, rss / 2**20))
        allp = list(self.own.values()) + list(self.foreign.values())
        by_pid = {p.pid: p for p in allp}
        for pid, g in gpu_s.items():
            p = by_pid.get(pid)
            if p and g > 0:
                apps[(p.app, p.via)][1] += g
        for p in allp:
            a = apps.get((p.app, p.via))
            if a is not None:
                a[2] += p.rss
                a[3].add(p.pid)
        seen_cpu = sum(self.acc_cpu.values())
        self.acc_cpu.clear()
        self.acc_meta.clear()

        sc = self_cpu()
        self_cost = sc - self.self_prev
        self.self_prev = sc
        self_rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 2**20  # bytes on macOS

        db = self.db
        with db:
            db.execute("INSERT INTO samples VALUES (?,?,?,?,?,?,?,?,?,?)",
                       (ts, dur, host_cpu, seen_cpu, dev, ren, til, len(allp), self_cost, self_rss))
            rows, other = [], [0.0, 0.0, 0, 0]
            for (app, via), v in apps.items():
                if v[0] >= APP_MIN_CPU or v[1] >= APP_MIN_CPU:
                    rows.append((ts, app, via, round(v[0], 3), round(v[1], 3), round(v[2] / 2**20, 1), len(v[3])))
                else:
                    other[0] += v[0]
                    other[1] += v[1]
                    other[2] += v[2]
                    other[3] += len(v[3])
            if other[0] or other[1]:
                rows.append((ts, "(other)", "", round(other[0], 3), round(other[1], 3),
                             round(other[2] / 2**20, 1), other[3]))
            db.executemany("INSERT INTO app_cpu VALUES (?,?,?,?,?,?,?)", rows)
            db.executemany("INSERT INTO proc_cpu VALUES (?,?,?,?,?,?,?,?)",
                           [(t, pid, ppid, app, via, name, round(c, 3), round(r, 1))
                            for t, pid, ppid, app, via, name, c, r in procs])
            if ts - self.last_docker >= DOCKER_INTERVAL - 1:
                self.last_docker = ts
                db.executemany("INSERT INTO docker VALUES (?,?,?,?,?)", self.docker_poll(ts))
            sm = read_sysmem()
            if sm:
                cur = sm["counters"]
                d = [max(c - p, 0) for c, p in zip(cur, self.vm_prev)] if self.vm_prev else [0, 0, 0]
                self.vm_prev = cur
                mb = PAGE / 2**20
                db.execute("INSERT INTO sysmem VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                           (ts, sm["pressure"], round(sm["used"]), round(sm["app"]), round(sm["wired"]),
                            round(sm["compressed"]), round(sm["cached"]), round(sm["free"]),
                            round(sm["swap_used"]), round(sm["swap_total"]),
                            round(d[0] * mb, 1), round(d[1] * mb, 1), round(d[2] * mb, 1)))
            if ts - self.last_mem >= MEM_INTERVAL * self.scale - 1:
                self.last_mem = ts
                mem = defaultdict(lambda: [0, 0, 0])
                for p in allp:
                    m = mem[p.app]
                    m[0] += p.rss
                    m[1] += 1
                    m[2] += p.fp
                rows, other = [], [0, 0, 0]
                for a, v in mem.items():
                    if v[2] >= 20 * 2**20 or v[0] >= 20 * 2**20:
                        rows.append((ts, a, round(v[0] / 2**20, 1), v[1], round(v[2] / 2**20, 1)))
                    else:
                        other = [o + x for o, x in zip(other, v)]
                rows.append((ts, "(other)", round(other[0] / 2**20, 1), other[1], round(other[2] / 2**20, 1)))
                db.executemany("INSERT INTO mem VALUES (?,?,?,?,?)", rows)
        self.check_budget(self_cost, dur)
        if ts - self.last_rollup >= 3600:
            self.last_rollup = ts
            rollup_and_prune(db)

    def cap_attributed(self, host_cpu: float, dur: float):
        """Attributed CPU may lag or lead the machine counter by a poll, so it is held to a
        running balance: machine CPU this sample plus what earlier samples left unmatched.
        Any excess comes out of the "(children of X)" rows first, then every row."""
        acc = self.acc_cpu
        seen = sum(acc.values())
        avail = host_cpu + self.headroom
        excess = seen - (avail * 1.02 + 0.5)
        if excess > 0:
            for keys in ([k for k in acc if k < 0], list(acc)):
                tot = sum(acc[k] for k in keys)
                if tot <= 0 or excess <= 0:
                    continue
                f = max(0.0, 1 - excess / tot)
                for k in keys:
                    acc[k] *= f
                excess -= tot * (1 - f)
            log(f"attributed {seen:.0f}s > machine {avail:.0f}s in one sample: trimmed to {sum(acc.values()):.0f}s")
            seen = sum(acc.values())
        self.headroom = min(max(avail - seen, 0.0), host_cpu)
        lim = NCPU * dur
        by_app = defaultdict(float)
        for k, c in acc.items():
            by_app[self.acc_meta[k][2]] += c
        for app, c in by_app.items():
            if c > lim:
                log(f"{app}: {c:.0f}s in a {dur:.0f}s sample exceeds {NCPU} cores; capped")
                for k in acc:
                    if self.acc_meta[k][2] == app:
                        acc[k] *= lim / c

    def check_budget(self, cost: float, dur: float):
        """Stretch the poll intervals when the rolling own-CPU average is over budget,
        and relax them again once it is well under."""
        self.costs.append((cost, dur))
        del self.costs[:-BUDGET_WINDOW]
        if len(self.costs) < BUDGET_WINDOW:   # judge a full window, not startup
            return
        pct = 100 * sum(c for c, _ in self.costs) / sum(d for _, d in self.costs)
        old = self.scale
        if pct > BUDGET_PCT and self.scale < MAX_SCALE:
            self.scale = min(MAX_SCALE, self.scale * 1.5)
        elif pct < BUDGET_PCT / 2.5 and self.scale > 1:
            self.scale = max(1.0, self.scale / 1.5)
        if self.scale != old:
            self.costs.clear()
            log(f"own CPU {pct:.2f}% of a core (budget {BUDGET_PCT}%): intervals x{self.scale:.2f} -> "
                f"poll {FAST_INTERVAL * self.scale:.1f}s, sample {SAMPLE_INTERVAL * self.scale:.1f}s")

    def run(self):
        stop = []
        signal.signal(signal.SIGTERM, lambda *_: stop.append(1))
        signal.signal(signal.SIGINT, lambda *_: stop.append(1))
        log(f"sampler started pid={os.getpid()} db={DB_PATH}")
        self.fast_poll()
        self.ps_poll()
        self.gpu_poll()
        self.acc_cpu.clear()
        self.acc_meta.clear()
        self.last_sample = time.time()
        self.host_prev = host_cpu_ticks()
        self.self_prev = self_cpu()
        next_fast = time.monotonic() + FAST_INTERVAL
        next_sample = time.monotonic() + SAMPLE_INTERVAL
        while not stop:
            now = time.monotonic()
            time.sleep(max(0.05, min(next_fast, next_sample) - now))
            if stop:
                break
            now = time.monotonic()
            try:
                if now >= next_fast:
                    self.fast_poll()
                    next_fast = max(next_fast + FAST_INTERVAL * self.scale, now + 0.5)
                if now >= next_sample:
                    self.sample()
                    next_sample = max(next_sample + SAMPLE_INTERVAL * self.scale, now + 1)
            except Exception as e:  # noqa: BLE001
                log(f"sample error: {e!r}")
                time.sleep(1)
        log("sampler stopped")


def self_cpu() -> float:
    a = resource.getrusage(resource.RUSAGE_SELF)
    b = resource.getrusage(resource.RUSAGE_CHILDREN)
    return a.ru_utime + a.ru_stime + b.ru_utime + b.ru_stime


_users: dict[int, str] = {}


def user_name(uid: int) -> str:
    if uid not in _users:
        try:
            import pwd
            _users[uid] = pwd.getpwuid(uid).pw_name
        except KeyError:
            _users[uid] = str(uid)
    return _users[uid]


def parse_time(s: str) -> float:
    days = 0
    if "-" in s:
        d, s = s.split("-", 1)
        days = int(d)
    parts = [float(x) for x in s.split(":")]
    sec = 0.0
    for x in parts:
        sec = sec * 60 + x
    return days * 86400 + sec


def log(msg: str):
    print(f"{dt.datetime.now():%Y-%m-%d %H:%M:%S} {msg}", file=sys.stderr, flush=True)


# ---------------------------------------------------------------- docker

def docker_socket() -> str | None:
    host = os.environ.get("DOCKER_HOST", "")
    cands = [host[7:]] if host.startswith("unix://") else []
    cands += [str(Path.home() / ".orbstack/run/docker.sock"), "/var/run/docker.sock"]
    for c in cands:
        if c and os.path.exists(c):
            return c
    return None


class _UnixHTTP(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("localhost", timeout=10)
        self._path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(10)
        self.sock.connect(self._path)


def docker_get(sock: str, url: str):
    c = _UnixHTTP(sock)
    try:
        c.request("GET", url)
        r = c.getresponse()
        body = r.read()
        if r.status != 200:
            raise RuntimeError(f"{url}: HTTP {r.status}")
        return json.loads(body)
    finally:
        c.close()


# ---------------------------------------------------------------- database

SCHEMA = """
CREATE TABLE IF NOT EXISTS samples(ts REAL PRIMARY KEY, dur REAL, host_cpu_s REAL, seen_cpu_s REAL,
  gpu_dev INT, gpu_ren INT, gpu_til INT, nprocs INT, self_cpu_s REAL, self_rss_mb REAL);
CREATE TABLE IF NOT EXISTS app_cpu(ts REAL, app TEXT, via TEXT, cpu_s REAL, gpu_s REAL, rss_mb REAL, nproc INT);
CREATE INDEX IF NOT EXISTS app_cpu_ts ON app_cpu(ts);
CREATE TABLE IF NOT EXISTS proc_cpu(ts REAL, pid INT, ppid INT, app TEXT, via TEXT, name TEXT, cpu_s REAL, rss_mb REAL);
CREATE INDEX IF NOT EXISTS proc_cpu_ts ON proc_cpu(ts);
CREATE TABLE IF NOT EXISTS docker(ts REAL, container TEXT, cpu_s REAL, dur REAL, mem_mb REAL);
CREATE INDEX IF NOT EXISTS docker_ts ON docker(ts);
CREATE TABLE IF NOT EXISTS mem(ts REAL, app TEXT, rss_mb REAL, nproc INT, fp_mb REAL);
CREATE TABLE IF NOT EXISTS sysmem(ts REAL PRIMARY KEY, pressure INT, used_mb INT, app_mb INT, wired_mb INT,
  compressed_mb INT, cached_mb INT, free_mb INT, swap_used_mb INT, swap_total_mb INT,
  swapin_mb REAL, swapout_mb REAL, pageout_mb REAL);
CREATE TABLE IF NOT EXISTS hourly_sysmem(hour INT PRIMARY KEY, max_pressure INT, avg_used_mb REAL, max_used_mb REAL,
  avg_compressed_mb REAL, max_compressed_mb REAL, max_swap_used_mb REAL, min_free_mb REAL,
  swapin_mb REAL, swapout_mb REAL, pageout_mb REAL);
CREATE TABLE IF NOT EXISTS hourly_mem(hour INT, app TEXT, avg_fp_mb REAL, max_fp_mb REAL, avg_rss_mb REAL,
  PRIMARY KEY(hour, app));
CREATE INDEX IF NOT EXISTS mem_ts ON mem(ts);
CREATE TABLE IF NOT EXISTS hourly_app(hour INT, app TEXT, via TEXT, cpu_s REAL, gpu_s REAL,
  peak_pct REAL, avg_rss_mb REAL, PRIMARY KEY(hour, app, via));
CREATE TABLE IF NOT EXISTS hourly_sys(hour INT PRIMARY KEY, dur REAL, host_cpu_s REAL, seen_cpu_s REAL,
  gpu_avg REAL, gpu_max INT, self_cpu_s REAL);
CREATE TABLE IF NOT EXISTS hourly_docker(hour INT, container TEXT, cpu_s REAL, avg_mem_mb REAL,
  PRIMARY KEY(hour, container));
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
"""


def open_db() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(DB_PATH, timeout=30)
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA synchronous=NORMAL")
    db.executescript(SCHEMA)
    if "fp_mb" not in [r[1] for r in db.execute("PRAGMA table_info(mem)")]:
        db.execute("ALTER TABLE mem ADD COLUMN fp_mb REAL")   # databases from before footprint
    return db


def rollup_and_prune(db: sqlite3.Connection):
    """Roll completed hours into hourly_* tables, then prune old raw rows."""
    row = db.execute("SELECT v FROM meta WHERE k='rolled_until'").fetchone()
    start = int(row[0]) if row else int(db.execute("SELECT COALESCE(MIN(ts),0) FROM samples").fetchone()[0] // 3600 * 3600)
    end = int(time.time() // 3600 * 3600)
    if start and end > start:
        with db:
            db.execute(f"""INSERT OR REPLACE INTO hourly_app
                SELECT CAST(ts/3600 AS INT)*3600, app, via, SUM(cpu_s), SUM(gpu_s),
                       MAX(cpu_s*100.0/{SAMPLE_INTERVAL}), AVG(rss_mb) FROM app_cpu WHERE ts>=? AND ts<? GROUP BY 1,2,3""", (start, end))
            db.execute("""INSERT OR REPLACE INTO hourly_sys
                SELECT CAST(ts/3600 AS INT)*3600, SUM(dur), SUM(host_cpu_s), SUM(seen_cpu_s),
                       AVG(gpu_dev), MAX(gpu_dev), SUM(self_cpu_s) FROM samples WHERE ts>=? AND ts<? GROUP BY 1""", (start, end))
            db.execute("""INSERT OR REPLACE INTO hourly_docker
                SELECT CAST(ts/3600 AS INT)*3600, container, SUM(cpu_s), AVG(mem_mb)
                FROM docker WHERE ts>=? AND ts<? GROUP BY 1,2""", (start, end))
            db.execute("""INSERT OR REPLACE INTO hourly_sysmem
                SELECT CAST(ts/3600 AS INT)*3600, MAX(pressure), AVG(used_mb), MAX(used_mb), AVG(compressed_mb),
                       MAX(compressed_mb), MAX(swap_used_mb), MIN(free_mb), SUM(swapin_mb), SUM(swapout_mb),
                       SUM(pageout_mb) FROM sysmem WHERE ts>=? AND ts<? GROUP BY 1""", (start, end))
            # an app missing from a snapshot was under the row threshold: count it as 0
            db.execute("""INSERT OR REPLACE INTO hourly_mem
                SELECT m.h, m.app, m.s / n.cnt, m.mx, m.r / n.cnt FROM
                  (SELECT CAST(ts/3600 AS INT)*3600 h, app, SUM(COALESCE(fp_mb, rss_mb)) s,
                          MAX(COALESCE(fp_mb, rss_mb)) mx, SUM(rss_mb) r
                   FROM mem WHERE ts>=? AND ts<? GROUP BY 1, 2) m
                JOIN (SELECT CAST(ts/3600 AS INT)*3600 h, COUNT(DISTINCT ts) cnt FROM mem
                      WHERE ts>=? AND ts<? GROUP BY 1) n USING(h)""", (start, end, start, end))
            db.execute("INSERT OR REPLACE INTO meta VALUES('rolled_until', ?)", (str(end),))
    cut = time.time() - RAW_DAYS * 86400
    cut2 = time.time() - ROLLUP_DAYS * 86400
    with db:
        for t in ("samples", "app_cpu", "proc_cpu", "docker", "mem", "sysmem"):
            db.execute(f"DELETE FROM {t} WHERE ts < ?", (cut,))
        for t in ("hourly_app", "hourly_sys", "hourly_docker", "hourly_sysmem", "hourly_mem"):
            db.execute(f"DELETE FROM {t} WHERE hour < ?", (cut2,))
    db.execute("PRAGMA wal_checkpoint(TRUNCATE)")


# ---------------------------------------------------------------- launchd

def cmd_install(_args):
    uv = subprocess.run(["/usr/bin/which", "uv"], capture_output=True, text=True).stdout.strip() \
        or str(Path.home() / ".local/bin/uv")
    script = str(Path(__file__).resolve())
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    plist = {
        "Label": LABEL,
        "ProgramArguments": [uv, "run", "--quiet", "--script", script, "run"],
        "RunAtLoad": True,
        "KeepAlive": {"SuccessfulExit": False},
        "ThrottleInterval": 30,
        "ProcessType": "Background",
        "LowPriorityIO": True,
        "Nice": 10,
        "StandardOutPath": str(LOG_PATH),
        "StandardErrorPath": str(LOG_PATH),
        "EnvironmentVariables": {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin:" + str(Path(uv).parent)},
    }
    PLIST_PATH.parent.mkdir(parents=True, exist_ok=True)
    uid = os.getuid()
    subprocess.run(["launchctl", "bootout", f"gui/{uid}/{LABEL}"], capture_output=True)
    for _ in range(50):   # bootout returns before the old instance has gone
        if subprocess.run(["launchctl", "print", f"gui/{uid}/{LABEL}"], capture_output=True).returncode != 0:
            break
        time.sleep(0.2)
    PLIST_PATH.write_bytes(plistlib.dumps(plist))
    r = subprocess.run(["launchctl", "bootstrap", f"gui/{uid}", str(PLIST_PATH)], capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit(f"launchctl bootstrap failed: {r.stderr.strip()}")
    print(f"installed {PLIST_PATH}\nlog: {LOG_PATH}\ndb:  {DB_PATH}")


def cmd_uninstall(_args):
    subprocess.run(["launchctl", "bootout", f"gui/{os.getuid()}/{LABEL}"], capture_output=True)
    if PLIST_PATH.exists():
        PLIST_PATH.unlink()
    print(f"removed {PLIST_PATH} (database kept at {DB_PATH})")


def cmd_status(_args):
    r = subprocess.run(["launchctl", "print", f"gui/{os.getuid()}/{LABEL}"], capture_output=True, text=True)
    if r.returncode == 0:
        state = re.search(r"state = (\S+)", r.stdout)
        pid = re.search(r"\bpid = (\d+)", r.stdout)
        print(f"agent: {state.group(1) if state else '?'}" + (f" (pid {pid.group(1)})" if pid else ""))
    else:
        print("agent: not loaded")
    if not DB_PATH.exists():
        print("no database yet")
        return
    db = open_db()
    size = sum(p.stat().st_size for p in DB_PATH.parent.glob(DB_PATH.name + "*"))
    n, first, last, sc, d = db.execute(
        "SELECT COUNT(*), MIN(ts), MAX(ts), SUM(self_cpu_s), SUM(dur) FROM samples").fetchone()
    print(f"db: {DB_PATH} ({size / 2**20:.1f} MB), {n} samples")
    if n:
        print(f"first {fmt_ts(first)}, last {fmt_ts(last)} ({time.time() - last:.0f}s ago)")
        print(f"sampler cost: {sc:.1f} cpu-s over {d / 60:.0f} min = {100 * sc / d:.2f}% of one core")
        h = db.execute("SELECT SUM(self_cpu_s), SUM(dur) FROM samples WHERE ts > ?", (time.time() - 3600,)).fetchone()
        if h[1]:
            pk = db.execute("SELECT MAX(100.0*self_cpu_s/dur) FROM samples WHERE ts > ? AND dur > 0",
                            (time.time() - 3600,)).fetchone()[0]
            print(f"last hour:    {100 * h[0] / h[1]:.2f}% avg, {pk:.2f}% peak sample; peak RSS "
                  f"{db.execute('SELECT MAX(self_rss_mb) FROM samples').fetchone()[0]:.0f} MB")


# ---------------------------------------------------------------- report

def fmt_ts(ts: float, f: str = "%Y-%m-%d %H:%M:%S") -> str:
    return dt.datetime.fromtimestamp(ts).strftime(f)


def parse_when(s: str, now: dt.datetime, end: bool = False) -> float:
    s = s.strip().lower()
    today = now.replace(hour=0, minute=0, second=0, microsecond=0)
    if s == "now":
        return now.timestamp()
    if s == "today":
        return (today + dt.timedelta(days=1 if end else 0)).timestamp()
    if s == "yesterday":
        return (today - dt.timedelta(days=0 if end else 1)).timestamp()
    m = re.fullmatch(r"(\d+(?:\.\d+)?)\s*([smhdw])", s)
    if m:
        mult = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}[m.group(2)]
        return now.timestamp() - float(m.group(1)) * mult
    if re.fullmatch(r"\d{1,2}:\d{2}", s):   # a time today
        hh, mm = map(int, s.split(":"))
        return today.replace(hour=hh, minute=mm).timestamp()
    t = dt.datetime.fromisoformat(s)
    if end and len(s) <= 10:   # a bare date as --until means the end of that day
        t += dt.timedelta(days=1)
    return t.timestamp()


def cmd_report(a):
    if not DB_PATH.exists():
        sys.exit(f"no database at {DB_PATH}")
    db = open_db()
    now = dt.datetime.now()
    since = parse_when(a.since, now)
    until = parse_when(a.until, now, end=True) if a.until else now.timestamp()
    if a.since.lower() in ("today", "yesterday") and not a.until:
        until = parse_when(a.since, now, end=True)
    sections = [s.strip() for s in a.sections.split(",")]
    out: dict = {"since": fmt_ts(since), "until": fmt_ts(min(until, now.timestamp()))}
    raw_floor = time.time() - RAW_DAYS * 86400
    use_hourly = since < raw_floor
    W = (since, until)
    appf = ""
    appargs: tuple = ()
    if a.app:
        appf = " AND app LIKE ?"
        appargs = (f"%{a.app}%",)

    sysrow = db.execute("SELECT COUNT(*), SUM(dur), SUM(host_cpu_s), SUM(seen_cpu_s), AVG(gpu_dev), SUM(self_cpu_s) "
                        "FROM samples WHERE ts>=? AND ts<?", W).fetchone()
    if use_hourly:
        sysrow = db.execute("SELECT COUNT(*), SUM(dur), SUM(host_cpu_s), SUM(seen_cpu_s), AVG(gpu_avg), SUM(self_cpu_s) "
                            "FROM hourly_sys WHERE hour>=? AND hour<?", W).fetchone()
    n, dur, host, seen, gpu, selfc = [x or 0 for x in sysrow]
    peak = db.execute("SELECT MAX(100.0*self_cpu_s/dur) FROM samples WHERE ts>=? AND ts<? AND dur>0", W).fetchone()[0]
    over = db.execute("SELECT COUNT(*), COALESCE(SUM(seen_cpu_s-host_cpu_s),0) FROM samples WHERE ts>=? AND ts<? "
                      "AND seen_cpu_s > host_cpu_s*1.5 + 5", W).fetchone()
    out["summary"] = {"samples": n, "minutes": round(dur / 60, 1), "total_cpu_s": round(host, 1),
                      "avg_cores_busy": round(host / dur, 2) if dur else 0,
                      "attributed_cpu_s": round(seen, 1), "unattributed_cpu_s": round(max(host - seen, 0), 1),
                      "gpu_avg_pct": round(gpu, 1), "logger_avg_pct": round(100 * selfc / dur, 3) if dur else 0,
                      "logger_peak_pct": round(peak or 0, 3), "logger_cpu_s": round(selfc, 2),
                      "overcounted_samples": over[0], "overcounted_cpu_s": round(over[1], 1)}
    if seen > host * 1.02 and host:
        out["summary"]["warning"] = (f"attributed CPU is {seen / host:.2f}x the machine's busy CPU; "
                                     f"run `usagemon.py repair` to trim the overcounted rows")

    if "top" in sections:
        tbl, tcol = ("hourly_app", "hour") if use_hourly else ("app_cpu", "ts")
        rows = db.execute(f"SELECT app, via, SUM(cpu_s), SUM(gpu_s) FROM {tbl} WHERE {tcol}>=? AND {tcol}<?{appf} "
                          f"GROUP BY app, via ORDER BY 3 DESC LIMIT ?", (*W, *appargs, a.limit)).fetchall()
        out["top_apps"] = [{"app": r[0], "via": r[1], "cpu_s": round(r[2], 1),
                            "avg_pct": round(100 * r[2] / dur, 1) if dur else 0,
                            "share_pct": round(100 * r[2] / host, 1) if host else 0,
                            "gpu_s": round(r[3], 1)} for r in rows]
    if "procs" in sections and not use_hourly:
        rows = db.execute(f"SELECT app, name, SUM(cpu_s), COUNT(DISTINCT pid), MAX(cpu_s) FROM proc_cpu "
                          f"WHERE ts>=? AND ts<?{appf} GROUP BY app, name ORDER BY 3 DESC LIMIT ?",
                          (*W, *appargs, a.limit)).fetchall()
        out["top_processes"] = [{"app": r[0], "process": r[1], "cpu_s": round(r[2], 1), "pids": r[3],
                                 "peak_pct": round(100 * r[4] / SAMPLE_INTERVAL)} for r in rows]
    if "hourly" in sections:
        hours = db.execute("SELECT CAST(ts/3600 AS INT)*3600 h, SUM(host_cpu_s), SUM(dur), AVG(gpu_dev), MAX(gpu_dev) "
                           "FROM samples WHERE ts>=? AND ts<? GROUP BY h", W).fetchall()
        if use_hourly:
            hours = db.execute("SELECT hour, host_cpu_s, dur, gpu_avg, gpu_max FROM hourly_sys "
                               "WHERE hour>=? AND hour<?", W).fetchall()
        tbl, tcol = ("hourly_app", "hour") if use_hourly else ("app_cpu", "ts")
        tops = defaultdict(list)
        for h, app, c in db.execute(f"SELECT CAST({tcol}/3600 AS INT)*3600 h, app, SUM(cpu_s) FROM {tbl} "
                                    f"WHERE {tcol}>=? AND {tcol}<?{appf} GROUP BY h, app ORDER BY h, 3 DESC",
                                    (*W, *appargs)):
            if len(tops[h]) < 3:
                tops[h].append((app, c))
        out["hourly"] = [{"hour": fmt_ts(h, "%m-%d %H:00"), "cpu_s": round(c, 0),
                          "avg_cores": round(c / d, 2) if d else 0, "gpu_avg": round(g or 0), "gpu_max": gm or 0,
                          "top": ", ".join(f"{x} {y:.0f}s" for x, y in tops.get(h, []))}
                         for h, c, d, g, gm in hours]
    if "docker" in sections:
        tbl, tcol, mcol = ("hourly_docker", "hour", "avg_mem_mb") if use_hourly else ("docker", "ts", "mem_mb")
        rows = db.execute(f"SELECT container, SUM(cpu_s), AVG({mcol}), MAX({mcol}) FROM {tbl} "
                          f"WHERE {tcol}>=? AND {tcol}<? GROUP BY container ORDER BY 2 DESC LIMIT ?",
                          (*W, a.limit)).fetchall()
        out["docker"] = [{"container": r[0], "cpu_s": round(r[1], 1),
                          "avg_pct": round(100 * r[1] / dur, 1) if dur else 0,
                          "avg_mem_mb": round(r[2] or 0), "max_mem_mb": round(r[3] or 0)} for r in rows]
    if "gpu" in sections:
        span = until - since
        bucket = a.bucket or (60 if span <= 7200 else 300 if span <= 86400 else 3600)
        rows = db.execute("SELECT CAST(ts/? AS INT)*? b, AVG(gpu_dev), MAX(gpu_dev) FROM samples "
                          "WHERE ts>=? AND ts<? AND gpu_dev IS NOT NULL GROUP BY b ORDER BY b",
                          (bucket, bucket, *W)).fetchall()
        gtop = defaultdict(list)
        for b, app, g in db.execute("SELECT CAST(ts/? AS INT)*? b, app, SUM(gpu_s) FROM app_cpu "
                                    "WHERE ts>=? AND ts<? AND gpu_s>0 GROUP BY b, app ORDER BY b, 3 DESC",
                                    (bucket, bucket, *W)):
            if len(gtop[b]) < 2:
                gtop[b].append((app, 100 * g / bucket))
        out["gpu_timeline"] = [{"time": fmt_ts(b, "%m-%d %H:%M"), "avg": round(avg or 0), "max": mx or 0,
                                "top": ", ".join(f"{x} {y:.0f}%" for x, y in gtop.get(b, []))}
                               for b, avg, mx in rows]
        out["gpu_top_apps"] = [{"app": r[0], "gpu_s": round(r[1], 1), "avg_pct": round(100 * r[1] / dur, 1) if dur else 0}
                               for r in db.execute("SELECT app, SUM(gpu_s) FROM app_cpu WHERE ts>=? AND ts<? "
                                                   "GROUP BY app HAVING SUM(gpu_s)>0 ORDER BY 2 DESC LIMIT ?",
                                                   (*W, a.limit))]
    if "mem" in sections:
        out.update(mem_report(db, W, until - since, a, use_hourly))
    if "spikes" in sections:
        out["spikes"] = find_spikes(db, W, a.spike_pct, a.limit, appf, appargs)
    if "unattributed" in sections or "summary" in sections:
        pass

    if a.format == "json":
        print(json.dumps(out, indent=2))
    elif a.format == "csv":
        w = csv.writer(sys.stdout)
        for name, rows in out.items():
            if isinstance(rows, dict):
                rows = [rows]
            if isinstance(rows, list) and rows:
                w.writerow([f"# {name}"])
                w.writerow(rows[0].keys())
                for r in rows:
                    w.writerow(r.values())
    else:
        print_text(out)


def mem_report(db, W, span: float, a, use_hourly: bool) -> dict:
    """Memory: machine summary, top apps by average and peak footprint, and a timeline."""
    gb = lambda mb: round((mb or 0) / 1024, 1)  # noqa: E731
    appf, appargs = (" AND app LIKE ?", (f"%{a.app}%",)) if a.app else ("", ())
    if use_hourly:
        s = db.execute("SELECT COUNT(*), AVG(avg_used_mb), MAX(max_used_mb), MAX(max_pressure), MAX(max_swap_used_mb), "
                       "AVG(avg_compressed_mb), MAX(max_compressed_mb), SUM(swapout_mb), SUM(pageout_mb), MIN(min_free_mb) "
                       "FROM hourly_sysmem WHERE hour>=? AND hour<?", W).fetchone()
        apps = db.execute(f"SELECT app, SUM(avg_fp_mb)/(SELECT COUNT(*) FROM hourly_sysmem WHERE hour>=? AND hour<?), "
                          f"MAX(max_fp_mb), AVG(avg_rss_mb), NULL FROM hourly_mem WHERE hour>=? AND hour<?{appf} "
                          f"GROUP BY app ORDER BY 2 DESC LIMIT ?", (*W, *W, *appargs, a.limit)).fetchall()
    else:
        s = db.execute("SELECT COUNT(*), AVG(used_mb), MAX(used_mb), MAX(pressure), MAX(swap_used_mb), "
                       "AVG(compressed_mb), MAX(compressed_mb), SUM(swapout_mb), SUM(pageout_mb), MIN(free_mb) "
                       "FROM sysmem WHERE ts>=? AND ts<?", W).fetchone()
        nsnap = db.execute("SELECT COUNT(DISTINCT ts) FROM mem WHERE ts>=? AND ts<?", W).fetchone()[0] or 1
        apps = db.execute(f"SELECT app, SUM(COALESCE(fp_mb, rss_mb))/?, MAX(COALESCE(fp_mb, rss_mb)), "
                          f"SUM(rss_mb)/?, MAX(nproc) FROM mem WHERE ts>=? AND ts<?{appf} "
                          f"GROUP BY app ORDER BY 2 DESC LIMIT ?", (nsnap, nsnap, *W, *appargs, a.limit)).fetchall()
    n, used, used_max, pmax, swap_max, comp, comp_max, swapout, pageout, free_min = s
    out = {"mem_summary": {"ram_gb": gb(MEM_TOTAL / 2**20), "readings": n, "avg_used_gb": gb(used),
                           "peak_used_gb": gb(used_max), "max_pressure": PRESSURE.get(pmax, pmax or "-"),
                           "avg_compressed_gb": gb(comp), "peak_compressed_gb": gb(comp_max),
                           "peak_swap_used_gb": gb(swap_max), "swapped_out_gb": gb(swapout),
                           "paged_out_gb": gb(pageout), "min_free_gb": gb(free_min)}}
    out["mem_top_apps"] = [{"app": r[0], "avg_footprint_mb": round(r[1] or 0), "peak_footprint_mb": round(r[2] or 0),
                            "avg_rss_mb": round(r[3] or 0), "max_procs": r[4] if r[4] is not None else ""}
                           for r in apps]
    bucket = a.bucket or (60 if span <= 7200 else 300 if span <= 86400 else 3600)
    if use_hourly:
        bucket = max(bucket, 3600)
        rows = db.execute("SELECT CAST(hour/? AS INT)*? b, MAX(max_pressure), AVG(avg_used_mb), AVG(avg_compressed_mb), "
                          "MAX(max_swap_used_mb), MIN(min_free_mb), SUM(swapout_mb) FROM hourly_sysmem "
                          "WHERE hour>=? AND hour<? GROUP BY b ORDER BY b", (bucket, bucket, *W)).fetchall()
        tops = {}
    else:
        rows = db.execute("SELECT CAST(ts/? AS INT)*? b, MAX(pressure), AVG(used_mb), AVG(compressed_mb), "
                          "MAX(swap_used_mb), MIN(free_mb), SUM(swapout_mb) FROM sysmem "
                          "WHERE ts>=? AND ts<? GROUP BY b ORDER BY b", (bucket, bucket, *W)).fetchall()
        tops = defaultdict(list)
        for b, app, fp in db.execute("SELECT CAST(ts/? AS INT)*? b, app, MAX(COALESCE(fp_mb, rss_mb)) FROM mem "
                                     "WHERE ts>=? AND ts<? AND app!='(other)' GROUP BY b, app ORDER BY b, 3 DESC",
                                     (bucket, bucket, *W)):
            if len(tops[b]) < 2:
                tops[b].append((app, fp))
    out["mem_timeline"] = [{"time": fmt_ts(b, "%m-%d %H:%M"), "pressure": PRESSURE.get(p, p),
                            "used_gb": gb(u), "compressed_gb": gb(c), "swap_gb": gb(sw), "free_gb": gb(fr),
                            "swapout_mb": round(so or 0),
                            "top": ", ".join(f"{x} {y / 1024:.1f}G" for x, y in tops.get(b, []))}
                           for b, p, u, c, sw, fr, so in rows]
    return out


def find_spikes(db, W, pct: float, limit: int, appf: str, appargs: tuple):
    """Runs of consecutive samples where one app used >= pct% of a core, ranked by cpu-s,
    with the app's median rate over the preceding hour as a baseline."""
    rows = db.execute(f"SELECT ts, app, SUM(cpu_s) FROM app_cpu WHERE ts>=? AND ts<?{appf} GROUP BY ts, app ORDER BY ts",
                      (*W, *appargs)).fetchall()
    sample_ts = [r[0] for r in db.execute("SELECT ts FROM samples WHERE ts>=? AND ts<? ORDER BY ts", W)]
    idx = {t: i for i, t in enumerate(sample_ts)}
    durs = dict(db.execute("SELECT ts, dur FROM samples WHERE ts>=? AND ts<?", W).fetchall())
    runs = []
    open_runs: dict[str, dict] = {}
    for ts, app, cpu in rows:
        d = durs.get(ts) or SAMPLE_INTERVAL
        rate = 100 * cpu / d
        if rate < pct:
            continue
        r = open_runs.get(app)
        i = idx.get(ts, -1)
        if r and r["last_i"] == i - 1:
            r["end"] = ts
            r["last_i"] = i
            r["cpu"] += cpu
            r["peak"] = max(r["peak"], rate)
            r["n"] += 1
        else:
            if r:
                runs.append(r)
            open_runs[app] = {"app": app, "start": ts - d, "end": ts, "last_i": i, "cpu": cpu, "peak": rate, "n": 1}
    runs += open_runs.values()
    runs.sort(key=lambda r: -r["cpu"])
    res = []
    for r in runs[:limit]:
        prev = [c for (c,) in db.execute("SELECT SUM(cpu_s) FROM app_cpu WHERE app=? AND ts>=? AND ts<? GROUP BY ts",
                                         (r["app"], r["start"] - 3600, r["start"]))]
        nprev = db.execute("SELECT COUNT(*) FROM samples WHERE ts>=? AND ts<?", (r["start"] - 3600, r["start"])).fetchone()[0]
        prev += [0.0] * max(nprev - len(prev), 0)
        base = 100 * statistics.median(prev) / SAMPLE_INTERVAL if prev else 0
        top = db.execute("SELECT name, SUM(cpu_s) FROM proc_cpu WHERE app=? AND ts>? AND ts<=? GROUP BY name "
                         "ORDER BY 2 DESC LIMIT 2", (r["app"], r["start"], r["end"])).fetchall()
        res.append({"app": r["app"], "start": fmt_ts(r["start"], "%m-%d %H:%M:%S"),
                    "seconds": round(r["end"] - r["start"]), "cpu_s": round(r["cpu"], 1),
                    "avg_pct": round(100 * r["cpu"] / (r["end"] - r["start"])), "peak_pct": round(r["peak"]),
                    "baseline_pct": round(base, 1),
                    "top": ", ".join(f"{n} {c:.0f}s" for n, c in top)})
    return res


def table(rows: list[dict], cols: list[str] | None = None):
    if not rows:
        print("  (none)")
        return
    cols = cols or list(rows[0].keys())
    width = {c: max(len(c), *(len(str(r.get(c, ""))) for r in rows)) for c in cols}
    width = {c: min(w, 60) for c, w in width.items()}
    num = {c: all(isinstance(r.get(c), (int, float)) for r in rows) for c in cols}
    line = lambda vals: "  " + "  ".join((str(v)[:60].rjust(width[c]) if num[c] else str(v)[:60].ljust(width[c]))  # noqa: E731
                                         for c, v in zip(cols, vals))
    print(line(cols))
    for r in rows:
        print(line([r.get(c, "") for c in cols]))


def print_text(out: dict):
    s = out["summary"]
    print(f"mac-usage-monitor report  {out['since']} → {out['until']}")
    print(f"  {s['samples']} samples over {s['minutes']} min; CPU {s['total_cpu_s']} cpu-s "
          f"(avg {s['avg_cores_busy']} cores busy of {NCPU}); attributed {s['attributed_cpu_s']}, "
          f"unattributed {s['unattributed_cpu_s']}; GPU avg {s['gpu_avg_pct']}%")
    print(f"  logger: {s['logger_avg_pct']:.2f}% avg, {s['logger_peak_pct']:.2f}% peak of one core "
          f"({s['logger_cpu_s']} cpu-s; budget {BUDGET_PCT}%)")
    if s.get("overcounted_samples"):
        print(f"  ! {s['overcounted_samples']} samples attribute more CPU than the machine used "
              f"(+{s['overcounted_cpu_s']} cpu-s)")
    if s.get("warning"):
        print(f"  ! {s['warning']}")
    titles = {"top_apps": "Top apps by CPU (avg_pct: % of one core over the window)",
              "top_processes": "Top processes", "hourly": "Hourly", "docker": "Docker containers",
              "gpu_top_apps": "Top apps by GPU time", "gpu_timeline": "GPU utilisation timeline (Device %)",
              "mem_top_apps": "Top apps by memory (footprint, as Activity Monitor's Memory column)",
              "mem_timeline": "Memory timeline",
              "spikes": "Spikes (runs where one app was above the threshold)"}
    if "mem_summary" in out:
        m = out["mem_summary"]
        print(f"\nMemory: {m['ram_gb']} GB RAM; used avg {m['avg_used_gb']} GB, peak {m['peak_used_gb']} GB; "
              f"pressure max {m['max_pressure']}; compressed avg {m['avg_compressed_gb']} GB, "
              f"peak {m['peak_compressed_gb']} GB; swap peak {m['peak_swap_used_gb']} GB, "
              f"swapped out {m['swapped_out_gb']} GB; free min {m['min_free_gb']} GB")
    for k, title in titles.items():
        if k in out:
            print(f"\n{title}")
            table(out[k])


def cmd_repair(a):
    """Trim rows recorded by older builds that attributed more CPU than the machine used:
    the excess comes out of "(children of X)" rows first, then every row in the sample,
    and no app keeps more than NCPU x the sample length. Hourly rollups are rebuilt."""
    if not DB_PATH.exists():
        sys.exit(f"no database at {DB_PATH}")
    db = open_db()
    since = parse_when(a.since, dt.datetime.now()) if a.since else 0
    if not a.dry_run:
        bak = DB_PATH.with_name(f"usage.db.bak-{int(time.time())}")
        with sqlite3.connect(bak) as b:
            db.backup(b)
        print(f"backup: {bak}")
    fixed, removed, first_fixed = 0, 0.0, None
    samples = db.execute("SELECT ts, dur, host_cpu_s, seen_cpu_s FROM samples WHERE ts>=? ORDER BY ts",
                         (since,)).fetchall()
    with db:
        for ts, dur, host, seen in samples:
            # Polls and samples are not aligned, so a normal sample can run a little over
            # the machine counter. Only a clear overcount is trimmed, and then to the
            # machine's own busy CPU for that sample.
            avail = host
            excess = seen - host if seen > host * 1.5 + 5 else 0.0
            lim = NCPU * (dur or SAMPLE_INTERVAL)
            over_app = db.execute("SELECT COUNT(*) FROM app_cpu WHERE ts=? AND cpu_s>?", (ts, lim)).fetchone()[0]
            if excess > 0 or over_app:
                if excess > 0:
                    kids = db.execute("SELECT rowid, app, via, cpu_s FROM proc_cpu WHERE ts=? "
                                      "AND name LIKE '(children of %'", (ts,)).fetchall()
                    tot = sum(r[3] for r in kids)
                    if tot > 0:
                        f = max(0.0, 1 - excess / tot)
                        red = defaultdict(float)
                        for rid, app, via, c in kids:
                            db.execute("UPDATE proc_cpu SET cpu_s=? WHERE rowid=?", (c * f, rid))
                            red[(app, via)] += c * (1 - f)
                        for (app, via), r in red.items():
                            row = db.execute("SELECT rowid, cpu_s FROM app_cpu WHERE ts=? AND app=? AND via=?",
                                             (ts, app, via)).fetchone() or \
                                  db.execute("SELECT rowid, cpu_s FROM app_cpu WHERE ts=? AND app='(other)'",
                                             (ts,)).fetchone()
                            if row:
                                db.execute("UPDATE app_cpu SET cpu_s=? WHERE rowid=?", (max(0.0, row[1] - r), row[0]))
                    total = db.execute("SELECT COALESCE(SUM(cpu_s),0) FROM app_cpu WHERE ts=?", (ts,)).fetchone()[0]
                    excess = total - avail
                    if excess > 0 and total > 0:
                        g = max(0.0, 1 - excess / total)
                        db.execute("UPDATE app_cpu SET cpu_s=cpu_s*? WHERE ts=?", (g, ts))
                        db.execute("UPDATE proc_cpu SET cpu_s=cpu_s*? WHERE ts=?", (g, ts))
                for app, c in db.execute("SELECT app, SUM(cpu_s) FROM app_cpu WHERE ts=? GROUP BY app HAVING SUM(cpu_s)>?",
                                         (ts, lim)).fetchall():
                    db.execute("UPDATE app_cpu SET cpu_s=cpu_s*? WHERE ts=? AND app=?", (lim / c, ts, app))
                    db.execute("UPDATE proc_cpu SET cpu_s=cpu_s*? WHERE ts=? AND app=?", (lim / c, ts, app))
                new = db.execute("SELECT COALESCE(SUM(cpu_s),0) FROM app_cpu WHERE ts=?", (ts,)).fetchone()[0]
                db.execute("UPDATE samples SET seen_cpu_s=? WHERE ts=?", (new, ts))
                fixed += 1
                removed += seen - new
                first_fixed = first_fixed or ts
                seen = new
        if a.dry_run:
            db.rollback()
    print(f"{'would trim' if a.dry_run else 'trimmed'} {fixed} samples, {removed:.0f} cpu-s removed")
    if fixed and not a.dry_run:
        hour = int(first_fixed // 3600 * 3600)
        with db:
            db.execute("INSERT OR REPLACE INTO meta VALUES('rolled_until', ?)", (str(hour),))
        rollup_and_prune(db)
        print(f"hourly rollups rebuilt from {fmt_ts(hour)}")


# ---------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("run", help="run the sampler in the foreground")
    sub.add_parser("install", help="install and start the launchd agent")
    sub.add_parser("uninstall", help="stop and remove the launchd agent")
    sub.add_parser("status", help="agent state and sampler cost")
    rp = sub.add_parser("repair", help="trim rows that attribute more CPU than the machine used")
    rp.add_argument("--since", help="only samples from this time (default: all)")
    rp.add_argument("--dry-run", action="store_true")
    r = sub.add_parser("report", help="usage report")
    r.add_argument("--since", default="1h", help="1h, 30m, 2d, today, yesterday, 14:00, 2026-11-03, '2026-11-03 14:00' (default 1h)")
    r.add_argument("--until", default=None, help="same formats; default now (or end of day for today/yesterday)")
    r.add_argument("--sections", default="top,procs,hourly,docker,gpu,mem,spikes",
                   help="comma list of: top,procs,hourly,docker,gpu,mem,spikes")
    r.add_argument("--app", default=None, help="only apps whose name contains this")
    r.add_argument("--limit", type=int, default=15)
    r.add_argument("--spike-pct", type=float, default=100.0, help="spike threshold in %% of one core (default 100)")
    r.add_argument("--bucket", type=int, default=0, help="GPU timeline bucket seconds (default by window)")
    r.add_argument("--format", choices=["text", "json", "csv"], default="text")
    a = ap.parse_args()
    if a.cmd == "run":
        Sampler(open_db()).run()
    elif a.cmd == "install":
        cmd_install(a)
    elif a.cmd == "uninstall":
        cmd_uninstall(a)
    elif a.cmd == "status":
        cmd_status(a)
    elif a.cmd == "report":
        cmd_report(a)
    elif a.cmd == "repair":
        cmd_repair(a)


if __name__ == "__main__":
    main()
