#!/usr/bin/env python3
"""
process_audit.py — Cross-platform process audit report generator.

Usage:
  sudo python3 process_audit.py [options]

Options:
  --output FILE, -o FILE     Write JSON to FILE instead of stdout
  --match GLOB, -m GLOB      Only report processes whose name, exe, or cmdline
                             matches this glob pattern (e.g. 'python*', '*nginx*')
  --trace                    Enable sampling-based tracing window
  --trace-duration SECS      Tracing window length in seconds (default: 30)
  --compact                  Compact (non-indented) JSON output

Sentinel values in output:
  "EOR_INCOMPLETE"
      Data collection aborted due to an unexpected error mid-field.
  "PERMISSION_DENIED"
      The field required elevated privileges not available at runtime.

Requirements: Python 3.6+, psutil >= 5.x  (pip install psutil)
Run as root for full process visibility across all users.
"""

import argparse
import collections
import concurrent.futures
import fnmatch
import gzip
import io
import json
import os
import platform
import pwd
import re
import socket
import struct
import sys
import tempfile
import threading
import time
import traceback
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    import psutil
except ImportError:
    sys.exit("psutil is required: pip install psutil")

EOR_INCOMPLETE: str = "EOR_INCOMPLETE"
PERM_DENIED: str = "PERMISSION_DENIED"

IS_LINUX = sys.platform.startswith("linux")


def _now_iso(ts: Optional[float] = None) -> str:
    t = ts if ts is not None else time.time()
    return datetime.fromtimestamp(t, tz=timezone.utc).isoformat()


def _human_duration(secs: float) -> str:
    s = int(max(secs, 0))
    if s < 60:
        return f"{s}s"
    if s < 3600:
        m, sec = divmod(s, 60)
        return f"{m}m {sec}s"
    h, rem = divmod(s, 3600)
    m, sec = divmod(rem, 60)
    return f"{h}h {m}m {sec}s"


def _safe(fn, perm_sentinel=False):
    """Call fn(); return EOR_INCOMPLETE or PERM_DENIED on failure."""
    try:
        return fn()
    except (psutil.AccessDenied, PermissionError):
        return PERM_DENIED if perm_sentinel else PERM_DENIED
    except (psutil.NoSuchProcess, ProcessLookupError):
        return EOR_INCOMPLETE
    except Exception:
        return EOR_INCOMPLETE


def _load_syscall_table() -> Dict[int, str]:
    """Parse x86_64 syscall numbers from system headers; fall back to a compact built-in table."""
    candidates = [
        "/usr/include/x86_64-linux-gnu/asm/unistd_64.h",
        "/usr/include/asm/unistd_64.h",
        "/usr/include/asm-generic/unistd.h",
    ]
    for path in candidates:
        try:
            with open(path) as fh:
                content = fh.read()
            table = {}
            for m in re.finditer(r"#define __NR_(\w+)\s+(\d+)", content):
                table[int(m.group(2))] = m.group(1)
            if table:
                return table
        except FileNotFoundError:
            continue
    return {
        0: "read", 1: "write", 2: "open", 3: "close", 4: "stat",
        5: "fstat", 6: "lstat", 7: "poll", 8: "lseek", 9: "mmap",
        10: "mprotect", 11: "munmap", 12: "brk", 17: "pread64",
        18: "pwrite64", 23: "select", 28: "madvise", 41: "socket",
        42: "connect", 43: "accept", 44: "sendto", 45: "recvfrom",
        46: "sendmsg", 47: "recvmsg", 48: "shutdown", 49: "bind",
        50: "listen", 56: "clone", 59: "execve", 60: "exit",
        61: "wait4", 62: "kill", 72: "fcntl", 78: "getdents",
        79: "getcwd", 186: "gettid", 202: "futex", 228: "clock_gettime",
        231: "exit_group", 232: "epoll_wait", 257: "openat",
        281: "epoll_pwait", 290: "accept4", 318: "getrandom",
    }


SYSCALL_TABLE: Dict[int, str] = _load_syscall_table() if IS_LINUX else {}


def _syscall_name(num_str: str) -> str:
    try:
        return SYSCALL_TABLE.get(int(num_str), f"syscall_{num_str}")
    except (ValueError, TypeError):
        return str(num_str)


def _service_name(port: int, proto: str = "tcp") -> Optional[str]:
    try:
        return socket.getservbyport(port, proto)
    except OSError:
        return None


def _format_connection(conn) -> dict:
    proto = "UDP" if conn.type == socket.SOCK_DGRAM else "TCP"
    family = "IPv6" if conn.family == socket.AF_INET6 else "IPv4"
    laddr = raddr = None
    if conn.laddr:
        laddr = {
            "ip": conn.laddr.ip,
            "port": conn.laddr.port,
            "service": _service_name(conn.laddr.port, proto.lower()),
        }
    if conn.raddr:
        raddr = {
            "ip": conn.raddr.ip,
            "port": conn.raddr.port,
            "service": _service_name(conn.raddr.port, proto.lower()),
        }
    return {
        "fd": conn.fd if conn.fd and conn.fd > 0 else None,
        "protocol": proto,
        "family": family,
        "state": conn.status or None,
        "local": laddr,
        "remote": raddr,
    }


def _get_open_files(pid: int) -> Any:
    """Return open file descriptors with full paths, categorised by type."""
    regular = []
    sockets = []
    pipes = []
    other = []

    fd_dir = f"/proc/{pid}/fd" if IS_LINUX else None

    if fd_dir and os.path.isdir(fd_dir):
        try:
            fds = os.listdir(fd_dir)
        except PermissionError:
            return PERM_DENIED
        except OSError:
            return EOR_INCOMPLETE

        for fd_name in fds:
            fd_path = f"{fd_dir}/{fd_name}"
            try:
                link = os.readlink(fd_path)
            except (PermissionError, FileNotFoundError):
                continue

            entry = {"fd": int(fd_name), "path": link}

            if link.startswith("socket:["):
                entry["inode"] = int(link[8:-1])
                sockets.append(entry)
            elif link.startswith("pipe:["):
                entry["inode"] = int(link[6:-1])
                pipes.append(entry)
            elif link.startswith("anon_inode:"):
                entry["type"] = link[11:]
                other.append(entry)
            else:
                try:
                    st = os.stat(fd_path)
                    entry["size_bytes"] = st.st_size
                except OSError:
                    pass
                regular.append(entry)
    else:
        try:
            p = psutil.Process(pid)
            for f in p.open_files():
                regular.append({"fd": f.fd, "path": f.path})
        except psutil.AccessDenied:
            return PERM_DENIED
        except (psutil.NoSuchProcess, Exception):
            return EOR_INCOMPLETE

    return {"regular": regular, "sockets": sockets,
            "pipes": pipes, "other": other}


def _get_connections(pid: int) -> Any:
    try:
        p = psutil.Process(pid)
        conns = p.net_connections()
        return [_format_connection(c) for c in conns]
    except psutil.AccessDenied:
        return PERM_DENIED
    except (psutil.NoSuchProcess, Exception):
        return EOR_INCOMPLETE


def _collect_process_snapshot(pid: int, now: float) -> dict:
    """Gather a point-in-time snapshot of a single process."""
    rec: dict = {"pid": pid}

    try:
        p = psutil.Process(pid)
    except psutil.NoSuchProcess:
        rec["error"] = EOR_INCOMPLETE
        return rec
    except psutil.AccessDenied:
        rec["error"] = PERM_DENIED
        return rec

    try:
        with p.oneshot():
            rec["name"] = _safe(p.name)
            rec["exe"] = _safe(p.exe)
            rec["cmdline"] = _safe(p.cmdline) or []
            rec["ppid"] = _safe(p.ppid)
            rec["status"] = _safe(p.status)
            rec["username"] = _safe(p.username)
            rec["nice"] = _safe(p.nice)
            rec["num_threads"] = _safe(p.num_threads)

            uids = _safe(p.uids)
            rec["uids"] = (
                {"real": uids.real, "effective": uids.effective, "saved": uids.saved}
                if uids not in (EOR_INCOMPLETE, PERM_DENIED) else uids
            )
            gids = _safe(p.gids)
            rec["gids"] = (
                {"real": gids.real, "effective": gids.effective, "saved": gids.saved}
                if gids not in (EOR_INCOMPLETE, PERM_DENIED) else gids
            )

            create_time = _safe(p.create_time)
            if create_time not in (EOR_INCOMPLETE, PERM_DENIED):
                uptime = now - create_time
                rec["started_at_iso"] = _now_iso(create_time)
                rec["uptime_secs"] = round(uptime, 3)
                rec["uptime_human"] = _human_duration(uptime)
            else:
                rec["started_at_iso"] = create_time
                rec["uptime_secs"] = create_time
                rec["uptime_human"] = create_time

            mem = _safe(p.memory_info)
            if mem not in (EOR_INCOMPLETE, PERM_DENIED):
                rec["memory"] = {
                    "rss_bytes": mem.rss,
                    "vms_bytes": mem.vms,
                    "rss_mb": round(mem.rss / 1_048_576, 2),
                    "vms_mb": round(mem.vms / 1_048_576, 2),
                    "percent": round(_safe(p.memory_percent) or 0, 4),
                }
                shared = getattr(mem, "shared", None)
                if shared is not None:
                    rec["memory"]["shared_bytes"] = shared
            else:
                rec["memory"] = mem

            cpu_times = _safe(p.cpu_times)
            if cpu_times not in (EOR_INCOMPLETE, PERM_DENIED):
                rec["cpu_times"] = {
                    "user_secs": cpu_times.user,
                    "system_secs": cpu_times.system,
                }
                iowait = getattr(cpu_times, "iowait", None)
                if iowait is not None:
                    rec["cpu_times"]["iowait_secs"] = iowait
            else:
                rec["cpu_times"] = cpu_times

            io = _safe(p.io_counters)
            if io not in (EOR_INCOMPLETE, PERM_DENIED):
                rec["io_counters"] = {
                    "read_count": io.read_count,
                    "write_count": io.write_count,
                    "read_bytes": io.read_bytes,
                    "write_bytes": io.write_bytes,
                }
            else:
                rec["io_counters"] = io

            ctx = _safe(p.num_ctx_switches)
            if ctx not in (EOR_INCOMPLETE, PERM_DENIED):
                rec["context_switches"] = {
                    "voluntary": ctx.voluntary,
                    "involuntary": ctx.involuntary,
                }
            else:
                rec["context_switches"] = ctx

    except (psutil.NoSuchProcess, psutil.AccessDenied):
        rec.setdefault("error", EOR_INCOMPLETE)
        return rec
    except Exception:
        rec["error"] = EOR_INCOMPLETE
        return rec

    rec["open_files"] = _get_open_files(pid)
    rec["connections"] = _get_connections(pid)

    return rec


def _trace_process(pid: int, duration: float, interval: float = 0.1) -> dict:
    """
    Sample a process over `duration` seconds and return aggregated trace data.
    Runs in its own thread; all I/O operations release the GIL.
    """
    result: dict = {
        "duration_secs": duration,
        "sample_interval_secs": interval,
        "syscall_summary": EOR_INCOMPLETE,
        "cpu_samples_percent": EOR_INCOMPLETE,
        "avg_cpu_percent": EOR_INCOMPLETE,
        "peak_cpu_percent": EOR_INCOMPLETE,
        "io_delta": EOR_INCOMPLETE,
        "net_addresses_seen": EOR_INCOMPLETE,
    }

    try:
        p = psutil.Process(pid)
    except psutil.AccessDenied:
        for k in result:
            result[k] = PERM_DENIED
        return result
    except psutil.NoSuchProcess:
        return result

    try:
        io_start = p.io_counters()
    except psutil.AccessDenied:
        io_start = None
    except Exception:
        io_start = None

    syscall_counts: collections.Counter = collections.Counter()
    cpu_samples: List[float] = []
    net_addrs_seen: Set[Tuple] = set()

    sc_path = f"/proc/{pid}/syscall" if IS_LINUX else None
    end_time = time.time() + duration

    while time.time() < end_time:
        if sc_path:
            try:
                with open(sc_path) as fh:
                    content = fh.read().strip()
                if content and content not in ("running", ""):
                    sc_num_str = content.split()[0]
                    syscall_counts[_syscall_name(sc_num_str)] += 1
            except PermissionError:
                syscall_counts["__permission_denied__"] += 1
            except (FileNotFoundError, ProcessLookupError):
                break
            except Exception:
                pass

        try:
            cpu_samples.append(p.cpu_percent())
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            break
        except Exception:
            pass

        try:
            for conn in p.net_connections():
                if conn.raddr and conn.raddr.ip:
                    proto = "UDP" if conn.type == socket.SOCK_DGRAM else "TCP"
                    net_addrs_seen.add((proto, conn.raddr.ip, conn.raddr.port))
        except psutil.AccessDenied:
            net_addrs_seen.add(("__permission_denied__",))
        except (psutil.NoSuchProcess, Exception):
            pass

        time.sleep(interval)

    if sc_path:
        if "__permission_denied__" in syscall_counts:
            result["syscall_summary"] = PERM_DENIED
        else:
            result["syscall_summary"] = dict(syscall_counts.most_common())
    else:
        result["syscall_summary"] = None

    if cpu_samples:
        result["cpu_samples_percent"] = cpu_samples
        result["avg_cpu_percent"] = round(
            sum(cpu_samples) / len(cpu_samples), 3)
        result["peak_cpu_percent"] = round(max(cpu_samples), 3)
    else:
        result["cpu_samples_percent"] = []
        result["avg_cpu_percent"] = None
        result["peak_cpu_percent"] = None

    if io_start is not None:
        try:
            io_end = p.io_counters()
            result["io_delta"] = {
                "read_bytes": io_end.read_bytes - io_start.read_bytes,
                "write_bytes": io_end.write_bytes - io_start.write_bytes,
                "read_count": io_end.read_count - io_start.read_count,
                "write_count": io_end.write_count - io_start.write_count,
            }
        except psutil.AccessDenied:
            result["io_delta"] = PERM_DENIED
        except Exception:
            result["io_delta"] = EOR_INCOMPLETE
    else:
        result["io_delta"] = EOR_INCOMPLETE

    perm_addr = ("__permission_denied__",) in net_addrs_seen
    clean_addrs = [a for a in net_addrs_seen if a[0]
                   != "__permission_denied__"]
    result["net_addresses_seen"] = [
        {"protocol": a[0], "ip": a[1], "port": a[2]} for a in sorted(clean_addrs)
    ]
    if perm_addr:
        result["net_addresses_seen_note"] = PERM_DENIED

    return result


def _matches_glob(proc: psutil.Process, pattern: str) -> bool:
    for fn in (proc.name, proc.exe, lambda: " ".join(proc.cmdline())):
        try:
            val = fn() or ""
            if fnmatch.fnmatch(val, pattern) or fnmatch.fnmatch(
                    os.path.basename(val), pattern):
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied, Exception):
            pass
    return False


class _StreamingJSONWriter:
    """Write a large JSON object incrementally to a file object, avoiding full in-memory assembly."""

    def __init__(self, fp, indent: int = 2):
        self._fp = fp
        self._indent = indent
        self._started = False

    def begin(self, preamble: dict):
        """Write the opening brace and all non-array top-level keys."""
        self._fp.write("{\n")
        items = list(preamble.items())
        for i, (k, v) in enumerate(items):
            self._fp.write(f'  {json.dumps(k)}: ')
            self._fp.write(json.dumps(v, indent=self._indent, default=str))
            self._fp.write(",\n")

    def begin_array(self, key: str):
        self._fp.write(f'  {json.dumps(key)}: [\n')
        self._started = False

    def write_record(self, record: dict):
        if self._started:
            self._fp.write(",\n")
        payload = json.dumps(record, indent=self._indent, default=str)
        indented = "\n".join("    " + line for line in payload.splitlines())
        self._fp.write(indented)
        self._started = True

    def end_array(self):
        self._fp.write("\n  ]")

    def end(self):
        self._fp.write("\n}\n")


def _worker_snapshot(args):
    pid, now = args
    try:
        return _collect_process_snapshot(pid, now)
    except Exception:
        return {"pid": pid, "error": EOR_INCOMPLETE}


def generate_report(
    match_glob: Optional[str] = None,
    trace: bool = False,
    trace_duration: float = 30.0,
    output_path: Optional[str] = None,
    pretty: bool = True,
    max_workers: int = 0,
) -> None:
    """
    Collect and stream the process audit report to output_path or stdout.
    Records are written incrementally so RAM usage stays bounded.
    Tracing runs one thread per process concurrently.
    """
    now = time.time()
    indent = 2 if pretty else None

    if max_workers <= 0:
        cpu_count = os.cpu_count() or 4
        max_workers = min(cpu_count * 2, 32)

    all_procs = list(psutil.process_iter(["pid"]))
    candidates = [
        p for p in all_procs
        if match_glob is None or _matches_glob(p, match_glob)
    ]
    pids = [p.pid for p in candidates]

    print(
        f"[process_audit] {len(pids)} processes selected"
        + (f" (glob={match_glob!r})" if match_glob else "")
        + (f", tracing {trace_duration}s" if trace else ""),
        file=sys.stderr,
    )

    preamble = {
        "report_metadata": {
            "generated_at_epoch": now,
            "generated_at_iso": _now_iso(now),
            "hostname": socket.gethostname(),
            "platform": sys.platform,
            "kernel": platform.release(),
            "uptime_secs": round(now - psutil.boot_time(), 1),
            "total_processes": len(all_procs),
            "reported_processes": len(pids),
            "glob_filter": match_glob,
            "tracing_enabled": trace,
            "tracing_duration_secs": trace_duration if trace else None,
            "worker_threads": max_workers,
        },
    }

    out_fp = open(output_path, "w") if output_path else sys.stdout
    writer = _StreamingJSONWriter(out_fp, indent=indent or 0)

    try:
        writer.begin(preamble)

        if trace:
            print("[process_audit] Starting trace window...", file=sys.stderr)
            trace_futures: Dict[int, concurrent.futures.Future] = {}
            trace_executor = concurrent.futures.ThreadPoolExecutor(
                max_workers=max_workers, thread_name_prefix="tracer"
            )
            for pid in pids:
                trace_futures[pid] = trace_executor.submit(
                    _trace_process, pid, trace_duration
                )

            print(
                f"[process_audit] Tracing {
                    len(pids)} processes for {trace_duration}s "
                "(snapshots will be collected in parallel during trace window)...",
                file=sys.stderr,
            )

            snap_futures: Dict[int, concurrent.futures.Future] = {}
            snap_executor = concurrent.futures.ThreadPoolExecutor(
                max_workers=max_workers, thread_name_prefix="snapper"
            )
            for pid in pids:
                snap_futures[pid] = snap_executor.submit(
                    _worker_snapshot, (pid, now))

            trace_executor.shutdown(wait=True)
            snap_executor.shutdown(wait=True)

            trace_results = {
                pid: f.result() for pid,
                f in trace_futures.items()}
            snap_results = {pid: f.result() for pid, f in snap_futures.items()}

            writer.begin_array("processes")
            for pid in pids:
                rec = snap_results.get(
                    pid, {"pid": pid, "error": EOR_INCOMPLETE})
                rec["trace"] = trace_results.get(pid, EOR_INCOMPLETE)
                writer.write_record(rec)
            writer.end_array()

        else:
            snap_futures: Dict[int, concurrent.futures.Future] = {}
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=max_workers, thread_name_prefix="snapper"
            ) as ex:
                for pid in pids:
                    snap_futures[pid] = ex.submit(_worker_snapshot, (pid, now))

            writer.begin_array("processes")
            for pid in pids:
                try:
                    rec = snap_futures[pid].result()
                except Exception:
                    rec = {"pid": pid, "error": EOR_INCOMPLETE}
                writer.write_record(rec)
            writer.end_array()

        writer.end()

    except Exception:
        try:
            out_fp.write(
                f'\n, "_fatal_error": {
                    json.dumps(EOR_INCOMPLETE)}\n}}\n')
        except Exception:
            pass
    finally:
        if output_path and out_fp is not sys.stdout:
            out_fp.close()

    if output_path:
        print(
            f"[process_audit] Report written to {output_path}",
            file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(
        description="Generate a cross-platform JSON process audit report.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--output", "-o", metavar="FILE",
                        help="Write JSON to FILE instead of stdout")
    parser.add_argument("--match", "-m", metavar="GLOB",
                        help="Only report processes matching this glob (name, exe, or cmdline)")
    parser.add_argument("--trace", action="store_true", default=False,
                        help="Enable sampling-based tracing window")
    parser.add_argument("--trace-duration", type=float, default=30.0, metavar="SECS",
                        help="Tracing window length in seconds (default: 30)")
    parser.add_argument("--compact", action="store_true", default=False,
                        help="Compact (non-indented) JSON output")
    parser.add_argument("--workers", type=int, default=0, metavar="N",
                        help="Thread pool size (default: 2 × CPU count, max 32)")
    args = parser.parse_args()

    generate_report(
        match_glob=args.match,
        trace=args.trace,
        trace_duration=args.trace_duration,
        output_path=args.output,
        pretty=not args.compact,
        max_workers=args.workers,
    )


if __name__ == "__main__":
    main()
