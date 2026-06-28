#!/usr/bin/env python3
"""
net_report.py — Cross-platform TCP/UDP socket audit report generator.

Produces a JSON report of every TCP and UDP socket on the system.
Works on Linux, macOS, FreeBSD, NetBSD, OpenBSD, and any other platform
supported by psutil.  On Linux, /proc/net/tcp and /proc/net/udp are read
for additional detail (queue depths, kernel timers, retransmit counts).

Requirements: Python 3.6+, psutil >= 5.x  (pip install psutil)
Run as root for full process visibility across all users.
"""

import gzip
import json
import os
import pwd
import socket
import struct
import sys
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

try:
    import psutil
except ImportError:
    sys.exit("psutil is required: pip install psutil")


TIMER_TYPES: Dict[str, str] = {
    "00": "none",
    "01": "retransmit",
    "02": "keepalive",
    "03": "TIME_WAIT",
    "04": "zero_window_probe",
}


def _detect_hz() -> int:
    candidates = [
        "/boot/config",
        f"/boot/config-{os.uname().release}",
        "/proc/config.gz",
    ]
    for path in candidates:
        try:
            opener = gzip.open if path.endswith(".gz") else open
            with opener(path, "rt") as fh:
                for line in fh:
                    line = line.strip()
                    if line.startswith("CONFIG_HZ=") and "CONFIG_HZ_" not in line:
                        return int(line.split("=", 1)[1])
        except Exception:
            continue
    return 100


def _hex_to_ip_port(hex_addr: str, hex_port: str) -> Tuple[str, int]:
    if len(hex_addr) == 8:
        raw = struct.pack("<I", int(hex_addr, 16))
        ip = socket.inet_ntop(socket.AF_INET, raw)
    elif len(hex_addr) == 32:
        raw = b"".join(struct.pack("<I", int(hex_addr[i:i+8], 16)) for i in range(0, 32, 8))
        ip = socket.inet_ntop(socket.AF_INET6, raw)
    else:
        raise ValueError(f"unexpected hex address length {len(hex_addr)}: {hex_addr!r}")
    return ip, int(hex_port, 16)


def _uid_to_username(uid: int) -> Optional[str]:
    try:
        return pwd.getpwuid(uid).pw_name
    except Exception:
        return None


def _service_name(port: int, proto: str = "tcp") -> Optional[str]:
    try:
        return socket.getservbyport(port, proto)
    except OSError:
        return None


def _rdns(ip: str) -> Optional[str]:
    if not ip or ip in ("0.0.0.0", "::", "::1", "127.0.0.1"):
        return None
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return None


def _human_duration(secs: float) -> str:
    s = int(secs)
    if s < 60:
        return f"{s}s"
    if s < 3600:
        m, sec = divmod(s, 60)
        return f"{m}m {sec}s"
    h, rem = divmod(s, 3600)
    m, sec = divmod(rem, 60)
    return f"{h}h {m}m {sec}s"


def _parse_proc_net(path: str, hz: int) -> Dict[Tuple, dict]:
    extras: Dict[Tuple, dict] = {}
    try:
        with open(path) as fh:
            lines = fh.readlines()
    except FileNotFoundError:
        return extras

    for line in lines[1:]:
        fields = line.split()
        if len(fields) < 10:
            continue
        try:
            local_ip, local_port = _hex_to_ip_port(*fields[1].split(":"))
            rem_ip, rem_port = _hex_to_ip_port(*fields[2].split(":"))
            tx_hex, rx_hex = fields[4].split(":")
            timer_hex, when_hex = fields[5].split(":")
            when_jiffies = int(when_hex, 16)
            when_secs = max(when_jiffies, 0) / hz if hz else None
            key = (local_ip, local_port, rem_ip, rem_port)
            extras[key] = {
                "tx_queue": int(tx_hex, 16),
                "rx_queue": int(rx_hex, 16),
                "timer_type": TIMER_TYPES.get(timer_hex, f"unknown({timer_hex})"),
                "timer_expires_secs": round(when_secs, 3) if when_secs is not None else None,
                "retransmits": int(fields[6], 16),
                "uid": int(fields[7]),
                "inode": int(fields[9]),
            }
        except (ValueError, IndexError):
            continue
    return extras


def _estimate_age(
    pid: Optional[int],
    fd: Optional[int],
    now: float,
) -> Tuple[Optional[float], Optional[str], str]:
    if pid and fd and fd > 0:
        fd_path = f"/proc/{pid}/fd/{fd}"
        try:
            st = os.lstat(fd_path)
            age = now - st.st_ctime
            return (
                round(age, 3),
                _human_duration(age),
                "proc_fd_ctime (lower-bound: time fd was last opened/dup'd)",
            )
        except (FileNotFoundError, PermissionError, OSError):
            pass

    if pid:
        try:
            p = psutil.Process(pid)
            age = now - p.create_time()
            return (
                round(age, 3),
                _human_duration(age),
            )
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    return None, None, "unavailable (no owning process or access denied)"


def _enrich_process(pid: Optional[int], fd: Optional[int]) -> Optional[dict]:
    if not pid:
        return None
    try:
        p = psutil.Process(pid)
        with p.oneshot():
            create_time = p.create_time()
            return {
                "pid": pid,
                "ppid": _safe(p.ppid),
                "name": _safe(p.name),
                "exe": _safe(p.exe),
                "cmdline": _safe(p.cmdline) or [],
                "username": _safe(p.username),
                "status": _safe(p.status),
                "process_create_time_epoch": create_time,
                "process_create_time_iso": datetime.fromtimestamp(
                    create_time, tz=timezone.utc
                ).isoformat() if create_time else None,
                "fd": fd if fd and fd > 0 else None,
            }
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return {"pid": pid, "error": "access_denied_or_exited"}


def _safe(method):
    try:
        return method()
    except (psutil.AccessDenied, psutil.NoSuchProcess, Exception):
        return None


def _format_addr(ip: Optional[str], port: Optional[int], proto: str,
                 resolve_dns: bool, resolve_services: bool) -> dict:
    hostname = None
    service = None
    if ip and resolve_dns:
        hostname = _rdns(ip)
    if port and resolve_services:
        service = _service_name(port, proto)
    return {
        "ip": ip or None,
        "port": port if port else None,
        "hostname": hostname,
        "service": service,
    }


def _gather_sockets(
    resolve_dns: bool,
    resolve_services: bool,
    now: float,
    hz: int,
) -> Tuple[List[dict], List[dict]]:
    is_linux = sys.platform.startswith("linux")

    tcp_extras: Dict[Tuple, dict] = {}
    udp_extras: Dict[Tuple, dict] = {}
    if is_linux:
        tcp_extras = _parse_proc_net("/proc/net/tcp", hz)
        tcp_extras.update(_parse_proc_net("/proc/net/tcp6", hz))
        udp_extras = _parse_proc_net("/proc/net/udp", hz)
        udp_extras.update(_parse_proc_net("/proc/net/udp6", hz))

    all_conns = []
    try:
        all_conns = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        try:
            all_conns = psutil.net_connections(kind="inet4")
        except psutil.AccessDenied:
            pass

    tcp_records: List[dict] = []
    udp_records: List[dict] = []

    for conn in all_conns:
        is_tcp = conn.type == socket.SOCK_STREAM
        is_udp = conn.type == socket.SOCK_DGRAM
        if not (is_tcp or is_udp):
            continue

        proto = "tcp" if is_tcp else "udp"
        laddr_ip = conn.laddr.ip if conn.laddr else None
        laddr_port = conn.laddr.port if conn.laddr else None
        raddr_ip = conn.raddr.ip if conn.raddr else None
        raddr_port = conn.raddr.port if conn.raddr else None
        is_ipv6 = conn.family == socket.AF_INET6
        norm_rip = raddr_ip or ("::" if is_ipv6 else "0.0.0.0")
        norm_rport = raddr_port or 0
        proc_key = (laddr_ip, laddr_port, norm_rip, norm_rport)
        extras = (tcp_extras if is_tcp else udp_extras).get(proc_key, {})
        age_secs, age_human = _estimate_age(conn.pid, conn.fd, now)
        status = conn.status if conn.status else None

        record: dict = {
            "protocol": proto.upper(),
            "family": "IPv6" if is_ipv6 else "IPv4",
            "state": status,
            "local": _format_addr(laddr_ip, laddr_port, proto, resolve_dns, resolve_services),
            "remote": _format_addr(raddr_ip, raddr_port, proto, resolve_dns, resolve_services),
            "connection_age": {
                "age_secs": age_secs,
                "age_human": age_human,
            },
            "process": _enrich_process(conn.pid, conn.fd),
        }

        if extras:
            uid = extras.get("uid")
            record["linux_extras"] = {
                "inode": extras.get("inode"),
                "uid": uid,
                "username": _uid_to_username(uid) if uid is not None else None,
                "queues": {
                    "tx_bytes_pending": extras.get("tx_queue"),
                    "rx_bytes_pending": extras.get("rx_queue"),
                },
                "timer": {
                    "type": extras.get("timer_type"),
                    "expires_in_secs": extras.get("timer_expires_secs"),
                },
                "retransmits": extras.get("retransmits"),
                "time_wait_expiry_secs": (
                    extras.get("timer_expires_secs")
                    if status == "TIME_WAIT" else None
                ),
            }
        else:
            record["linux_extras"] = None

        if is_tcp:
            tcp_records.append(record)
        else:
            udp_records.append(record)

    return tcp_records, udp_records


def _summarize(tcp: List[dict], udp: List[dict]) -> dict:
    tcp_states: Dict[str, int] = {}
    listening: List[dict] = []

    for s in tcp:
        state = s.get("state") or "UNKNOWN"
        tcp_states[state] = tcp_states.get(state, 0) + 1
        if state == "LISTEN":
            proc = s.get("process") or {}
            listening.append({
                "ip": s["local"]["ip"],
                "port": s["local"]["port"],
                "service": s["local"]["service"],
                "process": {"pid": proc.get("pid"), "name": proc.get("name")} if proc else None,
            })

    udp_bound = sum(
        1 for s in udp
        if s["local"].get("ip") and s["local"].get("port")
    )
    udp_connected = sum(
        1 for s in udp
        if s["remote"].get("ip") and s["remote"].get("port")
    )

    return {
        "tcp_total": len(tcp),
        "tcp_states": tcp_states,
        "tcp_listening_ports": listening,
        "udp_total": len(udp),
        "udp_bound": udp_bound,
        "udp_connected": udp_connected,
    }


def generate_report(
    resolve_dns: bool = False,
    resolve_services: bool = True,
    output_path: Optional[str] = None,
    pretty: bool = True,
) -> dict:
    now = time.time()
    hz = _detect_hz()

    tcp_records, udp_records = _gather_sockets(resolve_dns, resolve_services, now, hz)

    report = {
        "report_metadata": {
            "generated_at_epoch": now,
            "generated_at_iso": datetime.fromtimestamp(now, tz=timezone.utc).isoformat(),
            "hostname": socket.gethostname(),
            "platform": sys.platform,
            "kernel": os.uname().release,
            "uptime_secs": round(time.time() - psutil.boot_time(), 1),
            "linux_proc_extras_available": sys.platform.startswith("linux"),
            "options": {
                "resolve_dns": resolve_dns,
                "resolve_services": resolve_services,
            },
        },
        "summary": _summarize(tcp_records, udp_records),
        "tcp_sockets": tcp_records,
        "udp_sockets": udp_records,
    }

    if output_path:
        with open(output_path, "w") as fh:
            json.dump(report, fh, indent=2 if pretty else None, default=str)
        total = len(tcp_records) + len(udp_records)
        print(
            f"[net_report] Wrote {output_path}  "
            f"({len(tcp_records)} TCP, {len(udp_records)} UDP sockets)",
            file=sys.stderr,
        )

    return report


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Generate a cross-platform JSON audit report of TCP and UDP sockets.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 net_report.py
  sudo python3 net_report.py --output report.json --dns
  sudo python3 net_report.py --output report.json --compact
""",
    )
    parser.add_argument("--output", "-o", metavar="FILE",
                        help="Write JSON to FILE instead of stdout")
    parser.add_argument("--dns", action="store_true", default=False,
                        help="Reverse-DNS resolve IP addresses (adds latency)")
    parser.add_argument("--no-services", action="store_true", default=False,
                        help="Skip service-name resolution for port numbers")
    parser.add_argument("--compact", action="store_true", default=False,
                        help="Compact (non-indented) JSON output")
    args = parser.parse_args()

    report = generate_report(
        resolve_dns=args.dns,
        resolve_services=not args.no_services,
        output_path=args.output,
        pretty=not args.compact,
    )

    if not args.output:
        print(json.dumps(report, indent=None if args.compact else 2, default=str))


if __name__ == "__main__":
    main()
