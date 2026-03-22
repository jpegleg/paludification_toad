#!/usr/bin/env python3
import os
import re
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from exception_logger import exception_handler_quiet

SYSCTL_SETTINGS = {
    "kern.maxfiles": "1048576",
    "kern.maxthread": "32768",
    "kern.maxproc": "8192",
    "kern.maxvnodes": "262144",
    "kern.somaxconn": "32767",
    "kern.maxclusters": "524288",
    "net.inet.tcp.rfc1323": "1",
    "net.inet.tcp.sack": "1",
    "net.inet.tcp.ecn": "1",
    "net.inet.tcp.keepidle": "600",
    "net.inet.tcp.keepintvl": "30",
    "net.inet.tcp.always_keepalive": "1",
    "net.inet.tcp.syncachelimit": "65536",
    "net.inet.tcp.synbucketlimit": "512",
    "net.inet.udp.recvspace": "1048576",
    "net.inet.udp.sendspace": "65536",
    "net.inet.ip.portfirst": "1024",
    "net.inet.ip.portlast": "65535",
}

DAEMON_CAPABILITIES = {
    "openfiles-max": "131072",
    "openfiles-cur": "131072",
    "maxproc-max": "8192",
    "maxproc-cur": "4096",
    "tc": "default",
}

def backup_file(path: Path) -> None:
    if path.exists():
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        shutil.copy2(path, path.with_name(f"{path.name}.bak.{timestamp}"))

def run(cmd: list[str]) -> None:
    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def set_runtime_sysctls() -> None:
    for key, value in SYSCTL_SETTINGS.items():
        run(["sysctl", f"{key}={value}"])

def update_sysctl_conf(path: Path) -> None:
    backup_file(path)
    lines = path.read_text().splitlines() if path.exists() else []
    key_pattern = re.compile(r"^\s*([A-Za-z0-9_.]+)\s*=\s*(\S+)(?:\s*#.*)?$")
    output = []
    seen = set()

    for line in lines:
        match = key_pattern.match(line)
        if match and match.group(1) in SYSCTL_SETTINGS:
            key = match.group(1)
            if key not in seen:
                output.append(f"{key}={SYSCTL_SETTINGS[key]}")
                seen.add(key)
        else:
            output.append(line)

    if output and output[-1] != "":
        output.append("")

    for key, value in SYSCTL_SETTINGS.items():
        if key not in seen:
            output.append(f"{key}={value}")

    path.write_text("\n".join(output).rstrip() + "\n")

def split_login_conf_stanzas(text: str) -> list[list[str]]:
    lines = text.splitlines()
    if not lines:
        return []

    stanzas = []
    current = []

    for line in lines:
        if not current:
            current = [line]
            continue

        previous = current[-1].rstrip()
        starts_new = line and not line[0].isspace() and not previous.endswith("\\")
        if starts_new:
            stanzas.append(current)
            current = [line]
        else:
            current.append(line)

    if current:
        stanzas.append(current)

    return stanzas

def parse_login_class(stanza: list[str]) -> tuple[str | None, dict[str, str]]:
    if not stanza:
        return None, {}

    first = stanza[0].strip()
    if not first or first.startswith("#") or ":" not in first:
        return None, {}

    name = first.split(":", 1)[0].strip()
    caps = {}

    for line in stanza[1:]:
        stripped = line.strip()
        if not stripped.startswith(":"):
            continue
        for field in stripped.split(":"):
            if not field or "=" not in field:
                continue
            key, value = field.split("=", 1)
            caps[key.strip()] = value.strip()

    return name, caps

def build_login_class(name: str, caps: dict[str, str]) -> list[str]:
    ordered = []
    for key in ("openfiles-max", "openfiles-cur", "maxproc-max", "maxproc-cur", "tc"):
        if key in caps:
            ordered.append((key, caps[key]))

    lines = [f"{name}:\\"]

    for key, value in ordered[:-1]:
        lines.append(f"\t:{key}={value}:\\")
    lines.append(f"\t:{ordered[-1][0]}={ordered[-1][1]}:")

    return lines

def update_login_conf(path: Path) -> None:
    backup_file(path)
    text = path.read_text() if path.exists() else ""
    stanzas = split_login_conf_stanzas(text)
    output = []
    found = False

    for stanza in stanzas:
        name, caps = parse_login_class(stanza)
        if name == "daemon":
            merged = dict(caps)
            merged.update(DAEMON_CAPABILITIES)
            output.extend(build_login_class("daemon", merged))
            found = True
        else:
            output.extend(stanza)

    if not found:
        if output and output[-1] != "":
            output.append("")
        output.extend(build_login_class("daemon", DAEMON_CAPABILITIES))

    path.write_text("\n".join(output).rstrip() + "\n")
    run(["cap_mkdb", str(path)])

@exception_handler_quiet
def main():
    if os.geteuid() != 0:
        raise PermissionError("must be run as root")
    update_sysctl_conf(Path("/etc/sysctl.conf"))
    set_runtime_sysctls()
    update_login_conf(Path("/etc/login.conf"))

if __name__ == "__main__":
    main()
