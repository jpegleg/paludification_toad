import os
import stat
import json
from pathlib import Path
from collections import defaultdict


def _classify_entry(path: Path, stat_result: os.stat_result) -> str:
    mode = stat_result.st_mode
    if stat.S_ISLNK(mode):
        return "symlink"
    if stat.S_ISFIFO(mode):
        return "named_pipe"
    if stat.S_ISCHR(mode) or stat.S_ISBLK(mode):
        return "device"
    if stat.S_ISSOCK(mode):
        return "socket"
    if stat.S_ISREG(mode):
        return "file"
    if stat.S_ISDIR(mode):
        return "directory"
    return "unknown"


def _is_special(kind: str) -> bool:
    return kind in ("symlink", "named_pipe", "device", "socket")


def scan(root: str | os.PathLike) -> dict:
    root = Path(root).resolve()
    files: list[dict] = []
    directories: dict[str, int] = defaultdict(int)
    special_entries: list[dict] = []
    dir_stack: list[str] = [str(root)]
    dir_seen: set[int] = set()

    for current_dir, dir_names, file_names, dir_fd in os.fwalk(
        root, follow_symlinks=False
    ):
        current_path = Path(current_dir)

        try:
            dir_stat = os.stat(current_dir, dir_fd=dir_fd)
        except OSError:
            continue

        dir_inode = dir_stat.st_ino
        if dir_inode in dir_seen:
            dir_names.clear()
            continue
        dir_seen.add(dir_inode)

        dir_key = str(current_path)
        if dir_key not in directories:
            directories[dir_key] = 0

        for name in file_names + list(dir_names):
            entry_path = current_path / name

            try:
                entry_stat = os.lstat(entry_path)
            except OSError:
                continue

            kind = _classify_entry(entry_path, entry_stat)

            if _is_special(kind):
                special_entries.append(
                    {
                        "path": str(entry_path),
                        "kind": kind,
                        "size_bytes": entry_stat.st_size,
                    }
                )
                continue

            if kind == "file":
                size = entry_stat.st_size
                files.append({"path": str(entry_path), "size_bytes": size})

                ancestor = current_path
                while True:
                    directories[str(ancestor)] = directories.get(str(ancestor), 0) + size
                    if ancestor == root:
                        break
                    parent = ancestor.parent
                    if parent == ancestor:
                        break
                    ancestor = parent

    top_files = sorted(files, key=lambda f: f["size_bytes"], reverse=True)[:20]
    top_dirs = sorted(
        [{"path": p, "total_bytes": s} for p, s in directories.items()],
        key=lambda d: d["total_bytes"],
        reverse=True,
    )[:5]

    return {
        "root": str(root),
        "files": files,
        "directories": [
            {"path": p, "total_bytes": s} for p, s in sorted(directories.items())
        ],
        "special_entries": special_entries,
        "top_20_largest_files": top_files,
        "top_5_directories_by_usage": top_dirs,
    }


def disk_use(root: str | os.PathLike, *, indent: int | None = 2) -> str:
    return json.dumps(scan(root), indent=indent)


if __name__ == "__main__":
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "."
    print(disk_use(target))
