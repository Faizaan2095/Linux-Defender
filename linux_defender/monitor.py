"""Continuous, metadata-only monitoring for large files and risky ZIP archives.

This module does not extract archives. It periodically scans configured paths and
logs warnings to stderr (captured by systemd/journald when run as a service).
"""

from __future__ import annotations

import logging
import os
import signal
import time
import zipfile
from pathlib import Path
from threading import Event

LOG = logging.getLogger("linux_defender.monitor")
STOP = Event()
ARCHIVE_SUFFIXES = {".zip", ".jar", ".apk", ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".epub"}


def _positive_int(name: str, default: int) -> int:
    try:
        value = int(os.environ.get(name, default))
        return value if value > 0 else default
    except (TypeError, ValueError):
        return default


def _watch_paths() -> list[Path]:
    configured = os.environ.get("LINUX_DEFENDER_WATCH_PATHS", "")
    raw_paths = configured.split(os.pathsep) if configured else [str(Path.home() / "Downloads")]
    result = []
    for value in raw_paths:
        value = value.strip()
        if value:
            path = Path(value).expanduser().resolve()
            if path.exists():
                result.append(path)
            else:
                LOG.warning("Configured watch path does not exist: %s", path)
    return result


def _scan_file(path: Path, file_size: int, thresholds: dict[str, int]) -> list[str]:
    findings = []
    if file_size >= thresholds["large_file_bytes"]:
        findings.append(f"large file ({file_size / (1024 ** 2):.1f} MiB)")

    if path.suffix.lower() not in ARCHIVE_SUFFIXES:
        return findings

    try:
        with zipfile.ZipFile(path) as archive:
            entries = archive.infolist()
            expanded = sum(entry.file_size for entry in entries)
            compressed = sum(entry.compress_size for entry in entries)
            ratio = expanded / max(compressed, 1)
            if len(entries) >= thresholds["max_entries"]:
                findings.append(f"archive has {len(entries)} entries (limit {thresholds['max_entries']})")
            if expanded >= thresholds["max_uncompressed_bytes"]:
                findings.append(
                    f"archive expands to {expanded / (1024 ** 2):.1f} MiB "
                    f"(limit {thresholds['max_uncompressed_bytes'] / (1024 ** 2):.0f} MiB)"
                )
            if expanded >= thresholds["ratio_min_bytes"] and ratio >= thresholds["max_ratio"]:
                findings.append(f"suspicious compression ratio ({ratio:.1f}:1; limit {thresholds['max_ratio']}:1)")
    except (zipfile.BadZipFile, OSError, EOFError, ValueError):
        # Files may still be downloading or changing; retry on the next scan.
        return findings
    return findings


def scan_once(paths: list[Path], thresholds: dict[str, int], reported: dict[str, tuple[int, int, int]]) -> None:
    """Scan configured trees, warning once per file version that has findings."""
    seen: set[str] = set()
    for root in paths:
        if root.is_file():
            candidates = [root]
        else:
            candidates = []
            for current, dirs, files in os.walk(root, followlinks=False):
                dirs[:] = [name for name in dirs if not (Path(current) / name).is_symlink()]
                candidates.extend(Path(current) / name for name in files)
        for path in candidates:
            try:
                if path.is_symlink() or not path.is_file():
                    continue
                stat = path.stat()
                key = str(path)
                seen.add(key)
                signature = (stat.st_ino, stat.st_size, stat.st_mtime_ns)
                if reported.get(key) == signature:
                    continue
                findings = _scan_file(path, stat.st_size, thresholds)
                if findings:
                    LOG.warning("Review %s: %s", path, "; ".join(findings))
                    reported[key] = signature
                else:
                    reported.pop(key, None)
            except (OSError, PermissionError):
                continue
    for stale in reported.keys() - seen:
        reported.pop(stale, None)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    interval = _positive_int("LINUX_DEFENDER_SCAN_INTERVAL_SECONDS", 30)
    thresholds = {
        "large_file_bytes": _positive_int("LINUX_DEFENDER_MAX_FILE_SIZE_MB", 100) * 1024**2,
        "max_uncompressed_bytes": _positive_int("LINUX_DEFENDER_MAX_UNCOMPRESSED_MB", 500) * 1024**2,
        "max_ratio": _positive_int("LINUX_DEFENDER_MAX_ZIP_RATIO", 100),
        "max_entries": _positive_int("LINUX_DEFENDER_MAX_ZIP_ENTRIES", 10000),
        "ratio_min_bytes": 10 * 1024**2,
    }
    paths = _watch_paths()
    if not paths:
        LOG.error("No valid paths to monitor. Set LINUX_DEFENDER_WATCH_PATHS.")
        raise SystemExit(2)

    signal.signal(signal.SIGTERM, lambda *_: STOP.set())
    signal.signal(signal.SIGINT, lambda *_: STOP.set())
    LOG.info("Monitoring %s every %s seconds", ", ".join(map(str, paths)), interval)
    reported: dict[str, tuple[int, int, int]] = {}
    while not STOP.is_set():
        scan_once(paths, thresholds, reported)
        STOP.wait(interval)
    LOG.info("Monitor stopped")


if __name__ == "__main__":
    main()
