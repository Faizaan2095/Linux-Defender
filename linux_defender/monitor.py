"""Bounded, warning-only inspection for downloaded files and ZIP-compatible archives.

The monitor never extracts archives or executes their contents. ZIP members that
look like documentation or scripts are read only up to strict byte/count limits.
When ClamAV is installed, changed files are also passed to its local signature
scanner with scan-size and timeout limits. This is a review aid, not a guarantee.
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import signal
import stat
import subprocess
import zipfile
from pathlib import Path, PurePosixPath
from threading import Event

LOG = logging.getLogger("linux_defender.monitor")
STOP = Event()
ARCHIVE_SUFFIXES = {".zip", ".jar", ".apk", ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".epub"}
IMAGE_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".tif", ".tiff", ".heic", ".avif", ".svg"}
README_NAMES = {"readme", "readme.txt", "readme.md", "readme.rst", "readme.html"}
DOC_NAMES = README_NAMES | {"manifest.mf", "package.json", "manifest.json", "pyproject.toml", "setup.py"}
SCRIPT_SUFFIXES = {".sh", ".bash", ".py", ".pl", ".rb", ".ps1", ".bat", ".command"}
EXECUTABLE_SUFFIXES = SCRIPT_SUFFIXES | {".exe", ".dll", ".so", ". AppImage".strip().lower(), ".deb", ".rpm"}
MAX_MEMBER_READ_BYTES = 32 * 1024
MAX_TOTAL_MEMBER_READ_BYTES = 256 * 1024
MAX_MEMBER_INSPECTIONS = 16
MAX_README_CANDIDATES = 8
CREATOR_RE = re.compile(r"^\s*(author|creator|publisher|maintainer|vendor)\s*[:=]\s*(.{1,120})\s*$", re.I | re.M)
DANGEROUS_SCRIPT_PATTERNS = (
    re.compile(r"\b(?:curl|wget)\b[^\n|]{0,300}\|\s*(?:sudo\s+)?(?:sh|bash)\b", re.I),
    re.compile(r"\bbase64\s+(?:--decode|-d)\b[^\n|]{0,200}\|\s*(?:sh|bash)\b", re.I),
    re.compile(r"\brm\s+-rf\s+(?:/\s|/\*|--no-preserve-root)", re.I),
)


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


def _read_member(archive: zipfile.ZipFile, entry: zipfile.ZipInfo, budget: int) -> bytes:
    """Read at most the per-member and caller's remaining output budget."""
    limit = min(MAX_MEMBER_READ_BYTES, max(0, budget))
    if not limit:
        return b""
    with archive.open(entry) as stream:
        return stream.read(limit)


def _archive_content_review(archive: zipfile.ZipFile, thresholds: dict[str, int]) -> list[str]:
    """Inspect ZIP metadata and small, selected content samples without extraction."""
    entries = archive.infolist()
    expanded = sum(max(entry.file_size, 0) for entry in entries)
    compressed = sum(max(entry.compress_size, 0) for entry in entries)
    ratio = expanded / max(compressed, 1)
    findings: list[str] = []
    if len(entries) >= thresholds["max_entries"]:
        findings.append(f"archive has {len(entries)} entries (limit {thresholds['max_entries']})")
    if expanded >= thresholds["max_uncompressed_bytes"]:
        findings.append(
            f"archive expands to {expanded / (1024 ** 2):.1f} MiB "
            f"(limit {thresholds['max_uncompressed_bytes'] / (1024 ** 2):.0f} MiB)"
        )
    if expanded >= thresholds["ratio_min_bytes"] and ratio >= thresholds["max_ratio"]:
        findings.append(f"suspicious compression ratio ({ratio:.1f}:1; limit {thresholds['max_ratio']}:1)")

    docs: list[zipfile.ZipInfo] = []
    scripts: list[zipfile.ZipInfo] = []
    executable_count = 0
    nested_count = 0
    unsafe_paths = 0
    symlink_count = 0
    for entry in entries:
        if entry.is_dir():
            continue
        name = entry.filename
        normalized = name.replace("\\", "/")
        parts = PurePosixPath(normalized).parts
        if normalized.startswith("/") or re.match(r"^[A-Za-z]:", normalized) or ".." in parts:
            unsafe_paths += 1
        unix_mode = entry.external_attr >> 16
        if stat.S_IFMT(unix_mode) == stat.S_IFLNK:
            symlink_count += 1
        suffix = Path(name).suffix.lower()
        basename = Path(name).name.lower()
        if basename in DOC_NAMES and len(docs) < MAX_README_CANDIDATES:
            docs.append(entry)
        if suffix in EXECUTABLE_SUFFIXES:
            executable_count += 1
        if suffix in ARCHIVE_SUFFIXES:
            nested_count += 1
        if suffix in SCRIPT_SUFFIXES and len(scripts) < MAX_MEMBER_INSPECTIONS:
            scripts.append(entry)

    if unsafe_paths:
        findings.append(f"contains {unsafe_paths} path(s) with absolute or parent-directory components")
    if symlink_count:
        findings.append(f"contains {symlink_count} symbolic-link member(s)")
    if nested_count:
        findings.append(f"contains {nested_count} nested archive(s); nested contents were not unpacked")
    if executable_count:
        findings.append(f"contains {executable_count} executable or installer file(s); review before running")

    total_budget = MAX_TOTAL_MEMBER_READ_BYTES
    creator_claims: list[str] = []
    for entry in docs:
        if total_budget <= 0:
            break
        try:
            data = _read_member(archive, entry, total_budget)
        except (OSError, RuntimeError, zipfile.BadZipFile, NotImplementedError):
            continue
        total_budget -= len(data)
        text = data.decode("utf-8", errors="replace")
        for label, value in CREATOR_RE.findall(text):
            value = " ".join(value.strip().split())
            if value:
                creator_claims.append(f"{label}: {value[:120]}")
                break
        if Path(entry.filename).name.lower() in README_NAMES and "README present" not in " ".join(findings):
            findings.append("README present (contents skimmed; not proof of legitimacy)")

    suspicious_scripts = 0
    for entry in scripts:
        if total_budget <= 0:
            break
        try:
            data = _read_member(archive, entry, total_budget)
        except (OSError, RuntimeError, zipfile.BadZipFile, NotImplementedError):
            continue
        total_budget -= len(data)
        sample = data.decode("utf-8", errors="replace")
        if any(pattern.search(sample) for pattern in DANGEROUS_SCRIPT_PATTERNS):
            suspicious_scripts += 1
    if suspicious_scripts:
        findings.append(f"{suspicious_scripts} script sample(s) contain high-risk command patterns; manual review recommended")
    if creator_claims and findings:
        findings.append(f"archive documentation claims {creator_claims[0]} (unverified)")
    elif findings and not docs:
        findings.append("no supported documentation/creator metadata found")
    return findings


def _clamav_review(path: Path) -> list[str]:
    """Use optional local ClamAV signatures; never execute the scanned file."""
    if os.environ.get("LINUX_DEFENDER_CLAMSCAN", "auto").lower() in {"0", "false", "no", "off"}:
        return []
    clamscan = shutil.which("clamscan")
    if not clamscan:
        return []
    max_scan_mb = _positive_int("LINUX_DEFENDER_CLAMAV_MAX_SCAN_MB", 200)
    max_file_mb = _positive_int("LINUX_DEFENDER_CLAMAV_MAX_FILE_MB", 100)
    timeout = _positive_int("LINUX_DEFENDER_CLAMAV_TIMEOUT_SECONDS", 60)
    try:
        result = subprocess.run(
            [clamscan, "--no-summary", f"--max-filesize={max_file_mb}M", f"--max-scansize={max_scan_mb}M", str(path)],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return [f"ClamAV scan timed out after {timeout}s; result inconclusive"]
    except OSError as exc:
        return [f"ClamAV could not run ({exc.__class__.__name__}); result inconclusive"]
    if result.returncode == 1:
        # Avoid logging untrusted multiline output directly.
        detection = next((line.replace("\r", " ").replace("\n", " ")[:240] for line in result.stdout.splitlines() if "FOUND" in line), "detection reported")
        return [f"ClamAV: {detection}"]
    if result.returncode != 0:
        return [f"ClamAV returned error code {result.returncode}; result inconclusive"]
    return []


def _scan_file(path: Path, file_size: int, thresholds: dict[str, int]) -> list[str]:
    findings = []
    if path.suffix.lower() not in IMAGE_SUFFIXES and file_size >= thresholds["large_file_bytes"]:
        findings.append(f"large file ({file_size / (1024 ** 2):.1f} MiB)")
    if path.suffix.lower() in ARCHIVE_SUFFIXES:
        try:
            with zipfile.ZipFile(path) as archive:
                findings.extend(_archive_content_review(archive, thresholds))
        except (zipfile.BadZipFile, OSError, EOFError, ValueError):
            # Incomplete and corrupt archives aren't extracted; inspect on the next change.
            pass
    findings.extend(_clamav_review(path))
    return findings


def scan_once(
    paths: list[Path],
    thresholds: dict[str, int],
    reported: dict[str, tuple[int, int, int]],
    scanned: dict[str, tuple[int, int, int]] | None = None,
    stable: dict[str, tuple[tuple[int, int, int], int]] | None = None,
) -> None:
    """Scan stable files, warning once per changed version; clean versions are cached too."""
    scanned = scanned if scanned is not None else {}
    stable = stable if stable is not None else {}
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
                info = path.stat()
                key = str(path)
                seen.add(key)
                signature = (info.st_ino, info.st_size, info.st_mtime_ns)
                previous, observations = stable.get(key, (signature, 0))
                observations = observations + 1 if previous == signature else 1
                stable[key] = (signature, observations)
                if observations < 2 or scanned.get(key) == signature:
                    continue
                findings = _scan_file(path, info.st_size, thresholds)
                scanned[key] = signature
                if findings:
                    LOG.warning("Review %s: %s", path, "; ".join(findings))
                    reported[key] = signature
                else:
                    reported.pop(key, None)
            except OSError:
                continue
    for mapping in (reported, scanned, stable):
        for stale in mapping.keys() - seen:
            mapping.pop(stale, None)


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

    if os.environ.get("LINUX_DEFENDER_CLAMSCAN", "auto").lower() not in {"0", "false", "no", "off"}:
        if shutil.which("clamscan"):
            LOG.info("ClamAV found; changed, stable files will be signature-scanned")
        else:
            LOG.warning("ClamAV not installed; only bounded static checks will be used")
    signal.signal(signal.SIGTERM, lambda *_: STOP.set())
    signal.signal(signal.SIGINT, lambda *_: STOP.set())
    LOG.info("Monitoring %s every %s seconds (warning-only)", ", ".join(map(str, paths)), interval)
    reported: dict[str, tuple[int, int, int]] = {}
    scanned: dict[str, tuple[int, int, int]] = {}
    stable: dict[str, tuple[tuple[int, int, int], int]] = {}
    while not STOP.is_set():
        scan_once(paths, thresholds, reported, scanned, stable)
        STOP.wait(interval)
    LOG.info("Monitor stopped")


if __name__ == "__main__":
    main()
