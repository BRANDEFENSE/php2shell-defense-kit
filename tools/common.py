"""Shared, conservative inventory helpers. No exploit or remediation actions."""
import datetime
import os
import re
import json
from pathlib import Path

FIXED = {(8, 2): 35, (8, 3): 36, (8, 4): 27, (8, 5): 12}
CVES = ["CVE-2026-109618", "CVE-2026-109619"]
SETTINGS = {
    "session.upload_progress.enabled", "session.upload_progress.name",
    "session.upload_progress.cleanup", "session.serialize_handler",
    "session.use_strict_mode", "memory_limit", "post_max_size",
    "upload_max_filesize", "max_file_uploads", "max_input_vars",
    "max_input_nesting_level", "max_execution_time", "fatal_error_backtraces",
    "display_errors", "log_errors", "error_reporting", "expose_php",
    "pm.max_requests", "pm.max_children", "opcache.enable",
}
PHP_NAME = re.compile(r"^(?:php(?:[0-9.]+)?(?:-fpm|-cgi)?|php-fpm[0-9.]*|lsphp[0-9.]*|frankenphp|sw-engine-fpm|apache2|httpd)$", re.I)


def utcnow():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def write_report(path, report):
    """Private local report, refusing a symlink destination on supporting systems."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(path, flags, 0o600)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'w') as output:
            fd = None
            json.dump(report, output, indent=2)
    finally:
        if fd is not None:
            os.close(fd)


def version_status(value):
    """Upstream candidate only: vendor backports and running binary need proof."""
    m = re.search(r"(?<![0-9])(\d+)\.(\d+)\.(\d+)([A-Za-z][A-Za-z0-9]*)?", value or "")
    if not m:
        return {"upstream_version": None, "status": "unknown"}
    a, b, c = map(int, m.group(1, 2, 3))
    version = f"{a}.{b}.{c}"
    if m.group(4) and m.group(4).lower().startswith(("rc", "alpha", "beta", "dev")):
        status = "prerelease_requires_review"
    elif (a, b) in FIXED:
        status = "upstream_fix_version_candidate" if c >= FIXED[a, b] else "older_version_requires_vendor_verification"
    elif (5, 4, 0) <= (a, b, c) < (8, 2, 0):
        status = "legacy_requires_vendor_verification_or_upgrade"
    else:
        status = "unmapped_branch_requires_review"
    return {"upstream_version": version, "status": status}


def walk_files(roots, errors, max_files=10000):
    """No symlink traversal; bound work and retain permission/limit evidence."""
    seen = set()
    count = 0
    for root in roots:
        p = Path(root)
        if p.is_symlink():
            errors.append({"path": str(p), "reason": "symlink_root_skipped"})
            continue
        if not p.exists():
            errors.append({"path": str(p), "reason": "missing_root"})
            continue
        if p.is_file():
            paths = [p]
        else:
            paths = []
            def onerror(e):
                errors.append({"path": str(e.filename), "reason": "directory_unreadable"})
            for directory, dirs, names in os.walk(p, followlinks=False, onerror=onerror):
                for d in dirs:
                    if (Path(directory)/d).is_symlink():
                        errors.append({"path": str(Path(directory)/d), "reason": "symlink_directory_skipped"})
                dirs[:] = [d for d in dirs if d not in {".git", "node_modules", "vendor", ".venv"} and not (Path(directory)/d).is_symlink()]
                for name in names:
                    file = Path(directory)/name
                    if not file.is_symlink():
                        paths.append(file)
                        if len(paths) > max_files:
                            errors.append({"path": str(p), "reason": "file_limit_reached"})
                            break
                    else:
                        errors.append({"path": str(file), "reason": "symlink_file_skipped"})
                if len(paths) > max_files:
                    break
        for path in paths:
            key = str(path.absolute())
            if key in seen:
                continue
            seen.add(key)
            count += 1
            if count > max_files:
                errors.append({"reason": "global_file_limit_reached"})
                return
            yield path


def read_small(path, errors, limit=1024*1024):
    try:
        if path.stat().st_size > limit:
            errors.append({"path": str(path), "reason": "oversized_file_skipped"})
            return None
        return path.read_text(errors="replace")
    except OSError:
        errors.append({"path": str(path), "reason": "file_unreadable"})
        return None


def extract_settings(text):
    """Static occurrences, not an effective-configuration parser. Values allowlisted."""
    results = []
    for number, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith((";", "#", "//")):
            continue
        for key in SETTINGS:
            match = re.search(r"(?<![\w.])(?:php_(?:admin_)?(?:value|flag)\[)?" + re.escape(key) + r'''\]?\s*(?:=|\s)\s*["']?([A-Za-z0-9_.+/-]+)''', line)
            if match:
                results.append({"line": number, "setting": key, "value": match.group(1)[:80], "evidence": "static_occurrence_not_effective_runtime"})
    return results
