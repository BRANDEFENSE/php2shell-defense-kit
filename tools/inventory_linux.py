#!/usr/bin/env python3
"""Read-only local PHP inventory. Standard library; root improves visibility."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))  # keeps `python3 -I` working
from common import PHP_NAME, extract_settings, read_small, utcnow, version_status, walk_files, write_report


def command(argv, errors):
    if not shutil.which(argv[0]):
        errors.append({"component": argv[0], "reason": "command_unavailable"})
        return ""
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=20, check=False)
        if r.returncode:
            errors.append({"component": argv[0], "reason": "nonzero_exit", "returncode": r.returncode})
        return r.stdout
    except (OSError, subprocess.TimeoutExpired):
        errors.append({"component": argv[0], "reason": "command_failed_or_timed_out"})
        return ""


def processes(proc_root, errors):
    result = []
    try:
        entries = list(Path(proc_root).iterdir())
    except OSError:
        errors.append({"component": "proc", "reason": "unavailable"})
        return result
    for p in entries:
        if not p.name.isdigit():
            continue
        try:
            name = (p/"comm").read_text().strip()
            exe = os.readlink(p/"exe")
            if not PHP_NAME.fullmatch(name) and not PHP_NAME.fullmatch(Path(exe.replace(" (deleted)", "")).name):
                continue
            row = {"pid": int(p.name), "name": name, "executable": exe, "running_version": "unknown", "maps_visible": False, "php_modules": []}
            try:
                for line in (p/"maps").read_text().splitlines():
                    parts = line.split(None, 5)
                    if len(parts) == 6 and re.search(r"(?:libphp|/php|/lsphp|/frankenphp|sw-engine)", parts[5], re.I):
                        if parts[5] not in row["php_modules"]:
                            row["php_modules"].append(parts[5])
                row["maps_visible"] = True
            except OSError:
                errors.append({"pid": int(p.name), "reason": "maps_unreadable"})
            row["restart_review_required"] = " (deleted)" in exe or any(" (deleted)" in x for x in row["php_modules"])
            row["php_context"] = "webserver_candidate_verify_module" if name in {"apache2", "httpd"} and not row["php_modules"] else "php_runtime_or_module_observed"
            result.append(row)
        except OSError:
            # A process may disappear; permission gaps must remain visible.
            if p.exists():
                errors.append({"pid": int(p.name), "reason": "process_metadata_unreadable"})
    return result


def packages(errors):
    result = []
    if shutil.which("dpkg-query"):
        data = command(["dpkg-query", "-W", "-f=${binary:Package}\t${Version}\t${Architecture}\t${db:Status-Status}\n"], errors)
        for line in data.splitlines():
            fields = line.split("\t")
            if len(fields) == 4 and fields[3] == "installed" and re.search(r"(?:^|[-_])(php|lsphp|sw-engine)", fields[0], re.I):
                result.append({"manager": "dpkg", "name": fields[0], "version": fields[1], "architecture": fields[2], **version_status(fields[1])})
    elif shutil.which("rpm"):
        for line in command(["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n"], errors).splitlines():
            fields = line.split("\t")
            if len(fields) == 3 and re.search(r"(?:^|[-_])(php|lsphp|sw-engine)", fields[0], re.I):
                result.append({"manager": "rpm", "name": fields[0], "version": fields[1], "architecture": fields[2], **version_status(fields[1])})
    else:
        errors.append({"component": "packages", "reason": "unsupported_package_manager"})
    return result


def configurations(roots, errors):
    result = []
    for path in walk_files(roots, errors):
        if path.suffix.lower() not in {".ini", ".conf"} and path.name not in {".htaccess", ".user.ini", "php.ini"}:
            continue
        text = read_small(path, errors)
        if text is None:
            continue
        settings = extract_settings(text)
        if settings:
            result.append({"path": str(path), "settings": settings})
    return result


def repositories(roots, errors):
    result = []
    for path in walk_files(roots, errors):
        if not (path.name.startswith("Dockerfile") or path.name in {"compose.yml", "compose.yaml", "docker-compose.yml", "docker-compose.yaml", "composer.json", "composer.lock"} or path.suffix in {".tf", ".yml", ".yaml"}):
            continue
        text = read_small(path, errors)
        if text is None:
            continue
        for number, line in enumerate(text.splitlines(), 1):
            for match in re.finditer(r"(?i)(?<![A-Za-z0-9])(?:[A-Za-z0-9_.-]+/)*php:(\d+(?:\.\d+){0,2}(?:-[a-z0-9.-]+)?)", line):
                result.append({"path": str(path), "line": number, "evidence_type": "php_image_reference", "image_tag": match.group(1), **version_status(match.group(1))})
            if re.search(r"(?i)\b(?:php-fpm|libapache2-mod-php|lsphp|frankenphp)\b", line):
                result.append({"path": str(path), "line": number, "evidence_type": "runtime_build_or_deployment_reference", "status": "runtime_version_unknown"})
        if path.name.startswith("composer."):
            result.append({"path": str(path), "evidence_type": "php_application_dependency_manifest", "status": "does_not_prove_deployed_php_version"})
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--config-root", action="append", default=[], help="Repeat; overrides default config roots")
    p.add_argument("--repo-root", action="append", default=[], help="Optional explicit source directories")
    p.add_argument("--docker", action="store_true", help="Opt in to local Docker metadata; no exec, env or mounts collected")
    p.add_argument("--kubernetes", action="store_true", help="Opt in to current kubectl context pod names/images; no secrets/configmaps")
    p.add_argument("--probe-binary", action="append", default=[], help="Opt in to executing a trusted explicit absolute PHP binary with -n -v; CLI evidence only")
    p.add_argument("--output", required=True)
    args = p.parse_args()
    errors = []
    report = {"schema_version": "1.0", "observed_at": utcnow(), "host": os.uname().nodename, "uid": os.geteuid(), "processes": processes("/proc", errors), "packages": packages(errors), "configurations": configurations(args.config_root or ["/etc/php", "/usr/local/etc/php", "/etc/apache2", "/etc/httpd", "/etc/nginx"], errors), "repository_evidence": repositories(args.repo_root, errors), "containers": [], "kubernetes": [], "binary_probes": [], "limitations": ["Static settings are not effective runtime configuration", "Package and CLI versions do not prove the web-serving version", "No image filesystems or container namespaces were inspected", "Permission errors and missing roots are coverage gaps", "No process command lines, environments, sessions or request bodies collected"]}
    for binary in args.probe_binary:
        if not Path(binary).is_absolute() or not Path(binary).is_file():
            errors.append({"path": binary, "reason": "probe_requires_existing_absolute_trusted_binary"})
            continue
        output = command([binary, "-n", "-v"], errors)
        version = re.search(r"PHP\s+(\d+\.\d+\.\d+(?:[A-Za-z][A-Za-z0-9]*)?)", output)
        report["binary_probes"].append({"path": binary, "scope": "CLI_only_not_web_worker", **version_status(version.group(1) if version else "")})
    if args.docker:
        ids = command(["docker", "ps", "-aq"], errors).split()
        for cid in ids:
            raw = command(["docker", "inspect", "--format", '{{json .Id}}\t{{json .Name}}\t{{json .Config.Image}}\t{{json .Image}}\t{{json .State.Running}}', cid], errors).strip().split("\t")
            if len(raw) == 5:
                try:
                    report["containers"].append(dict(zip(["id", "name", "image_reference", "image_id", "running"], [json.loads(x) for x in raw])))
                except ValueError:
                    errors.append({"component": "docker", "reason": "metadata_parse_error"})
    if args.kubernetes:
        raw = command(["kubectl", "get", "pods", "--all-namespaces", "--request-timeout=15s", "-o", "custom-columns=NAMESPACE:.metadata.namespace,NAME:.metadata.name,IMAGES:.spec.containers[*].image,INIT_IMAGES:.spec.initContainers[*].image,PHASE:.status.phase", "--no-headers"], errors)
        report["kubernetes"] = [{"namespace": x[0], "pod": x[1], "images": x[2], "init_images": x[3], "phase": x[4]} for line in raw.splitlines() if len(x := line.split()) == 5]
    report["coverage_gaps"] = errors
    dest = Path(args.output)
    write_report(dest, report)
    print(f"Inventory written: {dest}; {len(errors)} coverage gaps. No vulnerability or remediation verdict issued.")


if __name__ == "__main__":
    main()
