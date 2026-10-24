# php2shell-check: is the PHP that serves HTTP really fixed?

Read-only check for PHP2Shell (CVE-2026-109618, CVE-2026-109619). MIT license (header in each script).
Question it answers: "is the PHP that really serves HTTP on this machine fixed, and is the running worker the fixed one?"
"Package installed" alone is not enough, so it shows four separate evidences:

| Evidence | What it checks |
|---|---|
| package | dpkg / rpm / apk PHP packages. Fixed = upstream 8.2.35, 8.3.36, 8.4.27, 8.5.12 or newer; an older-looking version counts only if the package changelog names BOTH CVE ids (Debian/Ubuntu/RHEL backports, for example Ubuntu noble 8.3.6-0ubuntu0.24.04.13). Alpine has no changelog: WARN, check the advisory. |
| runtime | php-fpm binaries (on disk and from running masters), Apache libphp, LiteSpeed lsphp, FrankenPHP, php-cgi. `php -v` is printed as INFO only: the CLI can be fixed while FPM is not. |
| process | running php-fpm / apache2 / httpd / lsphp / frankenphp workers whose executable or mapped libphp is "(deleted)" = the update replaced the file but the old code still serves (FAIL). A process started before its package was installed = WARN. |
| deployment | docker / podman running containers (`php -v` inside) and local images (pinned tags judged, floating tags WARN). Kubernetes, ECS and CI images are NOT covered. |

Also prints (INFO) the ini values relevant to the temporary controls: `session.upload_progress.enabled/name`, `memory_limit`, `post_max_size`, `fatal_error_backtraces`, FPM pool overrides, Apache php_value lines. `.user.ini`, `.htaccess` and application `ini_set()` are not scanned.

## Run

    sudo bash tools/php2shell-check.sh            # full check; root needed to read other users' /proc entries
    bash tools/php2shell-check.sh --no-containers # skip docker/podman
    bash tools/php2shell-check.sh --quiet         # hide INFO lines

No network, no writes (a temp dir is created and removed), no exploit traffic. Exit codes: 0 all PASS, 1 WARN, 2 FAIL, 3 nothing PHP found.
Inside a container run it as root; without CAP_SYS_PTRACE other users' workers are judged through their (inspected) parent process.

## Limits

- Judges versions and file state, not exploitability. Patching and restarting the workers is the only complete fix; the ini controls are temporary and partial (see `advisory-baseline.md and remediation.md`).
- A fixed version label does not prove the running worker was restarted on non-Linux layouts; on Linux the "(deleted)" test covers it.
- Apache mod_php stale test: the version of a replaced libphp is read from the file on disk (new), the stale state is caught by the process check.
- `tools/php2shell-check.ps1` (Windows) is UNTESTED: it was written next to the Linux script and never run (no PowerShell in the lab). Read it before use.

## Tested (Brandefense lab containers, arm64; raw outputs stay in the lab folder)

| Case | Result |
|---|---|
| php-fpm 8.3.35 / apache 8.3.35 | FAIL, exit 2 |
| php-fpm 8.3.36 / apache 8.3.36 / apache 8.5.12 | PASS, exit 0 |
| fpm 8.3.35 started, binary replaced on disk with 8.3.36 | runtime disk PASS, running pid FAIL "(deleted)" |
| apache 8.3.35 started, libphp.so replaced with 8.3.36 | FAIL mapped library replaced |
| fake Debian package, old version string, changelog with both CVEs / one / none | PASS / WARN / FAIL |
| Linux VM host with docker: containers 8.3.35, 8.1.34, 8.5.12; floating image tags | FAIL / PASS / WARN |
Not tested: real Ubuntu/RHEL/Alpine hosts, FrankenPHP, LiteSpeed, podman, x86-64.
