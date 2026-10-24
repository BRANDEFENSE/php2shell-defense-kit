# Internal inventory and evidence collection

## Local Linux

Run `python3 tools/inventory_linux.py --output reports/inventory.json`. Default roots are `/etc/php`, `/usr/local/etc/php`, `/etc/apache2`, `/etc/httpd`, `/etc/nginx`. Repeat `--config-root` to override those roots, including explicit application roots if `.user.ini` or `.htaccess` review is needed. Missing default roots are reported, not silently interpreted as absence.

Collected: candidate runtime/webserver process names, executable paths, selected PHP mapped-module paths, deleted-artifact flags, installed dpkg/rpm package metadata, allowlisted configuration occurrences. No process arguments, environments, passwords, sessions, complete configuration files or memory contents are exported.

Important gaps:

- Apache can exist without PHP. The collector marks that case as a candidate rather than asserting PHP presence.
- Binaries deleted from disk but still mapped are restart-review leads. Replacing a binary does not prove that its running process is fixed.
- A mapped-module filename rarely establishes its build. Obtain trusted package/build evidence on the host.
- The collector does not enter containers, inspect image layers, query registries, inventory SBOMs automatically or prove current effective PHP configuration.
- It does not inventory every non-dpkg/rpm distribution, appliance or proprietary PHP embedding. Add vendor evidence separately.
- Symlink roots/files/directories are skipped and recorded. Debian-style `conf.d` symlinks can therefore be coverage gaps. Supply their trusted real target directories explicitly after reviewing them.
- File walks stop at 10,000 files and skip files over 1 MiB. `.git`, `vendor`, `node_modules` and `.venv` descendants are excluded. An explicitly supplied dependency root can be scanned separately. Large/denied trees require a separately scoped pass.
- The collector reads metadata but may update filesystem access times. It does not modify application configuration.

`--probe-binary /usr/bin/php8.3` explicitly executes a locally trusted absolute binary with `-n -v`. This is off by default. It reads the on-disk CLI build only, with configuration loading disabled; it cannot establish the running web worker version.

## Containers and Kubernetes

`--docker` lists local containers and reads only ID, name, configured image reference, image ID and running state with a selected `docker inspect --format`. It does not export `.Config.Env`, mounts or complete inspect data. Access to the Docker daemon is privileged.

`--kubernetes` reads pod namespace, name, application/init image references and phase across namespaces using the current context. Access errors remain gaps. Ephemeral/debug containers, image layers and runtime PHP processes inside pods need separate review. No Secrets, ConfigMaps or service account tokens are read. Never infer PHP absence from an innocuous image name.

For each image, obtain the registry digest, SBOM/package manifest, fixed image build record and rollout evidence through your normal platform tooling. Track running image IDs, not mutable tags alone.

## Source and build inventory

`--repo-root /srv/source` finds PHP image references, runtime build hints and Composer manifests. Hints/comments can match. `composer.lock` describes application dependencies, not the PHP runtime patch level. Major/minor image tags remain unknown because tags can move.

`python3 tools/source_audit.py /srv/app --output reports/source.json` reports line numbers for serializer changes, session startup/decoding and lifecycle callbacks without copying source text. This is lexical candidate discovery. It cannot prove cross-file ordering, values, reachability or a vulnerability. Review control flow locally.

## Explicit web evidence

`http_inventory.py` sends one HEAD per explicitly supplied URL, with TLS verification and a five-second timeout; at most 500 URLs per invocation. It stores a parsed PHP version, response status and evidence source only. No query strings, credentials, response bodies, cookies, full headers or redirects are accepted/retained. HTTP 405, hidden headers and network errors remain unknown. It does not test exploitability or discover assets.

## Windows

The PowerShell collector reads selected process metadata, matching service names/state, file-version resources and selected config occurrences. It does not execute PHP. Review IIS FastCGI and handler mappings locally to relate actual application paths to PHP builds. Bundled binaries, architecture, app pool identity, dependency modules and restart state require manual verification.

The Windows script is not run-tested in this release. Its output schema differs from Linux. Static config discovery omits many XML or dynamic settings and must not be treated as complete IIS coverage.

## Operational extensions

Use your CMDB/EDR/SBOM systems to include control panels, network appliances, staging copies, shared-hosting tenants, forgotten domains, backup images, serverless/container builds and acquisition assets. Add an owner, runtime evidence, vendor patch record and restart/rollout proof for every asset in `templates/patch-tracker.csv`. Never fill unknown cells with assumed safe values.

## Offline SBOM component search

`python3 tools/sbom_inventory.py image.cdx.json image.spdx.json --output reports/sbom.json` reads CycloneDX or SPDX JSON locally, including nested CycloneDX components. It does not query registries or follow external references. PHP-like package names are candidates; image/SBOM completeness, artifact digests and the running deployment still need independent verification. Files over 50 MiB and unsupported/malformed documents remain coverage gaps.
