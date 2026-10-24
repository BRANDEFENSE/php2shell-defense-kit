# osquery local inventory pack

`php_inventory.json` uses `processes`, `listening_ports` and `process_open_sockets` for a Linux-oriented inventory. It does not perform network probing or collect command lines/environments.

Queries were checked for SQL shape against synthetic SQLite tables. **They have not been executed with osquery in this release.** Confirm table availability, schema, permissions and performance using your installed osquery version before scheduling the pack. A join can miss events from short-lived processes. Apache candidates may not load PHP. Socket observations require application baselining and are not maliciousness verdicts.

Run one query first in a local osquery shell, then install the pack using your existing fleet configuration process if appropriate. Do not overwrite your existing osquery configuration with this file.
