# PHP2Shell Detection Rules
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)]()

Detection queries for PHP2Shell (CVE-2026-109618 and CVE-2026-109619) in Microsoft Sentinel, Elastic and Splunk.

Read [Detecting PHP2Shell](https://aplite.de/research/detecting-php2shell) on our blog for the full write-up.

## About The Vulnerabilities

Two critical bugs in the PHP core allow unauthenticated remote code execution (RCE). An attacker can run code on a PHP web server without logging in. PHP fixed them on 21 October 2026 in 8.5.12, 8.4.27, 8.3.36 and 8.2.35, and attacks started before the fix ([PHP security advisory](https://www.php.net/archive/2026.php#2026-10-21-5)).

**Patch first.** These queries fix nothing. They show whether someone tried to attack you, or got in.

## Repo Structure

```
php2shell-detection-rules/
├── log-formats/
│   ├── nginx.conf
│   └── apache.conf
├── sentinel/
│   ├── 01-suspicious-form-posts.kql
│   ├── 02-memory-errors-and-worker-crashes.kql
│   └── 03-php-starting-a-shell.kql
├── elastic/
│   ├── 01-suspicious-form-posts.esql
│   ├── 02-memory-errors-and-worker-crashes.esql
│   └── 03-php-starting-a-shell.esql
├── splunk/
│   ├── 01-suspicious-form-posts.spl
│   ├── 02-memory-errors-and-worker-crashes.spl
│   └── 03-php-starting-a-shell.spl
├── lab/              # Docker lab that reproduces the log signals
├── LICENSE
└── README.md
```

Sentinel queries are KQL (Kusto Query Language), Elastic queries are ES|QL (Elasticsearch Query Language) and Splunk queries are SPL (Search Processing Language).

## The Queries

Every platform gets the same three queries.

| Query | Looks for | Data source | Severity |
| --- | --- | --- | --- |
| 01 Suspicious form POSTs | Multipart POSTs to URLs that never take uploads: chunked bodies, bursts from one source, and POSTs that fail with a 5xx. The attack body is small, so size is only one of several triggers | Web server access logs | Medium |
| 02 Memory errors and worker crashes | Out-of-memory errors raised before any script ran (`Allowed memory size ... in Unknown on line 0`), plus the PHP-FPM worker dying as a result (exit code 70, or an nginx 502). A segfault is flagged separately as possible corruption | PHP, PHP-FPM and web server error logs | Medium |
| 03 PHP starting a shell | A PHP or web server process starting a shell, script interpreter or download tool | EDR (endpoint detection and response) process events | High |

Query 03 is the clearest sign that an attack worked. The queries match on behavior, not on exploit tool names such as `php2shell` in the user agent, because tool names are easy to change.

## Lab

The [`lab/`](lab/) folder has a small Docker setup that reproduces every signal
these queries look for. It runs Apache with mod_php and nginx with PHP-FPM, each in
a vulnerable (PHP 8.4.26) and a patched (8.4.27) version, and sends the attack's
request shape at them so you can see the difference in the logs. It drives PHP into
the out-of-memory failure and stops there, it does not run any exploit. Use it to
understand the signals, or to test the queries against logs you generated yourself
before trusting them on production data. See [`lab/README.md`](lab/README.md).

## Before You Start

Default access log formats do not record the request Content-Type, Transfer-Encoding or request size. Query 01 needs all three. Add the format from [`log-formats/`](log-formats/) to every web server and reload it. If your SIEM (central log and alert platform) parses these logs, update the parser too.

## How To Run

Run each query once with the time range starting on 20 October 2026, when details of the bugs leaked. Then schedule it every hour over the last hour, so it keeps running after you patch.

**Microsoft Sentinel**

- Queries 01 and 02 assume Azure Monitor Agent text logs, with the raw line in `RawData` and the server name in `Computer`. Query 03 uses Microsoft Defender for Endpoint data.
- For the first run, set `start` to `datetime(2026-10-20)`.
- Save each query as a scheduled analytics rule that runs every hour and looks back one hour.

**Elastic**

- Query 01 reads the raw line from `event.original`. Turn on "Preserve original event" in the nginx or Apache integration, or parse `ct`, `te` and `reqlen` at ingest. Query 03 uses Elastic Defend data.
- The time range comes from the time picker in Discover, or from the rule schedule.
- Save each query as an ES|QL detection rule that runs every hour.

**Splunk**

- Query 01 parses the raw line with `rex`, so it works with any sourcetype. Query 03 uses the CIM (Common Information Model) Endpoint data model, fed by your EDR or Sysmon for Linux.
- For the first run, replace `earliest=-1h` with `earliest="10/20/2026:00:00:00"`.
- Save each search as a scheduled alert that runs every hour.

## Tuning

- Table, index and data stream names are placeholders. Change them to match your setup.
- Add your real upload URLs to the upload path list in query 01 (`KnownUploadPaths` in Sentinel, the `NOT IN` list in Elastic, the `IN` list in Splunk).
- The thresholds (10 multipart POSTs from one source in 10 minutes, form bodies over 1 MB) are starting points. Note the attack body itself is small, around a few hundred KB, so it is caught by the chunked, burst and 5xx conditions rather than by size.
- Query 02 leaves out normal in-script memory errors and timeouts, because they are too common to alert on. Check them during triage. The worker-exit and nginx-502 rows are supporting signals: strongest when they line up in time with the out-of-memory error.
- Query 03 skips `sendmail`, which PHP's `mail()` function starts through `sh`. Some apps also start shells for image or PDF tools, so compare the results with what each host did before 20 October.

## Status

We built the queries against the lab in [`lab/`](lab/) and tuned them to the signals it produces on vulnerable and patched servers. Your logs and setup will differ, so test them on your own data before you turn them into alerts. Issues and pull requests are welcome.

## References

- [PHP security advisory, 21 October 2026](https://www.php.net/archive/2026.php#2026-10-21-5)
- [GHSA-w8hw-w9fx-j79w (CVE-2026-109618)](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
- [GHSA-6wmf-4rv5-p3rp (CVE-2026-109619)](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
- [CISA alert, 21 October 2026](https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching)

## About Aplite

Maintained by [Aplite](https://aplite.de). We do detection engineering, with a focus on Microsoft Sentinel.

## License

[MIT](LICENSE)
