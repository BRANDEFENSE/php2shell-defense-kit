# Sources and provenance

Baseline checked 24 October 2026. These are primary technical sources; no endorsement is implied. The kit's own rules and tools are original. Third-party community detections are kept apart in `third_party/` and listed in [community-resources.md](community-resources.md).

| Source | Supports |
|---|---|
| [PHP release and October 23 update](https://www.php.net/archive/2026.php) | Fixed releases, temporary mitigations, source backports, CVE-2026-115560 conditions |
| [PHP OOM advisory](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) | OOM root cause, SAPI differences, resource-control caveats |
| [PHP stale-state advisory](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) | Producer/consumer lifecycle, startup-effective configuration, FPM conditional paths |
| [Wiz technical research](https://www.wiz.io/blog/php2shell-php-rce) | RCE and memory-disclosure demonstrations; memory exposure without shell execution |
| [Calif technical research](https://calif.io/php2shell/) | Independent lifecycle and source analysis, history and application-dependent paths |
| [Cloudflare protection update](https://blog.cloudflare.com/php-vulnerabilities-waf-protection/) | Request/response protection, rule deployment and default-name scope caveat |
| [AWS MadPot observations](https://aws.amazon.com/blogs/security/amazon-threat-intelligence-identifies-php2shell-exploitation-prior-to-public-disclosure-in-madpot/) | October 17/21 attempts, reported network pivots and uncertainty |
| [ProjectDiscovery inventory guide](https://projectdiscovery.io/research/php2shell) | Hidden PHP inventory, package versus worker restart, vendor backport verification |
| [Corelight detections](https://corelight.com/blog/php2shell-detection-before-disclosure) | Network visibility and open-source detection ecosystem |
| [Elastic behavior coverage](https://www.elastic.co/security-labs/threat-command/php2shell-php-rce-detection) | Host behavior detection and distinction between emulation and CVE reproduction |
| [Sigma specification](https://sigmahq.io/sigma-specification/specification/sigma-rules-specification.html) | Rule structure and modifier semantics |
| [YARA documentation](https://yara.readthedocs.io/en/latest/writingrules.html) | Rule syntax and matching semantics |

No source implies that every PHP-powered site is successfully exploitable under every configuration. No broad Internet prevalence estimate is used as a count of compromised systems. The package does not claim a new vulnerability or a production detection success rate.
