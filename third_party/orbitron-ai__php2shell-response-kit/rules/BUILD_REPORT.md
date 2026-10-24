# Build report

Generated from Sigma sources with pySigma. UNTESTED against live platforms.

| Rule | Platform | Variant | Result |
|---|---|---|---|
| lnx_php2shell_php_file_written_to_webroot | splunk | spl | ok |
| lnx_php2shell_php_file_written_to_webroot | splunk | cim.spl | not converted: Rule type not yet supported by the Splunk data model CIM pipeline! |
| lnx_php2shell_php_file_written_to_webroot | qradar | aql | ok |
| lnx_php2shell_php_file_written_to_webroot | qradar | payload.aql | ok |
| lnx_php2shell_php_file_written_to_webroot | crowdstrike | logscale | skipped: the Falcon pipeline does not map file_event fields - use Falcon's built-in webshell/script-write detections |
| lnx_php2shell_php_file_written_to_webroot | sentinelone | pq | ok |
| lnx_php2shell_php_file_written_to_webroot | sentinelone | dv | ok |
| lnx_php2shell_webserver_spawns_shell_or_lolbin | splunk | spl | ok |
| lnx_php2shell_webserver_spawns_shell_or_lolbin | splunk | cim.spl | ok |
| lnx_php2shell_webserver_spawns_shell_or_lolbin | qradar | aql | ok |
| lnx_php2shell_webserver_spawns_shell_or_lolbin | qradar | payload.aql | ok |
| lnx_php2shell_webserver_spawns_shell_or_lolbin | crowdstrike | logscale | ok |
| lnx_php2shell_webserver_spawns_shell_or_lolbin | sentinelone | pq | ok |
| lnx_php2shell_webserver_spawns_shell_or_lolbin | sentinelone | dv | ok |
| lnx_php2shell_webserver_suspicious_cmdline | splunk | spl | ok |
| lnx_php2shell_webserver_suspicious_cmdline | splunk | cim.spl | ok |
| lnx_php2shell_webserver_suspicious_cmdline | qradar | aql | ok |
| lnx_php2shell_webserver_suspicious_cmdline | qradar | payload.aql | ok |
| lnx_php2shell_webserver_suspicious_cmdline | crowdstrike | logscale | ok |
| lnx_php2shell_webserver_suspicious_cmdline | sentinelone | pq | ok |
| lnx_php2shell_webserver_suspicious_cmdline | sentinelone | dv | ok |
| php2shell_php_fpm_worker_exit_code70 | splunk | spl | ok |
| php2shell_php_fpm_worker_exit_code70 | splunk | cim.spl | not converted: Rule type not yet supported by the Splunk data model CIM pipeline! |
| php2shell_php_fpm_worker_exit_code70 | qradar | aql | not converted: field 'None' is not supported |
| php2shell_php_fpm_worker_exit_code70 | qradar | payload.aql | ok |
| php2shell_php_fpm_worker_exit_code70 | crowdstrike | logscale | ok |
| php2shell_php_fpm_worker_exit_code70 | sentinelone | pq | not converted: Invalid SigmaDetectionItem field name encountered: None. This pipeline only supports the following fields: {CommandLine}, {Company}, {CurrentDirectory}, {Descri |
| php2shell_php_fpm_worker_exit_code70 | sentinelone | dv | not converted: Invalid SigmaDetectionItem field name encountered: None. This pipeline only supports the following fields: {CommandLine}, {Company}, {CurrentDirectory}, {Descri |
| php2shell_php_oom_during_request_parsing | splunk | spl | ok |
| php2shell_php_oom_during_request_parsing | splunk | cim.spl | not converted: Rule type not yet supported by the Splunk data model CIM pipeline! |
| php2shell_php_oom_during_request_parsing | qradar | aql | not converted: field 'None' is not supported |
| php2shell_php_oom_during_request_parsing | qradar | payload.aql | ok |
| php2shell_php_oom_during_request_parsing | crowdstrike | logscale | ok |
| php2shell_php_oom_during_request_parsing | sentinelone | pq | not converted: Invalid SigmaDetectionItem field name encountered: None. Invalid SigmaDetectionItem field name encountered: None. This pipeline only supports the following fiel |
| php2shell_php_oom_during_request_parsing | sentinelone | dv | not converted: Invalid SigmaDetectionItem field name encountered: None. Invalid SigmaDetectionItem field name encountered: None. This pipeline only supports the following fiel |
| php2shell_php_worker_crash | splunk | spl | ok |
| php2shell_php_worker_crash | splunk | cim.spl | not converted: Rule type not yet supported by the Splunk data model CIM pipeline! |
| php2shell_php_worker_crash | qradar | aql | not converted: field 'None' is not supported |
| php2shell_php_worker_crash | qradar | payload.aql | ok |
| php2shell_php_worker_crash | crowdstrike | logscale | ok |
| php2shell_php_worker_crash | sentinelone | pq | not converted: Invalid SigmaDetectionItem field name encountered: None. Invalid SigmaDetectionItem field name encountered: None. Invalid SigmaDetectionItem field name encounte |
| php2shell_php_worker_crash | sentinelone | dv | not converted: Invalid SigmaDetectionItem field name encountered: None. Invalid SigmaDetectionItem field name encountered: None. Invalid SigmaDetectionItem field name encounte |
| win_php2shell_php_file_written_to_webroot | splunk | spl | ok |
| win_php2shell_php_file_written_to_webroot | splunk | cim.spl | ok |
| win_php2shell_php_file_written_to_webroot | qradar | aql | ok |
| win_php2shell_php_file_written_to_webroot | qradar | payload.aql | ok |
| win_php2shell_php_file_written_to_webroot | crowdstrike | logscale | skipped: the Falcon pipeline does not map file_event fields - use Falcon's built-in webshell/script-write detections |
| win_php2shell_php_file_written_to_webroot | sentinelone | pq | ok |
| win_php2shell_php_file_written_to_webroot | sentinelone | dv | ok |
| win_php2shell_webserver_spawns_shell_or_lolbin | splunk | spl | ok |
| win_php2shell_webserver_spawns_shell_or_lolbin | splunk | cim.spl | ok |
| win_php2shell_webserver_spawns_shell_or_lolbin | qradar | aql | ok |
| win_php2shell_webserver_spawns_shell_or_lolbin | qradar | payload.aql | ok |
| win_php2shell_webserver_spawns_shell_or_lolbin | crowdstrike | logscale | ok |
| win_php2shell_webserver_spawns_shell_or_lolbin | sentinelone | pq | ok |
| win_php2shell_webserver_spawns_shell_or_lolbin | sentinelone | dv | ok |
