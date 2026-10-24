/*
  ORBITRON php2shell (CVE-2026-109618 / CVE-2026-109619) - YARA hunting rules   v1.0.0 (2026-10-21)
  Purpose: find webshells / persistence typically dropped AFTER PHP remote code execution, and
  leftover session upload-progress artefacts. NOT an exploit signature for the CVEs.
  Scan web roots and session directories, e.g.:
    yara -r -s php2shell_hunting.yar /var/www
    yara -r    php2shell_hunting.yar /var/lib/php/sessions
  License: MIT. Review hits manually - obfuscated legitimate code can match.
*/

rule ORBITRON_PHP_Webshell_Generic
{
  meta:
    author      = "ORBITRON"
    date        = "2026-10-21"
    description = "Generic PHP webshell patterns: user input passed to eval/assert/system-like sinks or layered decode+eval"
    reference   = "https://blog.flatt.tech/entry/php2shell"
    severity    = "high"
  strings:
    $php  = "<?" ascii
    $s1 = /\b(eval|assert|create_function)\s*\(\s*(@\s*)?(base64_decode|gzinflate|gzuncompress|str_rot13|rawurldecode|hex2bin|stripslashes)?\s*\(?\s*\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)\b/ nocase
    $s2 = /\b(system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(\s*(@\s*)?\$_(GET|POST|REQUEST|COOKIE|SERVER)\b/ nocase
    $s3 = /\beval\s*\(\s*(gzinflate|gzuncompress|str_rot13|base64_decode|gzdecode)\s*\(\s*(gzinflate|gzuncompress|str_rot13|base64_decode|gzdecode)\s*\(/ nocase
    $s4 = /\$_(GET|POST|REQUEST|COOKIE)\s*\[[^\]]{1,40}\]\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/ nocase
    $s5 = /preg_replace\s*\(\s*['"][^'"]{1,60}\/[a-z]*e[a-z]*['"]\s*,\s*\$_(GET|POST|REQUEST|COOKIE)/ nocase
    $s6 = /fsockopen\s*\([^;]{0,200};[\s\S]{0,400}(\/bin\/(ba)?sh|cmd\.exe)/ nocase
  condition:
    filesize < 2MB and $php and any of ($s*)
}

rule ORBITRON_PHP_AutoPrepend_Persistence
{
  meta:
    author      = "ORBITRON"
    date        = "2026-10-21"
    description = "auto_prepend_file / auto_append_file set in .user.ini, .htaccess or php.ini - common PHP persistence. Wordfence's WAF loader is excluded."
    severity    = "medium"
  strings:
    $a  = /(^|[\r\n])\s*(php_value\s+)?auto_(prepend|append)_file\s*[= ]\s*["']?[^\r\n"']{3,200}/ nocase
    $wf = "wordfence-waf.php" nocase
  condition:
    filesize < 256KB and $a and not $wf
}

rule ORBITRON_PHP_Session_UploadProgress_Artifact
{
  meta:
    author      = "ORBITRON"
    date        = "2026-10-21"
    description = "PHP session file containing session.upload_progress data. With session.upload_progress.cleanup=On this data is removed when the upload finishes, so leftovers point to interrupted/crashed requests or cleanup=Off. Hunting lead only - not proof of exploitation."
    reference   = "https://www.php.net/manual/en/session.upload-progress.php"
    severity    = "low"
  strings:
    $prefix = "upload_progress_" ascii
    $k1 = "\"start_time\";" ascii
    $k2 = "\"content_length\";" ascii
    $k3 = "\"bytes_processed\";" ascii
  condition:
    filesize < 1MB and $prefix and 2 of ($k*)
}
