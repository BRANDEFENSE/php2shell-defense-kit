// Original Brandefense heuristics. MIT. Text files only; no CVE-specific attribution.
// Scan copied web roots offline. Matches require manual review, never auto-delete.
rule BD_PHP_Direct_Request_Command : php webshell heuristic {
 meta:
  author = "Brandefense Research Team"
  date = "2026-10-24"
  description = "Direct request superglobal passed to an execution function; heuristic, not PHP2Shell proof"
  scope = "generic_post_exploitation"
  license = "MIT"
 strings:
  $php = "<?php" nocase
  $exec = /\b(system|exec|shell_exec|passthru|popen|proc_open)[ \t\r\n]*\([ \t\r\n]*\$_(GET|POST|REQUEST|COOKIE)[ \t]*\[/ nocase
 condition:
  filesize < 2MB and $php in (0..4096) and $exec
}

rule BD_PHP_Encoded_Eval_Loader : php loader heuristic {
 meta:
  author = "Brandefense Research Team"
  date = "2026-10-24"
  description = "PHP eval immediately wrapping common decoding chains; obfuscation and legitimate packers can evade or match"
  scope = "generic_post_exploitation"
  license = "MIT"
 strings:
  $php = "<?php" nocase
  $eval = /\beval[ \t\r\n]*\([ \t\r\n]*(base64_decode|gzinflate|gzuncompress|str_rot13)[ \t\r\n]*\(/ nocase
 condition:
  filesize < 2MB and $php in (0..4096) and $eval
}

rule BD_PHP_Request_Driven_File_Write : php file_writer heuristic {
 meta:
  author = "Brandefense Research Team"
  date = "2026-10-24"
  description = "File write whose content is decoded request input, or whose path is chosen by the request; narrowed so ordinary CMS and plugin writers do not match; heuristic, not PHP2Shell proof"
  scope = "generic_post_exploitation"
  license = "MIT"
 strings:
  $php = "<?php" nocase
  $decoded = /\b(file_put_contents|fwrite|fputs)[ \t\r\n]*\([^;]{0,160}base64_decode[ \t\r\n]*\([ \t\r\n]*\$_(GET|POST|REQUEST|COOKIE)[ \t]*\[/ nocase
  $pathctl = /\bfile_put_contents[ \t\r\n]*\([ \t\r\n]*\$_(GET|POST|REQUEST|COOKIE)[ \t]*\[/ nocase
 condition:
  filesize < 2MB and $php in (0..4096) and ($decoded or $pathctl)
}

rule BD_PHP_Socket_And_Process_Primitives : php reverse_shell_candidate heuristic {
 meta:
  author = "Brandefense Research Team"
  date = "2026-10-24"
  description = "Socket and process primitives together; no data-flow proof and no PHP2Shell attribution"
  scope = "generic_post_exploitation"
  license = "MIT"
 strings:
  $php = "<?php" nocase
  $sock1 = /\bfsockopen[ \t\r\n]*\(/ nocase
  $sock2 = /\bstream_socket_client[ \t\r\n]*\(/ nocase
  $proc1 = /\bproc_open[ \t\r\n]*\(/ nocase
  $proc2 = /\bpopen[ \t\r\n]*\(/ nocase
  $proc3 = /\bshell_exec[ \t\r\n]*\(/ nocase
 condition:
  filesize < 2MB and $php in (0..4096) and 1 of ($sock*) and 1 of ($proc*)
}

rule BD_PHP_Upload_Progress_Research_Artifact : research triage {
 meta:
  author = "Brandefense Research Team"
  date = "2026-10-24"
  description = "Research or tooling text mentioning PHP2Shell and upload progress; includes legitimate defensive documents"
  scope = "research_artifact_not_malware"
  license = "MIT"
 strings:
  $name = "php2shell" nocase
  $cve1 = "CVE-2026-109618" nocase
  $cve2 = "CVE-2026-109619" nocase
  $field = "PHP_SESSION_UPLOAD_PROGRESS"
 condition:
  filesize < 5MB and ($name or $cve1 or $cve2) and $field
}
