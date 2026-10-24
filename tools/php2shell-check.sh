#!/bin/bash
# php2shell-check.sh - read-only check for PHP2Shell (CVE-2026-109618, CVE-2026-109619) on a Linux host.
#
# MIT License
# Copyright (c) 2026 Brandefense
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
# documentation files (the "Software"), to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and
# to permit persons to whom the Software is furnished to do so, subject to the following conditions:
# The above copyright notice and this permission notice shall be included in all copies or substantial portions of
# the Software. THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
# NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
#
# What it does: reports four evidences that "the running system is fixed", not only "a patch is installed":
#   1 package     installed PHP packages; fixed upstream version, or a distro changelog that names BOTH CVEs
#   2 runtime     the PHP that really serves HTTP (php-fpm, Apache libphp, LiteSpeed, FrankenPHP), not just `php -v`
#   3 process     running workers whose binary or PHP module was replaced/deleted after the update, start time vs
#                 package install time
#   4 deployment  local docker/podman images and running containers with their PHP version
# plus the ini values relevant to the temporary controls (INFO lines).
#
# Read-only: it reads /proc, package databases, config files and the bytes of PHP binaries (version string), and runs
# `docker|podman ps|images|exec php -v` (that one runs INSIDE a container). It NEVER executes a binary it found on the host
# or via /proc. It makes NO network calls, writes nothing, sends no exploit traffic.
# Run as root for a complete process check (other users' /proc entries are unreadable otherwise).
#
# Exit codes: 0 all PASS (INFO/N/A only), 1 at least one WARN, 2 at least one FAIL, 3 nothing PHP-related found.
# Fixed upstream: 8.2.35, 8.3.36, 8.4.27, 8.5.12. PHP 8.1 and older get no upstream fix: only a vendor backport counts.

set -u
export LC_ALL=C
CVE1="CVE-2026-109618"; CVE2="CVE-2026-109619"
VERSION="1.0.0"
DO_CONT=1; QUIET=0
for a in "$@"; do
  case "$a" in
    --no-containers) DO_CONT=0 ;;
    --quiet) QUIET=1 ;;
    -h|--help) sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    --version) echo "php2shell-check $VERSION"; exit 0 ;;
    *) echo "unknown option: $a (try --help)" >&2; exit 3 ;;
  esac
done

if [ -t 1 ]; then R=$'\033[31m'; Y=$'\033[33m'; G=$'\033[32m'; B=$'\033[36m'; Z=$'\033[0m'; else R=; Y=; G=; B=; Z=; fi
NPASS=0; NWARN=0; NFAIL=0; NINFO=0; FOUND=0
emit() { # level section text
  case "$1" in
    PASS) NPASS=$((NPASS+1)); c=$G ;;
    WARN) NWARN=$((NWARN+1)); c=$Y ;;
    FAIL) NFAIL=$((NFAIL+1)); c=$R ;;
    INFO) NINFO=$((NINFO+1)); c=$B; [ "$QUIET" = 1 ] && return ;;
    *) c= ;;
  esac
  printf '%s[%s]%s %-10s %s\n' "$c" "$1" "$Z" "$2" "$3"
}

# ---- version helpers -------------------------------------------------------------------------------------
# upstream_of <packager version>: strip epoch and distro suffix ("1:8.2.35-1~deb12u1" -> 8.2.35); a pre-release
# (dev, alpha, beta, RC) keeps a marker: "8.6.0RC1" -> 8.6.0-pre
upstream_of() {
  local v pre='[-~]?(dev|alpha|beta|RC|rc|Alpha|Beta|pre)[0-9]*'
  v=$(printf '%s' "$1" | sed -E 's/^[0-9]+://')
  if printf '%s' "$v" | grep -qE "^[0-9]+\.[0-9]+\.[0-9]+$pre"; then
    printf '%s' "$v" | sed -E 's/^([0-9]+\.[0-9]+\.[0-9]+).*/\1-pre/'
  else
    printf '%s' "$v" | sed -E 's/^([0-9]+\.[0-9]+\.[0-9]+).*/\1/'
  fi
}
# fixed_state <version>: prints fixed | vulnerable | unknown   (upstream numbering only)
# Pre-releases (dev/alpha/beta/RC) are never "fixed": below the fixed patch of a known line they are vulnerable,
# otherwise unknown. Only a final release at or above the fixed one is fixed.
fixed_state() {
  local v pre=0 ma mi pa
  v=$(upstream_of "$1")
  case "$v" in *-pre) pre=1; v=${v%-pre} ;; esac
  case "$v" in [0-9]*.[0-9]*.[0-9]*) ;; *) echo unknown; return ;; esac
  ma=${v%%.*}; mi=${v#*.}; mi=${mi%%.*}; pa=${v##*.}; pa=${pa%%[!0-9]*}
  if [ "$ma" -lt 8 ] 2>/dev/null; then echo vulnerable; return; fi
  if [ "$ma" -gt 8 ] 2>/dev/null; then [ "$pre" = 1 ] && echo unknown || echo fixed; return; fi
  case "$mi" in
    0|1) echo vulnerable; return ;;
    2) fx=35 ;; 3) fx=36 ;; 4) fx=27 ;; 5) fx=12 ;;
    *) [ "$pre" = 1 ] && echo unknown || echo fixed; return ;;   # 8.6 and newer: only a final release counts
  esac
  if [ "$pa" -lt "$fx" ]; then echo vulnerable
  elif [ "$pre" = 1 ]; then echo unknown
  else echo fixed; fi
}
have() { command -v "$1" >/dev/null 2>&1; }
# in_other_ns <pid>: true when the process lives in another mount namespace (a container seen from the host)
in_other_ns() { [ "$(readlink "/proc/$1/ns/mnt" 2>/dev/null)" != "$(readlink /proc/self/ns/mnt 2>/dev/null)" ]; }
TMP=$(mktemp -d 2>/dev/null || echo /tmp/p2s.$$); mkdir -p "$TMP"; trap 'rm -rf "$TMP"' EXIT
PKGSTATE="$TMP/pkgstate"; : > "$PKGSTATE"   # lines: <owner-key>\t<state>\t<text>   state=OK|BAD|UNSURE

# ---- 1. PACKAGE ------------------------------------------------------------------------------------------
echo "== 1. package evidence (is the fix installed?)"
changelog_hits() { # pkg -> prints "n_cve1 n_cve2 source" or nothing when no changelog is readable
  local pkg="$1" f out=""
  if have dpkg-query; then
    for d in "$pkg" "${pkg%-*}-common" "$(printf '%s' "$pkg" | sed -E 's/^(php[0-9.]*)-.*/\1-common/')" "$(printf '%s' "$pkg" | sed -E 's/^libapache2-mod-(php[0-9.]*)/\1-common/')"; do
      for f in "/usr/share/doc/$d/changelog.Debian.gz" "/usr/share/doc/$d/changelog.gz"; do
        [ -r "$f" ] && { out=$(zcat "$f" 2>/dev/null); src=$f; break 2; }
      done
    done
  elif have rpm; then
    out=$(rpm -q --changelog "$pkg" 2>/dev/null); src="rpm -q --changelog $pkg"
  fi
  [ -n "$out" ] || return 1
  printf '%s %s %s\n' "$(printf '%s' "$out" | grep -c "$CVE1")" "$(printf '%s' "$out" | grep -c "$CVE2")" "$src"
}
pkglist="$TMP/pkgs"; : > "$pkglist"
if have dpkg-query; then
  dpkg-query -W -f='${Package}\t${Version}\t${db:Status-Abbrev}\n' 'php*' 'libapache2-mod-php*' 'frankenphp*' 'lsphp*' 2>/dev/null \
    | awk -F'\t' '$3 ~ /^ii/ && $1 ~ /^(php[0-9.]*-(fpm|cli|cgi|common|apache2|embed)|php-fpm|php-cli|libapache2-mod-php[0-9.]*|lsphp.*|frankenphp.*)$/ {print $1"\t"$2}' > "$pkglist"
elif have rpm; then
  rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\n' 2>/dev/null | grep -E '^(php[0-9]*(-php)?-?(fpm|cli|cgi|common|embedded)?|mod_php|lsphp[0-9]*|frankenphp)\b' | grep -E '^(php|mod_php|lsphp|frankenphp)' | grep -Ev 'php-(pear|pecl)' > "$pkglist"
elif have apk; then
  apk info -v 2>/dev/null | grep -E '^php[0-9]*(-fpm|-cli|-cgi|-common|-apache2)?-[0-9]' | sed -E 's/^(php[0-9]*(-[a-z0-9]+)?)-([0-9].*)$/\1\t\3/' > "$pkglist"
fi
if [ ! -s "$pkglist" ]; then
  emit INFO package "no distro PHP packages found (source/docker build, vendor tarball or other packager); rely on sections 2-4"
else
  FOUND=1
  while IFS="$(printf '\t')" read -r pkg ver; do
    up=$(upstream_of "$ver"); st=$(fixed_state "$up")
    ch=$(changelog_hits "$pkg") ; n1=0; n2=0; src=""
    [ -n "$ch" ] && { n1=${ch%% *}; r=${ch#* }; n2=${r%% *}; src=${r#* }; }
    if [ "$st" = fixed ]; then
      emit PASS package "$pkg $ver  upstream $up >= fixed release"; printf '%s\tOK\t%s\n' "$pkg" "$ver" >> "$PKGSTATE"
    elif [ "$st" = unknown ]; then
      emit WARN package "$pkg $ver  pre-release or unreadable version: cannot be proven fixed (only a final release at or above the fixed one counts)"; printf '%s\tUNSURE\t%s\n' "$pkg" "$ver" >> "$PKGSTATE"
    elif [ -n "$ch" ] && [ "$n1" -gt 0 ] && [ "$n2" -gt 0 ]; then
      emit PASS package "$pkg $ver  upstream $up is older but the package changelog names BOTH $CVE1 and $CVE2 (backport) [$src]"; printf '%s\tOK\t%s\n' "$pkg" "$ver" >> "$PKGSTATE"
    elif [ -n "$ch" ] && { [ "$n1" -gt 0 ] || [ "$n2" -gt 0 ]; }; then
      emit WARN package "$pkg $ver  changelog names only one of $CVE1 / $CVE2 (found $n1/$n2); both are needed"; printf '%s\tUNSURE\t%s\n' "$pkg" "$ver" >> "$PKGSTATE"
    elif [ -n "$ch" ]; then
      emit FAIL package "$pkg $ver  upstream $up is below the fixed release and the changelog names neither CVE"; printf '%s\tBAD\t%s\n' "$pkg" "$ver" >> "$PKGSTATE"
    else
      emit WARN package "$pkg $ver  upstream $up is below the fixed release and no changelog is readable here (alpine, minimal image?): check the distro advisory for $CVE1 and $CVE2"; printf '%s\tUNSURE\t%s\n' "$pkg" "$ver" >> "$PKGSTATE"
    fi
  done < "$pkglist"
fi

# ---- 2. RUNTIME ------------------------------------------------------------------------------------------
echo "== 2. runtime evidence (which PHP serves HTTP?)"
RTLIST="$TMP/runtimes"; : > "$RTLIST"   # kind \t path \t version
add_rt() { grep -qF "$(printf '%s\t%s\t' "$1" "$2")" "$RTLIST" 2>/dev/null || printf '%s\t%s\t%s\n' "$1" "$2" "$3" >> "$RTLIST"; }
bin_version() { # static read, never executes the file: the compiled-in banner "PHP/x.y.z" (X-Powered-By)
  [ -f "$1" ] && [ -r "$1" ] || return 0
  grep -a -o -E 'PHP/[0-9]+\.[0-9]+\.[0-9]+([-~]?(dev|alpha|beta|RC|rc)[0-9]*)?' "$1" 2>/dev/null | head -1 | sed 's#PHP/##'
}
owner_pkg() { # file -> package name or empty
  if have dpkg; then dpkg -S "$1" 2>/dev/null | head -1 | sed 's/:.*//; s/, .*//'
  elif have rpm; then rpm -qf --qf '%{NAME}\n' "$1" 2>/dev/null | head -1 | grep -v 'not owned'
  elif have apk; then apk info -W "$1" 2>/dev/null | sed -n 's/.* is owned by \(.*\)-[0-9].*/\1/p' | head -1
  fi
}
# a) php-fpm binaries on disk and from running masters (the running exe runs even if deleted)
for b in $(command -v php-fpm 2>/dev/null) /usr/sbin/php-fpm* /usr/local/sbin/php-fpm /opt/remi/php*/root/usr/sbin/php-fpm /opt/plesk/php/*/sbin/php-fpm /usr/local/php*/sbin/php-fpm*; do
  [ -x "$b" ] && [ -f "$b" ] && add_rt "php-fpm(disk)" "$b" "$(bin_version "$b")"
done
for p in /proc/[0-9]*; do
  pid=${p#/proc/}; cmd=$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null)
  case "$cmd" in
    "php-fpm: master"*|"php-fpm8"*|"php-fpm "*|*"/php-fpm"*) ;;
    *) continue ;;
  esac
  [ -r "$p/exe" ] || continue
  in_other_ns "$pid" && continue   # containers are judged in section 4
  if [ "$(stat -c %u "$p/exe" 2>/dev/null)" != "0" ]; then   # a process named php-fpm whose binary is not root-owned is not trusted
    emit WARN runtime "process $pid is named like php-fpm but its binary is not owned by root: not trusted, version not read"; continue
  fi
  v=$(bin_version "$p/exe"); [ -n "$v" ] && add_rt "php-fpm(running pid $pid)" "$(readlink "$p/exe" 2>/dev/null)" "$v"
done
# b) Apache mod_php: libphp files referenced by the config and mapped into running httpd processes
for f in $(grep -rhoE 'LoadModule +php[0-9_a-z]*_module +[^ ]+' /etc/apache2 /etc/httpd /usr/local/apache2/conf /etc/apache2/mods-enabled 2>/dev/null | awk '{print $3}'); do
  case "$f" in /*) lib="$f" ;; *) lib=""; for d in /usr/lib/apache2/modules /usr/lib64/httpd/modules /etc/httpd /usr/local/apache2 /usr/lib/apache2/modules; do [ -f "$d/$f" ] && lib="$d/$f"; done ;; esac
  [ -n "$lib" ] && [ -f "$lib" ] && add_rt "apache-mod_php(disk)" "$lib" "$(grep -a -o -E 'PHP/[0-9]+\.[0-9]+\.[0-9]+' "$lib" 2>/dev/null | head -1 | sed 's#PHP/##')"
done
for p in /proc/[0-9]*; do
  [ -r "$p/maps" ] || continue
  in_other_ns "${p#/proc/}" && continue   # containers are judged in section 4
  m=$(grep -a -oE '/[^ ]*libphp[0-9._]*\.so[^ ]*' "$p/maps" 2>/dev/null | head -1); [ -n "$m" ] || continue
  lib=${m% (deleted)}; [ -r "$p/map_files" ] || true
  v=""; [ -f "$lib" ] && v=$(grep -a -o -E 'PHP/[0-9]+\.[0-9]+\.[0-9]+' "$lib" 2>/dev/null | head -1 | sed 's#PHP/##')
  add_rt "apache-mod_php(mapped by pid ${p#/proc/})" "$m" "$v"
done
# c) LiteSpeed / lsphp, FrankenPHP, php-cgi
for b in /usr/local/lsws/lsphp*/bin/lsphp /opt/cpanel/ea-php*/root/usr/bin/lsphp $(command -v lsphp 2>/dev/null); do
  [ -x "$b" ] && add_rt "litespeed-lsphp" "$b" "$(bin_version "$b")"
done
for b in $(command -v frankenphp 2>/dev/null) /usr/local/bin/frankenphp; do
  [ -x "$b" ] && add_rt "frankenphp" "$b" "$(bin_version "$b")"
done
for b in $(command -v php-cgi 2>/dev/null); do [ -x "$b" ] && add_rt "php-cgi" "$b" "$(bin_version "$b")"; done
# d) CLI php: informational only
CLI=$(command -v php 2>/dev/null); [ -n "$CLI" ] && emit INFO runtime "CLI php $CLI = $(bin_version "$CLI") (read from the file, not run; the CLI says nothing about what serves HTTP)"

if [ ! -s "$RTLIST" ]; then
  emit INFO runtime "no php-fpm / Apache mod_php / LiteSpeed / FrankenPHP found on this host (containers: see section 4)"
else
  FOUND=1
  sort -u "$RTLIST" | while IFS="$(printf '\t')" read -r kind path ver; do
    clean=${path% (deleted)}; echo "$kind|$clean|$ver"
  done > "$TMP/rt2"
  while IFS='|' read -r kind path ver; do
    if [ -z "$ver" ]; then emit WARN runtime "$kind $path : version not readable"; continue; fi
    up=$(upstream_of "$ver"); st=$(fixed_state "$up")
    own=$(owner_pkg "$path"); ostate=""
    [ -n "$own" ] && ostate=$(awk -F'\t' -v p="$own" '$1==p{print $2; exit}' "$PKGSTATE")
    if [ "$st" = fixed ]; then emit PASS runtime "$kind $path = $ver (>= fixed release)"
    elif [ "$st" = unknown ]; then emit WARN runtime "$kind $path = $ver : pre-release or unreadable version, cannot be proven fixed"
    elif [ "$ostate" = OK ]; then emit PASS runtime "$kind $path = $ver : owned by package $own whose changelog names both CVEs (backport)"
    elif [ "$ostate" = BAD ]; then emit FAIL runtime "$kind $path = $ver : below fixed release, package $own has no fix"
    else emit FAIL runtime "$kind $path = $ver : below the fixed release and no backport proof${own:+ (package $own)}"; fi
  done < "$TMP/rt2"
fi

# ---- 3. PROCESS ------------------------------------------------------------------------------------------
echo "== 3. process evidence (is a worker still running the old code?)"
BTIME=$(awk '/^btime/{print $2}' /proc/stat 2>/dev/null); HZ=$(getconf CLK_TCK 2>/dev/null || echo 100)
NPROC=0; UNREAD=0; UNINH=0; F0=$NFAIL; W0=$NWARN
for p in /proc/[0-9]*; do
  pid=${p#/proc/}; comm=$(cat "$p/comm" 2>/dev/null) || continue
  cmd=$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null)
  case "$comm|$cmd" in
    php-fpm*|*"php-fpm:"*|apache2*|httpd*|lsphp*|litespeed*|frankenphp*|php-cgi*|php-cgi\ *) ;;
    *) continue ;;
  esac
  NPROC=$((NPROC+1))
  exe=$(readlink "$p/exe" 2>/dev/null)
  if [ -z "$exe" ]; then
    pp=$(awk '{print $4}' "$p/stat" 2>/dev/null)
    if [ -n "$pp" ] && grep -q "^$pp|" "$TMP/procs" 2>/dev/null; then UNINH=$((UNINH+1)); else UNREAD=$((UNREAD+1)); fi
    continue
  fi
  echo "$pid|$comm|$exe" >> "$TMP/procs"
  # start time (epoch)
  st=$(awk '{print $22}' "$p/stat" 2>/dev/null | head -1); start=""
  [ -n "$BTIME" ] && [ -n "$st" ] && start=$((BTIME + st / HZ))
  # in a container? (different mount namespace than init)
  incont=""; in_other_ns "$pid" && incont=1
  stale=""
  case "$exe" in *"(deleted)"*) stale="binary $exe was replaced or deleted after the process started" ;; esac
  if [ -z "$stale" ] && [ -r "$p/maps" ]; then
    d=$(grep -a -E '(libphp[0-9._]*\.so|/php[0-9a-z._-]*\.so|libphp)[^ ]* \(deleted\)|\.so[^ ]*php[^ ]* \(deleted\)' "$p/maps" 2>/dev/null | awk '{print $6}' | sort -u | head -2 | tr '\n' ' ')
    [ -n "$d" ] && stale="mapped PHP library was replaced after start: $d"
  fi
  if [ -n "$stale" ]; then
    emit FAIL process "pid $pid ($comm${incont:+, container}) $stale : restart it (the old code is still serving)"
    continue
  fi
  # start time versus package install time of the owning package
  if [ -z "$incont" ] && [ -n "$start" ]; then
    own=$(owner_pkg "$exe"); inst=""
    if [ -n "$own" ]; then
      if have dpkg; then inst=$(stat -c %Y "/var/lib/dpkg/info/$own.list" 2>/dev/null)
      elif have rpm; then inst=$(rpm -q --qf '%{INSTALLTIME}' "$own" 2>/dev/null); fi
    fi
    if [ -n "$inst" ] && [ "$start" -lt "$inst" ] 2>/dev/null; then
      emit WARN process "pid $pid ($comm) started $(date -d @"$start" '+%F %T' 2>/dev/null || echo "$start") BEFORE package $own was installed/updated ($(date -d @"$inst" '+%F %T' 2>/dev/null || echo "$inst")): restart to be sure"
    fi
  fi
done
if [ "$NPROC" -eq 0 ]; then
  emit INFO process "no PHP-serving processes visible on the host (php-fpm, apache2/httpd, lsphp, frankenphp, php-cgi)"
else
  FOUND=1
  [ "$UNINH" -gt 0 ] && emit INFO process "$UNINH worker(s) of another user could not be read (no ptrace capability, typical inside containers); judged by their parent process, which was inspected"
  [ "$UNREAD" -gt 0 ] && emit WARN process "$UNREAD process(es) could not be inspected and have no inspected parent (run as root, with CAP_SYS_PTRACE in containers)"
  if [ "$NFAIL" -eq "$F0" ] && [ "$NWARN" -eq "$W0" ] && [ -s "$TMP/procs" ]; then
    emit PASS process "inspected $(wc -l < "$TMP/procs") PHP-serving process(es): no deleted executable, no replaced PHP library, none older than its package"
  fi
fi

# ---- 4. DEPLOYMENT (containers) --------------------------------------------------------------------------
echo "== 4. deployment evidence (containers and images on this host)"
if [ "$DO_CONT" = 0 ]; then
  emit INFO deployment "skipped (--no-containers)"
else
  CE=""; have docker && CE=docker; [ -z "$CE" ] && have podman && CE=podman
  if [ -z "$CE" ]; then
    emit INFO deployment "no docker/podman CLI here; check Kubernetes, ECS and CI images separately (this script does not)"
  elif ! timeout 10 "$CE" ps >/dev/null 2>&1; then
    emit WARN deployment "$CE is installed but not usable by this user (permission or daemon down)"
  else
    FOUND=1; ANYC=0
    timeout 20 "$CE" ps --format '{{.ID}}\t{{.Image}}\t{{.Names}}' 2>/dev/null | while IFS="$(printf '\t')" read -r id img name; do
      out=$(timeout 15 "$CE" exec "$id" sh -c 'v=$(php -v 2>/dev/null | head -1); f=$(php-fpm -v 2>/dev/null | head -1); a=$(apache2 -v 2>/dev/null | head -1; httpd -v 2>/dev/null | head -1); printf "%s | %s | %s" "$v" "$f" "$a"' 2>/dev/null) || out=""
      ver=$(printf '%s' "$out" | grep -o -E 'PHP [0-9]+\.[0-9]+\.[0-9]+([-~]?(dev|alpha|beta|RC|rc)[0-9]*)?' | head -1 | sed 's/PHP //')
      if [ -z "$ver" ]; then continue; fi
      st=$(fixed_state "$ver")
      if [ "$st" = fixed ]; then echo "PASS|container $name ($img) runs PHP $ver (>= fixed release)"
      elif [ "$st" = unknown ]; then echo "WARN|container $name ($img) runs PHP $ver : pre-release or unreadable version, cannot be proven fixed"
      else echo "FAIL|container $name ($img) runs PHP $ver (below fixed release): rebuild the image from a fixed base and redeploy every replica; its processes are separate from the host's"; fi
    done > "$TMP/cont"
    while IFS='|' read -r lvl txt; do emit "$lvl" deployment "$txt"; ANYC=1; done < "$TMP/cont"
    [ "$ANYC" = 0 ] && emit INFO deployment "no running container with a readable PHP version"
    # images: only pinned tags can be judged without running them
    timeout 20 "$CE" images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | sort -u | while read -r ref; do
      t=${ref#*:}; r=${ref%%:*}
      case "$r" in php|*/php|*/php-fpm|*/php-apache|*/php-cli) ;; *) continue ;; esac
      v=$(printf '%s' "$t" | grep -o -E '^[0-9]+\.[0-9]+\.[0-9]+([-~]?(dev|alpha|beta|RC|rc)[0-9]*)?' | head -1)
      if [ -z "$v" ]; then echo "WARN|image $ref has a floating tag: its PHP version depends on when it was pulled; pull again and redeploy"; continue; fi
      if [ "$(fixed_state "$v")" = unknown ]; then echo "WARN|image $ref pins PHP $v : pre-release, cannot be proven fixed"
      elif [ "$(fixed_state "$v")" = fixed ]; then echo "PASS|image $ref (PHP $v >= fixed release)"; else echo "WARN|image $ref pins PHP $v (below fixed release): do not deploy it; rebuild on a fixed tag"; fi
    done > "$TMP/imgs"
    while IFS='|' read -r lvl txt; do emit "$lvl" deployment "$txt"; done < "$TMP/imgs"
  fi
fi

# ---- ini values for the temporary controls (INFO only) ---------------------------------------------------
echo "== ini values relevant to the temporary controls (informational; patching is the only complete fix)"
show_ini() { # label cmd...
  lbl="$1"; shift
  out=$("$@" 2>/dev/null | grep -E '^(session\.upload_progress\.(enabled|name)|memory_limit|post_max_size|fatal_error_backtraces|max_input_vars|max_file_uploads)\b' | tr '\n' ';' | sed 's/ => /=/g')
  [ -n "$out" ] && emit INFO ini "$lbl: $out"
}
# (no `<binary> -i`: ini values are read from the config files below; discovered binaries are never executed)
for d in /etc/php*/fpm/pool.d /etc/php-fpm.d /usr/local/etc/php-fpm.d /etc/opt/remi/php*/php-fpm.d /etc/php/*/fpm/pool.d; do
  [ -d "$d" ] || continue
  g=$(grep -hE '^\s*php(_admin)?_(value|flag)\[(session\.upload_progress\.[a-z]+|memory_limit|post_max_size|fatal_error_backtraces)\]|^\s*pm\.max_requests' "$d"/*.conf 2>/dev/null | tr -s ' ' | tr '\n' ';')
  [ -n "$g" ] && emit INFO ini "FPM pool overrides in $d: $g"
done
for d in /etc/apache2 /etc/httpd /usr/local/apache2/conf; do
  [ -d "$d" ] || continue
  g=$(grep -rhE '^\s*php_(admin_)?(value|flag)\s+(session\.upload_progress\.[a-z]+|memory_limit|post_max_size|fatal_error_backtraces)' "$d" 2>/dev/null | tr -s ' ' | tr '\n' ';')
  [ -n "$g" ] && emit INFO ini "Apache php_value/php_flag in $d: $g"
done
for f in /etc/php*/*/php.ini /etc/php.ini /usr/local/etc/php/php.ini /etc/php/*/*/conf.d/*.ini /usr/local/etc/php/conf.d/*.ini /etc/php.d/*.ini; do
  [ -r "$f" ] || continue
  g=$(grep -hE '^\s*(session\.upload_progress\.(enabled|name)|memory_limit|post_max_size|fatal_error_backtraces)\s*=' "$f" 2>/dev/null | tr -d ' ' | tr '\n' ';')
  [ -n "$g" ] && emit INFO ini "$f: $g"
done
emit INFO ini "per-directory .user.ini / .htaccess files are not scanned; ini_set() in application code runs after request parsing"

# ---- summary ---------------------------------------------------------------------------------------------
echo "== summary: $NPASS PASS, $NWARN WARN, $NFAIL FAIL, $NINFO INFO"
if [ "$FOUND" = 0 ]; then echo "nothing PHP-related found on this host"; exit 3; fi
if [ "$NFAIL" -gt 0 ]; then echo "RESULT: FAIL - at least one runtime, process or container is not proven fixed"; exit 2; fi
if [ "$NWARN" -gt 0 ]; then echo "RESULT: WARN - fixed where proven, but some evidence is missing or a restart is needed"; exit 1; fi
echo "RESULT: PASS - package, runtime, process and deployment evidence all show the fixes"; exit 0
