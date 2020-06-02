#!/bin/bash
# Created by Sam Gleske
# MIT License - https://github.com/samrocketman/monitoring-scripts

#dev environment
#Mon Jun  1 20:29:38 EDT 2020
#Ubuntu 18.04.4 LTS
#Linux 5.3.0-53-generic x86_64
#GNU bash, version 4.4.20(1)-release (x86_64-pc-linux-gnu)
#OpenSSL 1.1.1  11 Sep 2018
#GNU Awk 4.1.4, API: 1.1 (GNU MPFR 4.0.1, GNU MP 6.1.2)
#date (GNU coreutils) 8.28

# Checks an entire certificate chain of a remote service and alerts via exit
# code and stdout if any certificate in the remote chain is nearly expired
# (within 60 days) or expired.

# Requires:
#  - bash shell
#  - OpenSSL
#  - GNU Awk (available on Mac through homebrew)
#  - BSD date or GNU date

# Exit code states for monitoring systems.  The following is for Icinga.
# success   = SSL certificate chain is valid
# warning   = one of the certificates will expire within 60 days.
# critical  = one of the certificates in the chain has expired
EXIT_SUCCESS=0
EXIT_WARNING=1
EXIT_CRITICAL=2
EXIT_UNKNOWN=3 # only used by help text

# Days before expiration to trigger a warning.  Value is in seconds.
DAYS_TO_EXPIRE=5184000 # sixty days in seconds

function show_helptext() {
cat >&2 <<'EOF'
SYNOPSIS
    ssl_chain_expiration.sh HOST [PORT]

DESCRIPTION
    This monitoring script inspects TLS X.509 certificate chains and reports
    expirations for every certificate in the chain.

OPTIONS
    HOST - A hostname which has a TLS secured web service.  This script will
           connect and inspect the entire chain.
    PORT - A port to connect to the remote HOST.  By default 443.

EXAMPLE USAGE
    ./ssl_chain_expiration.sh example.com
    ./ssl_chain_expiration.sh example.com 443

EXIT STATUS:
    0 - success, All certificates valid for at least 60 days.
    1 - warning, One of the certificates in the chain will expire soon.
    2 - critical, One of the certificates in the chain has expired.
EOF
}

function awkscript() {
cat <<'EOF'
BEGIN {
  readcert = "false"
  endcert = "false"

  # good state
  exit_result = exit_success

  # error states
  almost_expired_exit_code = exit_warning
  expired_exit_code = exit_critical

  warn_seconds_before_expire = days_to_expire
}

$2 ~ /s:/ {
  subject = $0
}

$0 ~ /BEGIN CERTIFICATE/ {
  cert = $0
  readcert = "true"
  next
}

$0 ~ /END CERTIFICATE/ {
  cert = cert"\n"$0
  readcert = "false"
  endcert = "true"
}

readcert == "true" {
  cert = cert"\n"$0
}

endcert == "true" {
  endcert = "false"

  # https://www.gnu.org/software/gawk/manual/html_node/Getline_002fCoprocess.html
  coprocess = "openssl x509 -enddate"
  print cert |& coprocess
  coprocess |& getline expr_date
  close(coprocess)

  gsub(".*CN *= *", "", subject)
  gsub("notAfter=", "", expr_date)

  # Mac OS calculate with BSD date
  if(kernel == "Darwin") {
    datecmd = "date -jf '%b %d %T %Y %Z' \""expr_date"\" +%s"
    datecmd | getline expr_date_epoch
    close(datecmd)
  }

  # Linux calculate with GNU date
  if(kernel == "Linux") {
    datecmd = "date -d \""expr_date"\" +%s"
    datecmd | getline expr_date_epoch
    close(datecmd)
  }

  prefix = "GOOD:"
  if((expr_date_epoch - datenow ) < warn_seconds_before_expire) {
    prefix = "ALMOST EXPIRED:"
    exit_result = almost_expired_exit_code
  }
  if((expr_date_epoch - datenow ) < 1 ) {
    prefix = "EXPIRED:"
    exit_result = expired_exit_code
  }
  print prefix, subject, "expires", expr_date"."
}

END {
  exit(exit_result)
}
EOF
}

#
# MAIN EXECUTION
#

set -e

host="${1:-}"
port="${2:-443}"

if [ "$host" = '--help' ] || \
   [ "$host" = '-help' ] || \
   [ "$host" = '-h' ] || \
   [ -z "$host" ]; then
  show_helptext
  exit "${EXIT_UNKNOWN}"
fi

# openssl | gawk which calls date and openssl on each certificate
openssl s_client \
    -servername "$host" \
    -connect "$host":"$port" \
    -showcerts < /dev/null 2> /dev/null | \
  gawk \
      -v kernel="$(uname -s)" \
      -v datenow="$(date +%s)" \
      -v exit_success="${EXIT_SUCCESS}" \
      -v exit_warning="${EXIT_WARNING}" \
      -v exit_critical="${EXIT_CRITICAL}" \
      -v days_to_expire="${DAYS_TO_EXPIRE}" \
      "$(awkscript)"
