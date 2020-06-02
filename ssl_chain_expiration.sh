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
TIME_TO_EXPIRE=5184000 # sixty days in seconds

function show_helptext() {
cat >&2 <<'EOF'
SYNOPSIS
    ssl_chain_expiration.sh [OPTIONS] HOST [PORT]

DESCRIPTION
    This monitoring script inspects TLS X.509 certificate chains and reports
    expirations for every certificate in the chain.

ARGUMENTS
    HOST - A hostname which has a TLS secured web service.  This script will
           connect and inspect the entire chain.
    PORT - A port to connect to the remote HOST.  By default 443.

OPTIONS
    -s, --warn-expiration SECONDS
        Warn SECONDS before a certificate expires.  Value is default to 60 days
        or 5184000 seconds.
    -o, --oneline
        Compress output to one line of text.  This introduces flexibility in
        how the message is formatted for alternate monitoring systems.   By
        default, this option is disabled and output is according to a format
        valid for Icinga monitoring.

EXAMPLE USAGE
    Test a service
        ./ssl_chain_expiration.sh example.com
    Test a service customizing port.
        ./ssl_chain_expiration.sh example.com 443
    Test a service for expiring within 30 days.
        ./ssl_chain_expiration.sh --warn-expiration 2592000 example.com
        ./ssl_chain_expiration.sh -s 2592000 example.com

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

  warn_seconds_before_expire = seconds_to_expire
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
  if(oneline == "true") {
    oneline_text = oneline_text"  "prefix" "subject" expires "expr_date"."
  }
  else {
    print prefix, subject, "expires", expr_date"."
  }
}

END {
  if(oneline == "true") {
    print oneline_text
  }
  exit(exit_result)
}
EOF
}

function overall_status() {
  echo=( echo )
  if [ "${oneline}" = true ]; then
    echo+=( -n )
  fi
  case $1 in
    0)
      "${echo[@]}" 'OK: All certificates good.'
    ;;
    1)
      "${echo[@]}" 'WARNING: One or more certificates in the chain will expire soon.'
    ;;
    2)
      "${echo[@]}" 'CRITICAL: One or more certificates in the chain has expired.'
    ;;
    *)
      "${echo[@]}" 'UNKNOWN: an unknown error has occurred.'
    ;;
  esac
  [ ! -e "${TMP_DIR}/status.txt" ] || cat "${TMP_DIR}/status.txt"
  [ ! -d "${TMP_DIR:-}" ] || rm -rf "${TMP_DIR}"
}

function parse_options() {
  while [ "$#" -gt 0 ]; do
    case $1 in
      --help|-help|-h)
        show_helptext
        exit "${EXIT_UNKNOWN}"
      ;;
      -o|--oneline)
        oneline=true
        shift
      ;;
      -s|--warn-expiration)
        TIME_TO_EXPIRE="$2"
        shift
        shift
      ;;
      *)
        if [ -z "${host:-}" ]; then
          host="$1"
        else
          port="$1"
        fi
        shift
      ;;
    esac
  done
}

#
# MAIN EXECUTION
#

set -e

oneline=false
port=443
parse_options "$@"

if [ -z "${host:-}" ]; then
  echo 'ERROR: missing HOST argument.'
  show_helptext
  exit "${EXIT_UNKNOWN}"
fi

trap 'overall_status $?' EXIT
TMP_DIR="$(mktemp -d)"

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
      -v seconds_to_expire="${TIME_TO_EXPIRE}" \
      -v oneline="${oneline}" \
      "$(awkscript)" > "${TMP_DIR}/status.txt"
