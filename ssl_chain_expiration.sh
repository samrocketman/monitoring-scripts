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

# Days before expiration to trigger warnings.  Value is in seconds.
WARN_TO_EXPIRE=5184000 # sixty days in seconds
CRITICAL_TO_EXPIRE=2592000 # thirty days in seconds

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
    -c, --critical-expiration SECONDS
        Alert critical SECONDS before certificate expires.  Value is default to
        30 days or 2592000 seconds.
    -o, --oneline
        Compress output to one line of text.  This introduces flexibility in
        how the message is formatted for alternate monitoring systems.   By
        default, this option is disabled and output is according to a format
        valid for Icinga monitoring.
    -s, --skip-good
        This will only show warning or critical certificates.  If enabled this
        option will skip output of good results so that bad results are quickly
        available.  By default, this option is disabled so show good results.
    -w, --warn-expiration SECONDS
        Warn SECONDS before a certificate expires.  Value is default to 60 days
        or 5184000 seconds.

EXAMPLE USAGE
    Test a service
        ./ssl_chain_expiration.sh example.com
    Test a service customizing port.
        ./ssl_chain_expiration.sh example.com 443
    Test warn in 30 days and critically alert in 7 days.
        ./ssl_chain_expiration.sh -w 2592000 -c 604800 example.com
    Compress output to one line and only show certificate errors.
        ./ssl_chain_expiration.sh -o -s example.com

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
  # exit_warning
  # exit_critical

  warn_seconds_before_expire = warn_to_expire
  critical_seconds_before_expire = critical_to_expire
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
    datecmd = "date -jf \"%b %d %T %Y %Z\" \""expr_date"\" +%s"
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
    if(exit_warning > exit_result) {
      exit_result = exit_warning
    }
  }
  if((expr_date_epoch - datenow ) < critical_seconds_before_expire) {
    prefix = "CRITICAL NEAR EXPIRED:"
    exit_result = exit_critical
  }
  if((expr_date_epoch - datenow ) < 1 ) {
    prefix = "EXPIRED:"
    exit_result = exit_critical
  }
  if(skipgood == "true" && prefix == "GOOD:") {
    next
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
  if [ "$debug" = true -a -f "${TMP_DIR}/stderr" ]; then
    cat "${TMP_DIR}/stderr" >&2
  fi
  if [ "${oneline}" = true ]; then
    echo+=( -n )
  fi
  case $1 in
    0)
      "${echo[@]}" "OK: All certificates good for ${host}:${port}."
    ;;
    1)
      "${echo[@]}" "WARNING: Certificate in ${host}:${port} chain will expire soon."
    ;;
    2)
      "${echo[@]}" "CRITICAL: Certificate in ${host}:${port} chain has expired."
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
      -c|--critical-expiration)
        CRITICAL_TO_EXPIRE="$2"
        shift
        shift
      ;;
      --debug)
        debug=true
        shift
      ;;
      -o|--oneline)
        oneline=true
        shift
      ;;
      -s|--skip-good)
        skipgood=true
        shift
      ;;
      -w|--warn-expiration)
        WARN_TO_EXPIRE="$2"
        shift
        shift
      ;;
      -*)
        echo "ERROR: Invalid option provided '$1'.  See --help." >&2
        exit "${EXIT_UNKNOWN}"
      ;;
      *)
        if [ -z "${host:-}" ]; then
          host="$1"
        else
          if ! [ "$1" -gt 0 -a "$1" -lt 65535 ]; then
            echo "ERROR: Port '$1' must be a number between 1 and 65535" >&2
            exit 1
          fi
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

set -eo pipefail

oneline=false
skipgood=false
port=443
debug=false
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
    -showcerts < /dev/null 2> "${TMP_DIR}/stderr" | \
  gawk \
      -v kernel="$(uname -s)" \
      -v datenow="$(date +%s)" \
      -v exit_success="${EXIT_SUCCESS}" \
      -v exit_warning="${EXIT_WARNING}" \
      -v exit_critical="${EXIT_CRITICAL}" \
      -v warn_to_expire="${WARN_TO_EXPIRE}" \
      -v critical_to_expire="${CRITICAL_TO_EXPIRE}" \
      -v oneline="${oneline}" \
      -v skipgood="${skipgood}" \
      "$(awkscript)" > "${TMP_DIR}/status.txt"
