#!/bin/bash

shopt -s nullglob
MAILTO='user@example.com' # UPDATE THIS

# regularly updated list of valid TLDs and their own SLDs at
# https://publicsuffix.org/list/public_suffix_list.dat
# but the below should be enough in most cases
SLDS='ac|biz|co?|edu?|go?v|mil|net|nom|org?'

DATE=$(date +"%d_%m_%Y__%H_%M_%S" | tr -d '\n')

ANSI_RED=$'\e[31m'
ANSI_GREEN=$'\e[32m'
ANSI_YELLOW=$'\e[33m'
ANSI_BLUE=$'\e[34m'
ANSI_MAGENTA=$'\e[35m'
ANSI_CYAN=$'\e[36m'
ANSI_WHITE=$'\e[37m'
ANSI_BOLD=$'\e[1m'
ANSI_RESET=$'\e[0m'

ANSI_DEBUG="${ANSI_BLUE}"
ANSI_INFO="${ANSI_WHITE}${ANSI_BOLD}"
ANSI_WARNING="${ANSI_YELLOW}${ANSI_BOLD}"
ANSI_ERROR="${ANSI_RED}${ANSI_BOLD}"
ANSI_PROMPT="${ANSI_CYAN}"

DEBUG=3
INFO=2
WARNING=1
ERROR=0
PROMPT=-1   # always print
VERBOSITY=2 # max level printed

function usage {
  cat <<EOF
${ANSI_INFO}Usage:${ANSI_RESET}
  ${ANSI_WHITE}${BASH_SOURCE[0]} ${ANSI_CYAN}[<options>] ${ANSI_GREEN}<targets_file>

${ANSI_INFO}Arguments:${ANSI_RESET}
   ${ANSI_GREEN}<targets_file>${ANSI_RESET}  A comma-separated file containing one DNS name,IP address per line

${ANSI_INFO}Misc options:${ANSI_RESET}
  ${ANSI_CYAN}-D <directory>${ANSI_RESET}  Directory containing files from previous run
  ${ANSI_CYAN}-d${ANSI_RESET}        Enable debugging output

${ANSI_INFO}Nmap options:${ANSI_RESET}

  ${ANSI_CYAN}-pT  <ports>${ANSI_RESET}  Scan the given TCP port range.
  ${ANSI_CYAN}-pU  <ports>${ANSI_RESET}  Scan the given UDP port range.
  ${ANSI_CYAN}-ptT <ports>${ANSI_RESET}  Scan the <n> most common TCP ports.
  ${ANSI_CYAN}-ptU <ports>${ANSI_RESET}  Scan the <n> most common UDP ports.

  Default is all TCP ports and top 100 UDP ports.

${ANSI_INFO}FTP options:${ANSI_RESET}
  ${ANSI_CYAN}-fU <user file>${ANSI_RESET} File containing usernames for FTP bruteforce, one per line. Default is /dev/null (no login attempt)
  ${ANSI_CYAN}-fP <pass file>${ANSI_RESET} File containing passwords for FTP bruteforce, one per line. Default is /dev/null (no login attempt)
EOF
exit 1
}

function to_bool {
  local arg="$1"
  if [[ -n "${arg}" && ! "${arg}" =~ ^[01]$ ]] ; then
    log ERROR "Expected 0 or 1, got '${arg}'" >&2
    exit 1
  fi
  echo -n "${arg:-0}"
}

function to_posnum {
  local arg="$1"
  if [[ -n "${arg}" && ! "${arg}" =~ ^[0-9]+$ ]] ; then
    log ERROR "Expected a positive number, got '${arg}'" >&2
    exit 1
  fi
  echo -n "${arg}"
}


function prompt {
  local var="$1" msg="$2" yesno=$(to_bool "$3") level="PROMPT"
  print "${level}" "\\n     ${msg} "
  if [[ "${yesno}" -eq 0 ]] ; then
    read "${var}"
  else
    print "${level}" "(y/n) "
    read -n1 "${var}"
    print "${level}" '\n'
    while [[ ! "${!var}" =~ [yYnN] ]] ; do
      print "${level}" "     Answer with 'y' or 'n': "
      read -n1 "${var}"
      print "${level}" '\n\n'
    done
  fi
}

function log {
  local level="$1" msg="$2" spaces="     "
  print "${level}" "${level}: ${spaces:0:$((7 - ${#level}))}${msg}\n"
}

function print {
  local level="$1" msg="$2" color="ANSI_${level}"
  [[ "${!level}" -le "${VERBOSITY}" ]] || return
  echo -ne "${!color}${msg}${ANSI_RESET}"
}

function get_one_above_tlds {
  # read from stdin
  # emulate non-greedy match, by trying second-level domains first
  sed -nE \
    's/^([^\.]+\.)*([^\.]+\.('"${SLDS}"')\.[a-z]+)$/\2/p
     t
     s/^([^\.]+\.)*([^\.]+\.[a-z]+)$/\2/p' | sort -u
}

function get_topmost_match_domain {
  # read from stdin
  local re match="$1" exact=$(to_bool "$2")
  if [[ "${exact}" -eq 0 ]] ; then
    re='[^\.]*'"${match}"'[^\.]*'
  else
    re="${match}"
  fi
  sed -nE 's/^([^\.]+\.)*('"${re}"'(\.[^\.]+)*)$/\2/p' | sort -u
}

function get_dns_names {
  local ip="$1"
  log DEBUG "Getting DNS names for ${ip}" 1>&2
  grep "${ip}" "${TARGETS}" | cut -d, -f1 | egrep --color=never '[^ ]' # remove blank entries
}

function resolve {
  local host="$1"
  log DEBUG "Getting IP address for ${host}" 1>&2
  dig +short "${host}" | sed -En '/^([0-9]+\.){3}[0-9]+$/p'
}

function reverse_ip {
  local ip="$1"
  gawk '{
    split($0,arr,".")
    printf arr[4] "." arr[3] "." arr[2] "." arr[1]
  }' <<<"${ip}"
}

function live_dns {
  local crap host ip iporig
  nmap -sL -R $(tr , \\n <"${TARGETS}") | \
    awk '/^Nmap scan report for/{
      match($0,/^Nmap scan report for +([^ ]+)( +\(([^\)]+)\))?$/,arr)
      host=arr[1]
      ip=arr[3]
      if (!ip){ ip=host; host="" }
      if (ip) { printf host "," ip "\n" }
    }' | \
      while IFS=, read host ip ; do
        # if the DNS name is some generic one (contains the ip address in some
        # form), then don't bother
        crap=0
        iporig=${ip}
        revip=$(reverse_ip ${ip})
        [[ ${host/${ip}/} != ${host} ]] || \
          [[ ${host/${revip}/} != ${host} ]] && crap=1
        ip=${ip//./-}
        revip=${revip//./-}
        [[ ${host/${ip}/} != ${host} ]] || \
          [[ ${host/${revip}/} != ${host} ]] && crap=1
        ip=${ip//-/_}
        revip=${revip//-/_}
        [[ ${host/${ip}/} != ${host} ]] || \
          [[ ${host/${revip}/} != ${host} ]] && crap=1
        log DEBUG "DNS for ${host},${iporig} is crap? ${crap}" 1>&2
        [[ ${crap} -eq 1 ]] && echo ",${iporig}" || echo "${host},${iporig}"
      done > "${RESOLVED_TARGETS}"
}

function pass_dns {
  local host ip
  while IFS=, read host ip ; do
    if [[ -n "${host}" ]] ; then
      # passive forward DNS
      ${MYDIR}/dnsQ.sh "${host}" | sed 's/^/'"${host}"',/'
    fi
    if [[ -n "${ip}" ]] ; then
      # passive reverse DNS
      ${MYDIR}/dnsQ.sh -r "${ip}" | sed 's/$/,'"${ip}"'/'
    fi
  done < "${RESOLVED_TARGETS}" | sort -u > "${PASSDNS_TARGETS}"
  [[ -s "${PASSDNS_TARGETS}" ]] && \
    log INFO "Reverse DNS names for IP targets saved to '${PASSDNS_TARGETS}'"
}

function scan_tcp {
  local f
  for f in "${NMAP_LOG}".* ; do
    prompt proceed "Previous scan logs will be overwritten! Proceed?" 1
    [[ "${proceed}" == 'y' || "${proceed}" == 'Y' ]] || return
    break
  done
  sudo nmap "${NMAP_TCP_OPTS[@]}" -v -sC -Pn -sV -O $(< "${NMAP_TARGETS}") \
    -oA "${NMAP_LOG}" > "${NMAP_LOG}" || \
      nmap "${NMAP_TCP_OPTS[@]}" -v -sC -Pn -sV $(< "${NMAP_TARGETS}") \
        -oA "${NMAP_LOG}" > "${NMAP_LOG}" || exit $?
}

function scan_udp {
  local f
  for f in "${NMAP_LOG}".* ; do
    prompt proceed "Previous scan logs will be overwritten! Proceed?" 1
    [[ "${proceed}" == 'y' || "${proceed}" == 'Y' ]] || return
    break
  done
  sudo nmap "${NMAP_UDP_OPTS[@]}" -v -sU -Pn $(< "${NMAP_TARGETS}") \
    -oA "${NMAP_LOG}" >> "${NMAP_LOG}" || exit $?
}

function process_nmap_log {
  local f ip port proto state service
  egrep '^Nmap scan report|/(tcp|udp).*open' "${NMAP_LOG}" > "${NMAP_SHORT_LOG}"
  #XXX get the IP address
  egrep -o 'DNS:[^ ,]+' "${NMAP_LOG}" | cut -d: -f2 | sort -u > dns_names_from_ssl_certs.txt
  #XXX TARGETS is two column, comma-separated, dns_names_from_ssl_certs is only DNS names
  new_targets=$(comm -13 "${TARGETS}" dns_names_from_ssl_certs.txt)
  if [[ -n "${new_targets}" ]] ; then
    log INFO "Discovered the following new DNS names in SSL certificates:\\n${new_targets}"
  fi

  [[ -d services ]] || mkdir services || exit $?
  [[ -d ports ]] || mkdir ports || exit $?
  rm ports/*.txt services/*.txt
  sed -n -E 's/^Nmap scan report for.*[^0-9]([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\)?$|^([0-9]+)\/(tcp|udp) +([^ ]+) +([^ ]+).*/\1,\2,\3,\4,\5/p' \
    "${NMAP_SHORT_LOG}" | while IFS=, read ip port proto state service ; do
      if [[ -n "${ip}" ]] ; then
        cur_ip="${ip}"
      else
        log DEBUG "${proto} service ${service} is ${state} on ${cur_ip}:${port}"
        state="${state//\//_}"
        service="${service//\//_}"
        service="${service//\?/}"
        echo "${cur_ip}" >> "ports/${proto}_${state}_${port}.txt" 
        echo "${cur_ip}:${port}" >> "services/${service}_${state}.txt" 
      fi
    done

  for f in services/*.txt ports/*.txt ; do
    sort -u "${f}" > "${f/.txt/..txt}"
    mv "${f/.txt/..txt}" "${f}"
  done

  cat services/http_open.txt 2>/dev/null | sed 's|^|http://|' > http_urls.txt
  cat services/https_open.txt services/ssl_https_open.txt \
  services/ssl_http_open.txt dns_names_from_ssl_certs.txt \
    2>/dev/null | sed 's|^|https://|' >> http_urls.txt
}

function scan_ssl {
  local host ip port
  cat services/https* services/ssl_* 2>/dev/null | while IFS=: read ip port ; do
    for host in $(get_dns_names "${ip}") ; do
      if [[ ! -f "testssl_${host}_${port}.log" ]] ; then
        docker run -t --rm mvance/testssl:latest "${host}:${port}" > "testssl_${host}_${port}.log"
      fi
      if [[ ! -f "sslscan_${host}_${port}.log" ]] ; then
        sslscan "${host}:${port}" > "sslscan_${host}_${port}.log"
      fi
      if [[ ! -f "sslenumciphers_${host}_${port}.log" ]] ; then
        nmap -p "${port}" -Pn --script sslv2,ssl-enum-ciphers "${host}" \
          > "sslenumciphers_${host}_${port}.log"
      fi
    done
  done
}

function scan_ftp {
  local ip port
  if [[ -f services/ftp_open.txt && -s "${FTP_USERS}" && -s "${FTP_PWDS}" ]] ; then
    while IFS=: read ip port ; do
      hydra -u -I -L "${FTP_USERS}" -P "${FTP_PWDS}" -s "${port}" "${ip}" ftp
      #for user in "${FTP_USERS[@]}" ; do
      #  for pass in "${FTP_PWDS[@]}" ; do
      #    lftp -p "${port}" -u "${user}","${pass}" "${ip}" \
      #      < <(echo -e "set ssl:verify-certificate false\nls") \
      #      &> "lftp_${ip}_${port}.log"
      #  done
      #done
    done < services/ftp_open.txt
  fi
}

function scan_ssh {
  local ip port
  if [[ -f services/ssh_open.txt ]] ; then
    while IFS=: read ip port ; do
      log DEBUG "Getting SSH info for ${ip} on port ${port}"
      ssh aura@"${ip}" -vvv -fnN \
        -o StrictHostKeyChecking=no \
        -o BatchMode=yes &> "ssh_${ip}_${port}.log"
    done < services/ssh_open.txt
  fi
}

function scan_smtp {
  local host ip port
  while IFS=: read -u3 ip port ; do
    for host in $(get_dns_names "${ip}") ; do
      [[ "${host+1}" == '1' ]] && continue # already done
      declare ${host}=done
      if [[ "${host}" == mail*.* ]] ; then
        log DEBUG "Stripping ${host%%.*} from host"
        host="${host#*.}"
      fi
      [[ -f "sendEmail_${ip}_${port}.log" ]] && continue
      prompt proceed "Send email from aurainfosec-demo@${host} (port ${port})?" 1
      [[ "${proceed}" == 'y' || "${proceed}" == 'Y' ]] && send_email "${host}" "${port}"
    done
  done 3< <(cat services/smtp_open.txt 2>/dev/null)
}

function send_email {
  local host="$1" port="$2"
  #XXX does sendmail support non-standard port?
  if which -s sendmail ; then
    sendmail \
      -f 'Aura Infosec PenTest <aurainfosec-demo@'"${host}"'>' \
      -t "${MAILTO}" -O ConnectionCacheTimeout=5 \
      "${host}:${port}" \
        &> "sendmail_${host}_${port}.log"
    return
  fi

  if which -s sendEmail ; then
    sendEmail \
      -f 'Aura Infosec PenTest <aurainfosec-demo@'"${host}"'>' \
      -t "${MAILTO}" -o timeout=5 \
      -s "${host}:${port}" \
        &> "sendEmail_${host}_${port}.log"
    return
  fi
}

function scan_with_aquatone {
  local host
  for host in $(< "${AQUATONE_TARGETS}") ; do
    aquatone-discover -d "${host}" || exit $?
  done
  open_ports=$(sed -n -E 's/^Discovered open port ([0-9]+)\/tcp .*/\1/p' "${NMAP_LOG}" | sort -u | tr '\n' ,)
  open_ports="${open_ports%,}"
  #XXX what if no open ports
  for host in $(< "${AQUATONE_TARGETS}") ; do
    aquatone-scan -d "${host}" -p "${open_ports}" 2>&1 >> "${AQUATONE_LOG}" || exit $?
  done
  for host in $(< "${AQUATONE_TARGETS}") ; do
    aquatone-gather -d "${host}" 2>&1 >> "${AQUATONE_LOG}" || exit $?
  done
}

# DEFAULTS
NMAP_TCP_OPTS=(-p 1-65535)
NMAP_UDP_OPTS=(--top-ports 100)

while [[ $# -gt 0 ]] ; do
  case $1 in
    -pT*|-pU*|-ptT*|-ptU*)
      opt="${1#-p}"
      if [[ "${opt}" == t* ]] ; then
        range_type="--top-ports"
        opt="${opt#t}"
      else
        range_type="-p"
      fi

      [[ ${opt:0:1} == 'T' ]] && arr="NMAP_TCP_OPTS" || arr="NMAP_UDP_OPTS"

      ports="${opt:1}"
      if [[ -z "${ports}" ]] ; then
        ports="$2"
        shift
      fi
      if [[ ! "${ports}" =~ ^[0-9,\ -]+$ ]] ; then
        log ERROR "Invalid port range '${ports}'"
        usage
      fi

      typeset -a ${arr}="(${range_type} '${ports}')"
      ;;
    -fU*|-fP*)
      opt="${1#-f}"
      [[ ${opt:0:1} == 'U' ]] && var="FTP_USERS" || var="FTP_PWDS"

      typeset ${var}="${opt:1}"
      if [[ -z "${!var}" ]] ; then
        typeset ${var}="$2"
        shift
      fi
      ;;
    -D)
      WDIR="${1:2}"
      if [[ -z "${WDIR}" ]] ; then
        WDIR="$2"
        shift
      fi
      ;;
    -d)
      VERBOSITY="${DEBUG}"
      ;;
    -h)
      usage
      ;;
    -*)
      log ERROR "Unknown option $1" >&2
      usage
      ;;
    *)

      if [[ -n "${TARGETS}" ]] ; then
        log ERROR "Extra argument $1" >&2
        usage
      fi
      TARGETS="$1"
      ;;
  esac
  shift
done

[[ -n "${TARGETS}" ]] || usage
TARGETS=$(python -c "import os,sys; print os.path.abspath(sys.argv[1])" "${TARGETS}")
if [[ ! -f "${TARGETS}" ]] ; then
  log ERROR "No such file '${TARGETS}'"
  exit 1
fi

MYPATH=$(/usr/bin/which "${BASH_SOURCE[0]}")
MYDIR=$(dirname "${MYPATH}")
MYDIR=$(cd -P -- "${MYDIR}" ; pwd -P)

WDIR="${WDIR:-discover_${DATE}}"
[[ -d "${WDIR}" ]] || mkdir "${WDIR}" || exit $?
cd "${WDIR}"

NMAP_LOG="nmap_default_scripts.log"
AQUATONE_LOG="aquatone.log"
NMAP_SHORT_LOG="nmap_default_scripts_short.log"
AQUATONE_TARGETS="aquatone_targets.txt"
NMAP_TARGETS="nmap_targets.txt"
RESOLVED_TARGETS="targets_from_dns.txt"
PASSDNS_TARGETS="targets_from_passive_dns.txt"

# Live DNS resolution
prompt proceed "Proceed with the live DNS queries?" 1
[[ "${proceed}" == 'y' || "${proceed}" == 'Y' ]] && live_dns || cp "${TARGETS}" "${RESOLVED_TARGETS}"

prompt proceed "Proceed with the passive DNS queries?" 1
[[ "${proceed}" == 'y' || "${proceed}" == 'Y' ]] && pass_dns

#TODO option to append to those
if [[ ! -f "${AQUATONE_TARGETS}" ]] ; then
  cut -d, -f1 "${TARGETS}" | get_one_above_tlds > "${AQUATONE_TARGETS}"
  log INFO "Targets for Aquatone saved to ${AQUATONE_TARGETS}."
  prompt ignored "Edit as needed, then press Enter to proceed"
fi

#TODO option to add /<n> for every IP
#TODO option to add /<n> for every IP in a particular geo area
#TODO option to append to those
if [[ ! -f "${NMAP_TARGETS}" ]] ; then
  cat "${PASSDNS_TARGETS}" "${RESOLVED_TARGETS}" | sed 's/^www\.//' | sort -u \
    | tr , \\n | gawk '!x[$0]++ && $0' > "${NMAP_TARGETS}"
  log INFO "Targets for Nmap saved to ${NMAP_TARGETS}."
  prompt ignored "Edit as needed, then press Enter to proceed"
fi

### NMAP
touch "${NMAP_LOG}"

log DEBUG "TCP scanning opts: ${NMAP_TCP_OPTS[*]}"
prompt proceed "Proceed with the TCP scan?" 1
[[ "${proceed}" == 'y' || "${proceed}" == 'Y' ]] && scan_tcp

log DEBUG "UDP scanning opts: ${NMAP_UDP_OPTS[*]}"
prompt proceed "Proceed with the UDP scan?" 1
[[ "${proceed}" == 'y' || "${proceed}" == 'Y' ]] && scan_udp

process_nmap_log

### SSL
prompt proceed "Proceed with the SSL scan?" 1
[[ "${proceed}" == 'y' || "${proceed}" == 'Y' ]] && scan_ssl

### FTP
prompt proceed "Proceed with the FTP phase?" 1
[[ "${proceed}" == 'y' || "${proceed}" == 'Y' ]] && scan_ftp

### SSH
prompt proceed "Proceed with the ssh phase?" 1
[[ "${proceed}" == 'y' || "${proceed}" == 'Y' ]] && scan_ssh

### SMTP
prompt proceed "Proceed with the smtp phase?" 1
[[ "${proceed}" == 'y' || "${proceed}" == 'Y' ]] && scan_smtp

### AQUATONE
prompt proceed "Proceed with the Aquatone phase?" 1
[[ "${proceed}" == 'y' || "${proceed}" == 'Y' ]] && scan_with_aquatone
