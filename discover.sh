#!/bin/bash
# targets should be a csv: DNS name,IP address
# needs testssl.sh, sslscan, nmap, sendEmail

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

function to_bool {
    local arg="$1" func="$2"
    if [[ -n "${arg}" && ! "${arg}" =~ ^[01]$ ]] ; then
        log ERROR "Expected 0 or 1 as second argument to ${func}, got '${arg}'" >&2
        exit 1
    fi
    echo -n "${arg:-0}"
}

function prompt {
    local level="$1" var="$2" msg="$3" yesno=$(to_bool "$4" prompt)
    print "${level}" "         ${msg} "
    if [[ "${yesno}" -eq 0 ]] ; then
        read "${var}"
    else
        print "${level}" "(y/n) "
        read -n1 "${var}"
        print "${level}" '\n'
        while [[ ! "${!var}" =~ [yYnN] ]] ; do
            print "${level}" "         Answer with 'y' or 'n': "
            read -n1 "${var}"
            print "${level}" '\n'
        done
    fi
}

function log {
    local level="$1" msg="$2" spaces="       "
    print "${level}" "${level}: ${spaces:0:$((7 - ${#level}))}${msg}\n"
}

function print {
    local level="$1" msg="$2" color="ANSI_${level}"
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
    local re match="$1" exact=$(to_bool "$2" get_topmost_match_domain)
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
    grep "${ip}" "${TARGETS}" | cut -d, -f1
}

MAILTO='a.nikolova@aurainfosec.com'
# regularly updated list of valid TLDs and their own SLDs at
# https://publicsuffix.org/list/public_suffix_list.dat
# but the below should be enough in most cases
SLDS='ac|biz|co?|edu?|go?v|mil|net|nom|org?'

DATE=$(date +"%d_%m_%Y__%H_%M_%S" | tr -d '\n')
WDIR="${2:-discover_${DATE}}"
[[ -d "${WDIR}" ]] || mkdir "${WDIR}" || exit $?

TARGETS="${1:-targets.csv}"
TARGETS=$(python -c "import os,sys; print os.path.abspath(sys.argv[1])" "${TARGETS}")
[[ -f "${TARGETS}" ]] || exit 1 #TODO error
cd "${WDIR}"

NMAP_LOG="nmap_default_scripts.log"
AQUATONE_LOG="aquatone.log"
NMAP_SHORT_LOG="nmap_default_scripts_short.log"
AQUATONE_TARGETS="aquatone_targets.txt"
NMAP_TARGETS="nmap_targets.txt"

#TODO option to append to those
if [[ ! -f "${AQUATONE_TARGETS}" ]] ; then
    cut -d, -f1 "${TARGETS}" | get_one_above_tlds > "${AQUATONE_TARGETS}"
    log INFO "Targets for Aquatone saved to ${AQUATONE_TARGETS}."
    prompt INFO ignored "Edit as needed, then press Enter to proceed"
fi

#TODO option to add /<n> for every IP
#TODO option to append to those
if [[ ! -f "${NMAP_TARGETS}" ]] ; then
    cut -d, -f2 "${TARGETS}" | sort -u > "${NMAP_TARGETS}"
    log INFO "Targets for Nmap saved to ${NMAP_TARGETS}."
    prompt INFO ignored "Edit as needed, then press Enter to proceed"
fi

### NMAP
touch "${NMAP_LOG}"
prompt INFO proceed "Proceed with the TCP scan?" 1
if [[ "${proceed}" == 'y' || "${proceed}" == 'Y' ]] ; then
    sudo nmap -p1-65535 -v -sC -Pn -sV -O $(< "${NMAP_TARGETS}") 2>&1 >> "${NMAP_LOG}" || \
        nmap -p1-65535 -v -sC -Pn -sV $(< "${NMAP_TARGETS}") 2>&1 >> "${NMAP_LOG}" || exit $?
fi
prompt INFO proceed "Proceed with the UDP scan?" 1
if [[ "${proceed}" == 'y' || "${proceed}" == 'Y' ]] ; then
    sudo nmap --top-ports 100 -v -sU -Pn $(< "${NMAP_TARGETS}") 2>&1 >> "${NMAP_LOG}" || exit $?
fi

egrep '^Nmap scan report|/(tcp|udp).*open' "${NMAP_LOG}" >> "${NMAP_SHORT_LOG}"
egrep -o 'DNS:[^ ,]+' "${NMAP_LOG}" | cut -d: -f2 | sort -u >> dns_names_from_ssl_certs.txt

[[ -d services ]] || mkdir services || exit $?
[[ -d ports ]] || mkdir ports || exit $?
# rm ports/*.txt services/*.txt
sed -n -E 's/^Nmap scan report for.*[^0-9]([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\)?$|^([0-9]+)\/(tcp|udp) +([^ ]+) +([^ ]+).*/\1,\2,\3,\4,\5/p' \
    "${NMAP_SHORT_LOG}" | while IFS=, read ip port proto state service ; do
        if [[ -n "${ip}" ]] ; then
            cur_ip="${ip}"
        else
            # log DEBUG "${proto} service ${service} is ${state} on ${cur_ip}:${port}"
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

### SSL
#TODO other SSL services, inspect with openssl s_client
prompt INFO proceed "Proceed with the SSL scan?" 1
if [[ "${proceed}" == 'y' || "${proceed}" == 'Y' ]] ; then
    cat services/ssl_* 2>/dev/null | while IFS=: read ip port ; do
        for host in $(get_dns_names "${ip}") ; do
            if [[ ! -f "testssl_${host}_${port}.log" ]] ; then
                testssl.sh "${host}:${port}" > "testssl_${host}_${port}.log"
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
fi

### FTP
prompt INFO proceed "Proceed with the FTP phase?" 1
if [[ "${proceed}" == 'y' || "${proceed}" == 'Y' ]] ; then
    if [[ -f services/ftp_open.txt ]] ; then
        while IFS=: read ip port ; do
            #TODO other users passes, use a dictionary
            for user in ftp anonymous ; do
                lftp -p "${port}" -u "${user}","" "${ip}" \
                    < <(echo -e "set ssl:verify-certificate false\nls") \
                    &> "lftp_${ip}_${port}.log"
            done
        done < services/ftp_open.txt
    fi
fi

### AQUATONE
prompt INFO proceed "Proceed with the Aquatone phase?" 1
if [[ "${proceed}" == 'y' || "${proceed}" == 'Y' ]] ; then
    # for host in $(< "${AQUATONE_TARGETS}") ; do
    #     aquatone-discover -d "${host}" || exit $?
    # done
    open_ports=$(sed -n -E 's/^Discovered open port ([0-9]+)\/tcp .*/\1/p' "${NMAP_LOG}" | sort -u | tr '\n' ,)
    open_ports="${open_ports%,}"
    #XXX what if no open ports
    for host in $(< "${AQUATONE_TARGETS}") ; do
        aquatone-scan -d "${host}" -p "${open_ports}" 2>&1 >> "${AQUATONE_LOG}" || exit $?
    done
    for host in $(< "${AQUATONE_TARGETS}") ; do
        aquatone-gather -d "${host}" 2>&1 >> "${AQUATONE_LOG}" || exit $?
    done
fi

### SSH
prompt INFO proceed "Proceed with the ssh phase?" 1
if [[ "${proceed}" == 'y' || "${proceed}" == 'Y' ]] ; then
    if [[ -f services/ssh_open.txt ]] ; then
        while IFS=: read ip port ; do
            log DEBUG "Getting SSH info for ${ip} on port ${port}"
            ssh aura@"${ip}" -vvv -fnN \
                -o StrictHostKeyChecking=no \
                -o BatchMode=yes &> "ssh_${ip}_${port}.log"
        done < services/ssh_open.txt
    fi
fi

### SMTP
prompt INFO proceed "Proceed with the smtp phase?" 1
if [[ "${proceed}" == 'y' || "${proceed}" == 'Y' ]] ; then
    while IFS=: read -u3 ip port ; do
        for host in $(get_dns_names "${ip}") ; do
            #TODO check smtp_tried, add to it
            # [[ "${port}" -eq 587 ]] && continue
            if [[ "${host}" == mail*.* ]] ; then
                log DEBUG "Stripping ${host%%.*} from host"
                host="${host#*.}"
            fi
            [[ -f "sendEmail_${ip}_${port}.log" ]] && continue
            prompt INFO proceed "Send email from aurainfosec-demo@${host} (port ${port})?" 1
            [[ "${proceed}" == 'y' || "${proceed}" == 'Y' ]] || continue
            sendEmail -s "${host}:${port}" \
                -o timeout=20 \
                -f 'Aura Infosec PenTest <aurainfosec-demo@'"${host}"'>' \
                -t "${MAILTO}" -u 'Test message' -m 'Test message' \
                    &> "sendEmail_${ip}_${port}.log"
            echo
        done
    done 3< <(cat services/smtp_open.txt 2>/dev/null)
fi
