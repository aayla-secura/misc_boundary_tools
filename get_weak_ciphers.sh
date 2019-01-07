#!/bin/bash
# Reads from stdin, expects output from nmap's ssl-enum-ciphers or sslv2

function usage {
    cat <<EOF
Usage:
    ${BASH_SOURCE[0]} -s <level>

Options:
    -s <level>      If <level> is > 1 also flag SHA1 as bad
                    If <level> is > 2 also flag 128-bit ciphers as bad
EOF
exit 1
}

RE='MD5|RC4|DES'
while [[ $# -gt 0 ]] ; do
    case $1 in
        -s*)
            if [[ $1 == '-s' ]] ; then
                LVL="$2"
                shift
            else
                LVL="${1#-s}"
            fi
            [[ ${LVL} =~ ^[0-9]+$ ]] || usage
            [[ ${LVL} -ge 2 ]] && RE+='_DHE?_|_128'
            [[ ${LVL} -ge 1 ]] && RE+='|SHA($|[^23])'
            ;;
        -h)
            usage
            ;;
        -*)
            echo "Unknown option $1" >&2
            usage
            ;;
        *)
            echo "Unknown argument $1" >&2
            usage
            ;;
    esac
    shift
done

gsed -E \
    '/^\|_? +((SSL2?|TLS)_[^ ]+).*/ {
        :A /'"${RE}"'/ {bB} ; d ;
        :B s/^\|_? +((SSL2?|TLS)_[^ ]+).*/\1/ 
           s/^SSL2/SSL/ ; n;bA
    } ; d' | sort -u
