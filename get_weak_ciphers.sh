#!/bin/bash
# Reads from stdin, expects output from nmap's ssl-enum-ciphers or sslv2 scripts

function usage {
    cat <<EOF
Usage:
    ${BASH_SOURCE[0]} [-g]

Options:
    -g     For government.
EOF
exit 1
}

RE='(TLS|SSL)_RSA|_(NULL|RC4|3?DES|MD5|SHA($|[^2-5]))'
NEG_RE=''
while [[ $# -gt 0 ]] ; do
    case $1 in
        -g)
            NEG_RE='^TLS_ECDHE?_ECDSA_'
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

awk -v re="$RE" -v neg_re="$NEG_RE" \
    '/^\|_? +((SSL2?|TLS)_)/ {
      cipher=gensub(/^\|_? +((?:SSL2?|TLS)_[^ ]+).*/, "\\1", 1) 
      cipher=gensub(/^SSL2/, "SSL", 1, cipher)
      if (cipher ~ re || cipher !~ neg_re) {
        print cipher
      }
    }' | sort -u
