#!/bin/bash
# Reads from stdin, expects output from sslscan
#XXX SSLv3 use the same key exchange as TLS, i.e. they should be the same except for TLS->SSL
#XXX https://testssl.sh/openssl-iana.mapping.html only shows the SSLv2 and earlier for SSL_*
#XXX use https://www.openssl.org/docs/man1.0.2/apps/ciphers.html

function rmansi {
    gsed -E 's/\[([0-9]*;)?[0-9]*m//g'
}

if [[ -n "$1" ]] ; then
    MAPPING_FILE="$1"
else
    MAPPING_FILE="openssl_rfc_cipher_names.txt"
    curl -s https://testssl.sh/openssl-iana.mapping.html > "${MAPPING_FILE}"
fi

# only bash v4.0 and later support associative arrays :(
while read openssl_cipher rfc_cipher ; do
    # echo "$openssl_cipher => $rfc_cipher"
    n="${rfc_cipher:0:3}_${openssl_cipher//-/_}"
    # echo "${n}=${rfc_cipher}"
    declare "${n}"="${rfc_cipher}"
    export "${n}"
    # set | grep "^${n}="
done < <(
    < "${MAPPING_FILE}" \
        sed -n -E 's!^ *<tr><td> *\[0x[0-9a-f]+\] *</td><td> *([^ <]+) *(</td><td> [^<]+){3}</td><td> *([^ <]+).*!\1 \3!p'
        )
# exit 0

rmansi | gsed -E \
    '/Supported Server Cipher/,/^ *$/ {
        :A / DHE?-|SHA |MD5|RC4|DES|AES128/ {bB} ; d ;
        :B s/^ *[^ ]+ +(TLS|SSL)v[0-9.]+ + [0-9]+ bits +([^ ]+).*/\1 \2/ ; n;bA
    } ; d' | sort -u | while read ver openssl_cipher ; do
        n="${ver}_${openssl_cipher//-/_}"
        if [[ -z "${!n}" ]] ; then
            printf "\e[31;1m" 1>&2
            echo -n "Unknown cipher $n." 1>&2
            if [[ "$n" == SSL* ]] ; then
                x="TLS${n#SSL}"
            else
                x="SSL${n#TLS}"
            fi
            if [[ -n "${!x}" ]] ; then
                echo " Using ${n:0:3}${x:3} instead." 1>&2
                echo "${n:0:3}${x:3}"
            else
                echo
            fi
            printf "\e[0m" 1>&2
        else
            echo "${!n}"
        fi
    done
