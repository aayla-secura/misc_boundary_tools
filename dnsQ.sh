#!/bin/bash

MATCH='answer'
while [[ $# -gt 0 ]] ; do
    case "$1" in
        -r)
            MATCH='query' # reverse DNS
            ;;
        -)
            exit 1
            ;;
        *)
            [[ -n "${QUERY}" ]] && exit 2
            QUERY="$1"
            ;;
    esac
    shift
done
[[ -n "${QUERY}" ]] || exit 3

echo \
'{"query":"'"${QUERY}"'","aggregateResult":true,"includeAnonymousResults":true,"rrClass":[],"rrType":[],"customerID":[],"tlp":[],"offset":0,"limit":25}' | \
    http --print=b POST 'https://api.mnemonic.no/pdns/v3/search' \
        'Content-Type: application/json' \
        'Origin: https://passivedns.mnemonic.no' | \
            python -m json.tool | \
                sed -E -n 's/^ *"'"${MATCH}"'": *"([^"]+)", *$/\1/p'
