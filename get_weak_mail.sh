#!/bin/bash
# args are filenames containing one ip:port per line; filename should
# contain either pop or imap or smtp
#XXX 554 SMTP synchronization error when piping to netcat with some SMTP servers

FILES=("$@")

function get_weak_pop {
    local file="$1"
    while IFS=: read ip port ; do
        echo "Weak auth methods for POP server $ip:$port"
        nc "$ip" "$port" <<<"AUTH" | gawk '/^(PLAIN|LOGIN)\r?$/ { print "    " substr($0,1,5) }'
    done < "$file"
}

function get_weak_imap {
    local file="$1"
    while IFS=: read ip port ; do
        echo "Weak auth methods for IMAP server $ip:$port"
        nc "$ip" "$port" </dev/null | gawk '{
            for(i = 1; i <= NF; i++) {
                if ($i ~ /^AUTH=(PLAIN|LOGIN)/) print "    " substr($i,6,5)
            }
        }'
    done < "$file"
}

function get_weak_smtp {
    local file="$1"
    while IFS=: read ip port ; do
        echo "Weak auth methods for SMTP server $ip:$port"
        nc "$ip" "$port" <<<"EHLO foo" | gawk '/^[0-9]+-AUTH +/ {
            for(i = 1; i <= NF; i++) {
                if ($i ~ /^(PLAIN|LOGIN)/) print "    " substr($i,1,5)
            }
        }'
    done < "$file"
}

for f in "${FILES[@]}" ; do
    processed=0
    for pat in pop imap smtp ; do
        if [[ "${f}" =~ $pat ]] ; then
            get_weak_$pat "${f}"
            processed=1
            break
        fi
    done
    if [[ $processed -eq 0 ]] ; then
        echo "Unknown service in file '${f}'. Make sure name contains pop|imap|smtp" 1>&2
    fi
done
