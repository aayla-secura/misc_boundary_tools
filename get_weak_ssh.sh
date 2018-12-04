#!/bin/bash
# reads from stdin

gawk '
{sub (/^debug[0-9]*: */,"")}
/^peer server KEXINIT proposal/ {serv=1}
/^(ciphers|MACs) s/ {
    if (!serv) next;
    print "Vulnerable " $1 ":"
    sub(/^[^:]+: */,"")
    split($0,algos,",")
    for (a in algos) {
        if (algos[a] ~ /blowfish|cast128|idea|3?des|-(cbc|sha1|md5)/)
            print "    " algos[a]
    }
}
ENDFILE {serv=0}'
