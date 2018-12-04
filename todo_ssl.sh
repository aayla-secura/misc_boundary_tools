#!/bin/bash
# compare testssl scan from multiple targets, grouping them by IP and
# showing the differences
# files should contain only standard testssl output
# set PRINTDIFF to 1 if you want verbose output

FILES=("$@")
sed -n -E 's/.*rDNS \(([0-9.]+)\).*/\1/p' "${FILES[@]}" | sort -u |
    while IFS= read ip ; do
        echo "==== $ip ===="
        egrep -l 'rDNS \('"$ip"'\)' "${FILES[@]}"
    done

sed -n -E 's/.*rDNS \(([0-9.]+)\).*/\1/p' "${FILES[@]}" | sort -u |
    while IFS= read ip ; do
        echo "============================== ${ip} =============================="
        echo
        # no spaces in filenames
        files=($(egrep -l 'rDNS \('"${ip}"'\)' "${FILES[@]}" | sort -n -t_ -k3))
        while [[ "${#files[@]}" -gt 1 ]] ; do
            f="${files[0]}"
            files=("${files[@]:1}")
            # diff's -I option doesn't match clock skew or Status Code, why????....
            diff -U0 --to-file "${f}" "${files[@]}" | \
                awk -v verbose="$PRINTDIFF" '
                function print_diff() {
                    if (verbose)
                        print "\n---------- +" added ", -" removed " lines from " from_file " to " to_file " ----------\n"
                    else
                        print "+" added ", -" removed " lines from " from_file " to " to_file
                }
                /^(\[[0-9;]*m)*--- / {
                        if (from_file) {
                            print_diff()
                        }
                        added=0
                        removed=0
                        from_file=$2
                }
                /^(\[[0-9;]*m)*\+\+\+ / {
                    to_file=$2
                }
                ! /^(\[[0-9;]*m)*(\+\+\+|---|@@|[+-] *(\[[0-9;]*m)* *\
(Start|Done|Trust (hostname)|rDNS|TLS clock skew|HTTP (Status Code|clock skew)|Cookie\(s\)|Trust \(hostname\))) / {
                    if (verbose)
                        print $0;
                    if ($1 ~ "^(\[[0-9;]*m)*[+](\[[0-9;]*m)*$")
                        added++;
                    else if ($1 ~ "^(\[[0-9;]*m)*-(\[[0-9;]*m)*$")
                        removed++;
                }
                END {
                    print_diff()
                }' 2>/dev/null
        done
        echo
    done
