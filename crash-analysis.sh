#!/bin/bash

# To find crash files, use a command such as the following:
# find . -name 'id*' -type f | grep crashes | sort > crash_files.txt

readonly GDB="gdb"
readonly SELFTLS="mbedtls-1.3.??/fuzz/selftls"
readonly CRASH_FILES="./crash_files.txt"

usage() {
    local progname=$1

    cat <<- EOF
	Usage: $progname [crash number (>= 1)]

	This program uses gdb to analyze an afl crash.
	EOF
}

main() {
    if [ -z "$1" ]; then
        usage "$0"
        exit 1
    fi
    if (! [[ $1 =~ '^[0-9]+$' ]]) && [[ $1 -lt 1 ]]; then
        echo "the crash number must be at least 1"
        exit 1
    fi
    if [ ! -f "$CRASH_FILES" ]; then
        echo "crash file does not exist or is not a regular file"
        exit 1
    fi

    local lines=$(cat "$CRASH_FILES" | wc -l)

    if [ $lines -lt $1 ]; then
        echo "the crash number does not exist"
        exit 1
    fi

    local crashfile=$(sed -n "${1}p" "$CRASH_FILES")
    local packet_no=$(echo "$crashfile" | grep -Po 'packet-\d+' | grep -Po '\d+')

    echo "Starting gdb..."
    echo "Packet number: $packet_no"
    echo "Crashing packet content: $crashfile"
    "$GDB" --args "$SELFTLS" "$packet_no" "$crashfile"
}

main "$@"

