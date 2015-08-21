#!/bin/bash

readonly SELFTLS_BIN="../selftls"
readonly AFL_FUZZ="$HOME/afl/afl-1.86b/afl-fuzz"
readonly AFL_ASAN_CGROUPS="$HOME/afl/afl-1.86b/experimental/asan_cgroups/limit_memory.sh"
#readonly ASAN_LIB="/usr/lib/llvm-3.6/lib/clang/3.6.0/lib/linux/libclang_rt.asan-x86_64.a"
readonly ASAN_LIB="/usr/lib/x86_64-linux-gnu/libasan.so.0"

usage() {
    local progname=$1

    cat <<- EOF
	Usage: $progname [packet number] [fuzzer number]

	This program fuzzes mbed TLS using afl.
	Calling this program without arguments writes the network packets to files.
	A specific network packet can be replaced with the content from a file which allows for fuzzing that packet.
	To fuzz a specific packet, provide the packet number and the fuzzer number as command-line arguments.
	The master fuzzer has number 1, while slaves can have any other number.
	EOF
}

main() {
    if [ -z "$2" ]; then
        usage "$0"
        exit 1
    fi

    local packet_no="$1"
    local subfolder=""

    #export ASAN_OPTIONS='abort_on_error=1'

    if [ "1" = "$2" ]; then
        subfolder="$(date --rfc-3339=seconds)"
        mkdir "$subfolder"
    else
        # Slaves use the folder with newest date in the name
        subfolder=$(find . -maxdepth 1 -type d -regextype posix-egrep -iregex ".*[0-9]{4}-[0-9]{2}-[0-9]{2} .*" -print | sort | tail -1)
    fi

    cd "$subfolder"

    local FUZZER_NAME="packet-${packet_no}--fuzzer-$2"

    # Set up master
    if [ "1" = "$2" ]; then
        sudo sh -c "echo core >/proc/sys/kernel/core_pattern"
        sudo sh -c "cd /sys/devices/system/cpu && echo performance | tee cpu*/cpufreq/scaling_governor"

        mkdir -p in out sync_dir
        rm in/*
        "$SELFTLS_BIN"
        cp "packet-$packet_no" in

        "$AFL_FUZZ" -i in -o sync_dir -M "$FUZZER_NAME" "$SELFTLS_BIN" "$packet_no" @@

        # Next command is for ASAN/MSAN-enabled builds under Linux:
        #sudo swapoff -a; LD_PRELOAD="$ASAN_LIB" sudo "$AFL_ASAN_CGROUPS" -u "$USER" "$AFL_FUZZ" -i in -o sync_dir -m none "$SELFTLS_BIN" "$packet_no" @@
    else
        "$AFL_FUZZ" -i in -o sync_dir -S "$FUZZER_NAME" "$SELFTLS_BIN" "$packet_no" @@
    fi
}

main "$@"

