#!/bin/bash

readonly SELFTLS_BIN="../selftls"
# Add afl-fuzz to your PATH or the change the following variable:
readonly AFL_FUZZ="afl-fuzz"
readonly RAMDISK_PATH="/tmp/afl-ramdisk/mbedtls"
# The following parameter is the peak virtual memory use in MiB of selftls.
# The parameter is only necessary for ASAN-enabled builds on x86-64.
# You can determine the value for your selftls using the tool from
# http://jwilk.net/software/recidivm
# by running 'recidivm -u M selftls'.
readonly MEM_REQUIRED="300000000"
# If you want to use the experimental cgroups script under Linux for
# ASAN-enabled builds on x86-64, set the following path correctly and
# uncomment the relevant code further down:
readonly AFL_ASAN_CGROUPS="$HOME/afl-latest/experimental/asan_cgroups/limit_memory.sh"
# Set to 0, if you do not have an ASAN-enabled build.
export AFL_USE_ASAN=1

usage() {
	local progname=$1

	cat <<- EOF
	Usage: $progname [packet number] [fuzzer number]
	
	This program fuzzes mbed TLS using afl-fuzz.
	Calling this program without arguments writes the network packets to files.
	A specific network packet can be replaced with the content from a file which allows for fuzzing that packet.
	To fuzz a specific packet, provide the packet number and the fuzzer number as command-line arguments.
	The master fuzzer has number 1, while slaves can have any other number.
	
	mbedtls-fuzz v2.0
	Fabian Foerg <ffoerg@gdssecurity.com>
	https://blog.gdssecurity.com/labs/2015/9/21/fuzzing-the-mbed-tls-library.html
	Copyright 2015 Gotham Digital Science
	EOF
}

main() {
	if [ -z "$2" ]; then
		usage "$0"
		exit 1
	fi

	# Mount RAM disk if necessary
	local is_mounted=$(mount | grep "$RAMDISK_PATH")
	if [ -z "$is_mounted" ]; then
		mkdir -p "$RAMDISK_PATH"
		chmod 777 "$RAMDISK_PATH"
		sudo mount -t tmpfs -o size=512M tmpfs "$RAMDISK_PATH"
	fi
	cp -R . "$RAMDISK_PATH"
	cd "$RAMDISK_PATH"

	local subfolder=""
	if [ "1" = "$2" ]; then
		# Master creates subfolder
		subfolder="$(date --rfc-3339=seconds)"
		mkdir "$subfolder"
	else
		# Slaves use the folder with newest date in the name
		subfolder=$(find . -maxdepth 1 -type d -regextype posix-egrep -iregex ".*[0-9]{4}-[0-9]{2}-[0-9]{2} .*" -print | sort | tail -1)
	fi
	cd "$subfolder"

	local packet_no="$1"
	local FUZZER_NAME="packet-${packet_no}--fuzzer-$2"
	if [ "1" = "$2" ]; then
		# Master mode

		# Configure system for fuzzing
		sudo sh -c "echo core >/proc/sys/kernel/core_pattern"
		sudo sh -c "cd /sys/devices/system/cpu && echo performance | tee cpu*/cpufreq/scaling_governor"

		# Create directories
		mkdir -p fin sync

		# Run selftls to get files containing network packets
		rm fin/*
		"$SELFTLS_BIN"
		cp "packet-$packet_no" fin

		if [ "1" = "$AFL_USE_ASAN" ]; then
			"$AFL_FUZZ" -i fin -o sync -m "$MEM_REQUIRED" -M "$FUZZER_NAME" "$SELFTLS_BIN" "$packet_no" @@
			# If you want to use the experimental cgroups script under Linux:
			#sudo swapoff -a; sudo "$AFL_ASAN_CGROUPS" -u "$USER" "$AFL_FUZZ" -i fin -o sync -m none "$SELFTLS_BIN" "$packet_no" @@
		else
			"$AFL_FUZZ" -i fin -o sync -M "$FUZZER_NAME" "$SELFTLS_BIN" "$packet_no" @@
		fi

	else
		# Slave mode
		if [ "1" = "$AFL_USE_ASAN" ]; then
			"$AFL_FUZZ" -i fin -o sync -m "$MEM_REQUIRED" -S "$FUZZER_NAME" "$SELFTLS_BIN" "$packet_no" @@
		else
			"$AFL_FUZZ" -i fin -o sync -S "$FUZZER_NAME" "$SELFTLS_BIN" "$packet_no" @@
		fi
	fi
}

main "$@"

