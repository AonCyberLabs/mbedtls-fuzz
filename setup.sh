#!/bin/bash

readonly ARCHIVE_SUFFIX='-gpl.tgz'
readonly MBEDTLS_2_3='mbedtls-2.3.0'
readonly SHA_256_2_3='21237014f779bde70b2d71399cc1ea53365eb7f10cdd74a13ee6329a1910cb49'
readonly MBEDTLS_2_1='mbedtls-2.1.5'
readonly SHA_256_2_1='119ff3ee2788a2c5f0604b247bdffd401c439c8e551561cbb4b1f9d3a21a120d'
readonly MBEDTLS_1_3='mbedtls-1.3.17'
readonly SHA_256_1_3='f5beb43e850283915e3e0f8d37495eade3bfb5beedfb61e7b8da70d4c68edb82'
readonly MBEDTLS_A=( "$MBEDTLS_2_3" "$MBEDTLS_2_1" "$MBEDTLS_1_3" )
readonly SHA_256_A=( "$SHA_256_2_3" "$SHA_256_2_1" "$SHA_256_1_3" )
readonly NO_TIME=1

main() {
    # sudo apt-get install build-essential automake cmake wget

    echo -e "  ************\n  Please make sure to update the constants of scripts in the 'fuzz' folder!\n  ************\n"

    for i in "${!MBEDTLS_A[@]}"; do
        # download if necessary
        wget -nc https://tls.mbed.org/download/"${MBEDTLS_A[$i]}${ARCHIVE_SUFFIX}"

        # validate the checksum of the code archives
        CHECKSUM=$(shasum -a 256 "${MBEDTLS_A[$i]}${ARCHIVE_SUFFIX}")

        if [[ "$CHECKSUM" != "${SHA_256_A[$i]}  ${MBEDTLS_A[$i]}${ARCHIVE_SUFFIX}" ]]; then
            echo "Error: ${MBEDTLS_A[$i]}${ARCHIVE_SUFFIX} checksum check failed!"
            exit 1
        fi

        # extract archives
        tar xzf "${MBEDTLS_A[$i]}${ARCHIVE_SUFFIX}"

        VERSION='2'
        INCLUDE_DIR='mbedtls'

        if [[ "${MBEDTLS_A[$i]}" = "$MBEDTLS_1_3" ]]; then
            VERSION='1.3'
            INCLUDE_DIR='polarssl'
        fi

        # copy fuzzing code and configuration
        cp -R fuzz "${MBEDTLS_A[$i]}"
        cp "selftls-${VERSION}.c" "${MBEDTLS_A[$i]}/fuzz/selftls.c"

        # patch CMakeLists
        pushd "${MBEDTLS_A[$i]}" && patch -p1 < "../CMakeLists-${VERSION}.patch"; popd

        # make sure TLS time field is constant
        if [[ "$NO_TIME" = "1" ]]; then
            cp "config-${VERSION}.h" "${MBEDTLS_A[$i]}/include/${INCLUDE_DIR}/config.h"
        else
            pushd "${MBEDTLS_A[$i]}" && patch -p1 < "../time-${VERSION}.patch"; popd
        fi

        # compile the code
        pushd "${MBEDTLS_A[$i]}/fuzz" && ./compile.sh; popd
    done

    echo -e "\n  ************\n  If everything compiled correctly, go into one of the 'mbedtls-2.?.?/fuzz/' folders and run './fuzz.sh'\n  ************"
}

main "$@"

