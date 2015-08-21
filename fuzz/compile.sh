#!/bin/bash

# Variable AFL_CC is already taken!
readonly AFL_CC_BIN="${HOME}/afl/afl-1.86b/afl-clang-fast"
#readonly AFL_CC_BIN="${HOME}/afl/afl-1.86b/afl-gcc"

export CC="$AFL_CC_BIN"
#export AFL_USE_ASAN=1
#export AFL_USE_MSAN=1
export AFL_HARDEN=1

find . -name CMakeCache.txt -type f -print | xargs /bin/rm -f
cmake -DCMAKE_C_COMPILER="$AFL_CC_BIN" -DBUILD_SHARED_LIBS=Off -DENABLE_TESTING=Off -DCMAKE_BUILD_TYPE=Debug --clean-first .
make clean all

