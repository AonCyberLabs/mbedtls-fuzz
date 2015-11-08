#!/bin/bash

# Variable AFL_CC is already taken!
# Add afl-clang-fast to your PATH and/or adapt the following variable:
readonly AFL_CC_BIN="${HOME}/afl/afl-1.94b/afl-clang-fast"
#readonly AFL_CC_BIN="afl-gcc"

export CC="$AFL_CC_BIN"
export AFL_USE_ASAN=1
#export AFL_USE_MSAN=1
export AFL_HARDEN=1

cd ..
find . -name CMakeCache.txt -type f -print | xargs /bin/rm -f
cmake -DCMAKE_C_COMPILER="$AFL_CC_BIN" -DBUILD_SHARED_LIBS=Off -DENABLE_TESTING=Off -DCMAKE_BUILD_TYPE=Debug --clean-first .
make clean all

