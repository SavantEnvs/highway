#!/usr/bin/env bash
#
# mayhem/build.sh — builds the Highway fuzz harnesses and the codec test suite.
#
#  1. hwy + hwy_contrib (CMake, static) with $SANITIZER_FLAGS + SanCov, into
#     build/mayhem-fuzz. Built with -DHWY_COMPILE_ONLY_STATIC=1 for one fixed
#     SIMD target (-march=x86-64-v2 -> SSSE3): crashes then reproduce on any
#     host, and the vqsort part of hwy_contrib (which thread_pool pulls in)
#     compiles once instead of once per x86 target.
#     -DHWY_IS_DEBUG_BUILD=0: Highway turns its debug-only HWY_DASSERTs on
#     whenever ASan is on (hwy/base_c.h). Some sit on paths that corrupt input
#     reaches by design (range_coder.h DecodeSymbol asserts q is in the symbol
#     interval, then masks it "for safety against corrupted input"), so they
#     would abort on nearly every mutated stream. Release builds, which users
#     ship, compile them out; always-on HWY_ASSERTs, ASan and UBSan stay.
#  2. Each harness in mayhem/harnesses/ twice: libFuzzer binary and
#     -standalone reproducer, into /mayhem/.
#  3. Upstream's own gtest tests for the fuzzed codecs (base64, range coder,
#     ANS, Iguana) with the project's normal flags, into build/mayhem-test.
# build/ is gitignored upstream, so `git clean -ffdX` resets both trees.
set -euo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

SRC="${SRC:-/mayhem}"
cd "$SRC"

HWY_FUZZ_DEFS="-DHWY_COMPILE_ONLY_STATIC=1 -DHWY_IS_DEBUG_BUILD=0 -march=x86-64-v2"
FUZZ_CXXFLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link $HWY_FUZZ_DEFS"
FB=build/mayhem-fuzz
OUT="$SRC"

# 1) Sanitized + coverage-instrumented library.
cmake -S . -B "$FB" -G Ninja \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_C_FLAGS="$FUZZ_CXXFLAGS" \
  -DCMAKE_CXX_FLAGS="$FUZZ_CXXFLAGS" \
  -DCMAKE_C_FLAGS_RELWITHDEBINFO="-O1" \
  -DCMAKE_CXX_FLAGS_RELWITHDEBINFO="-O1" \
  -DBUILD_SHARED_LIBS=OFF -DHWY_FORCE_STATIC_LIBS=ON \
  -DHWY_ENABLE_TESTS=OFF -DHWY_ENABLE_EXAMPLES=OFF -DHWY_ENABLE_IO=OFF \
  -DHWY_ENABLE_INSTALL=OFF -DHWY_ENABLE_LIST_TARGETS=OFF -DHWY_ENABLE_CONTRIB=ON
cmake --build "$FB" -j"$MAYHEM_JOBS" --target hwy_contrib hwy

# 2) Harnesses.
mkdir -p "$OUT"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$FB/standalone_main.o"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.cc -o "$FB/lsan_off.o"
LIBS="$FB/libhwy_contrib.a $FB/libhwy.a -lpthread -lm"
for h in iguana_fuzz range_coder_fuzz ans_fuzz base64_fuzz; do
  $CXX -std=c++17 $FUZZ_CXXFLAGS -O1 -I. -c "mayhem/harnesses/$h.cc" -o "$FB/$h.o"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE \
    "$FB/$h.o" "$FB/lsan_off.o" $LIBS -o "$OUT/$h"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS \
    "$FB/$h.o" "$FB/standalone_main.o" "$FB/lsan_off.o" $LIBS -o "$OUT/$h-standalone"
done

# 3) Upstream's tests for the same codecs, normal flags, system googletest.
TB=build/mayhem-test
cmake -S . -B "$TB" -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_FLAGS="$COVERAGE_FLAGS" -DCMAKE_CXX_FLAGS="$COVERAGE_FLAGS" \
  -DBUILD_SHARED_LIBS=OFF -DHWY_FORCE_STATIC_LIBS=ON \
  -DHWY_ENABLE_TESTS=ON -DHWY_SYSTEM_GTEST=ON -DHWY_ENABLE_EXAMPLES=OFF \
  -DHWY_ENABLE_INSTALL=OFF -DHWY_ENABLE_LIST_TARGETS=OFF
cmake --build "$TB" -j"$MAYHEM_JOBS" --target base64_test range_coder_test ans_test iguana_test
