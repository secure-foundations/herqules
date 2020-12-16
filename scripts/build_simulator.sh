#!/bin/bash

set -e

# Path to pre-built Clang/LLVM toolchain
CLANG_HQ=
# Path to SPEC2006 source
SPEC2006=
# Path to SPEC2017 source
SPEC2017=

# Automatically-defined options
BUILD_PATH=`pwd`/build
CLANG_CFI=$CLANG_HQ/bin/clang
CLANGXX_CFI=$CLANG_HQ/bin/clang++
CLANG_NONE=clang-10
CLANGXX_NONE=clang++-10

OPT="-fstrict-vtable-pointers -fforce-emit-vtables -fvirtual-function-elimination -fwhole-program-vtables"

CFLAGS_NONE=" --target=x86_64-pc-linux-musl --sysroot=/opt/cross-none --gcc-toolchain=/opt/cross-none -flto -fvisibility=hidden $OPT"
LDFLAGS_NONE=" -Wl,-z,now -Wl,-z,relro --target=x86_64-pc-linux-musl --sysroot=/opt/cross-none --gcc-toolchain=/opt/cross-none -flto -fuse-ld=gold -Wl,-I,/lib/ld-musl-none-x86_64.so.1"

CFLAGS_CFI="-fplugin=$BUILD_PATH/llvm/libcfi.so -flto -fvisibility=hidden -fsanitize=cfi-nvcall,cfi-vcall,cfi-icall,cfi-mfcall,safe-stack $OPT"
LDFLAGS_CFI="-Wl,-z,now -Wl,-z,relro -fplugin=$BUILD_PATH/llvm/libcfi.so -flto -fuse-ld=gold -fsanitize=safe-stack"

echo "Building the main repository"
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Release -DLLVM_DIR=$CLANG_HQ/lib/cmake/llvm -DINTERFACE=MODEL_SIM -DBUILD_RTLIB_INLINE=ON ..
make
cd ..

echo "Building the standard runtimes"
cd rtlib/musl
mkdir build
cd build
export HQ_SYSCALLS_ONLY=1
CC=$CLANG_CFI CXX=$CLANGXX_CFI CFLAGS+=" -fplugin=$BUILD_PATH/llvm/libcfi.so" LDFLAGS+=" -L$BUILD_PATH/rtlib -Wl,--whole-archive -lrtlib -Wl,--no-whole-archive" ../configure
make -j
sudo cp lib/libc.* /opt/cross/x86_64-pc-linux-musl/lib/
unset HQ_SYSCALLS_ONLY
sudo ln -s /opt/cross/x86_64-pc-linux-musl/lib/libc.so /lib/ld-musl-x86_64.so.1
echo "/opt/cross/x86_64-pc-linux-musl/lib" | sudo tee /etc/ld-musl-x86_64.path
cd ../../..

echo "Building baseline SPEC"
cd tests/llvm-test-suite
mkdir build_none-sim
cd build_none-sim
cmake -DTEST_SUITE_SUBDIRS=External -DCMAKE_C_COMPILER=$CLANG_NONE -DCMAKE_CXX_COMPILER=$CLANGXX_NONE -C../cmake/caches/O3.cmake -DTEST_SUITE_SPEC2006_ROOT=$SPEC2006 -DTEST_SUITE_SPEC2017_ROOT=$SPEC2017 -DCMAKE_CXX_FLAGS="$CFLAGS_NONE" -DCMAKE_C_FLAGS="$CFLAGS_NONE" -DCMAKE_EXE_LINKER_FLAGS="$LDFLAGS_NONE" -DTEST_SUITE_USE_PERF=ON -DTEST_SUITE_RUN_TYPE=ref -DTEST_SUITE_COLLECT_CODE_SIZE=OFF -GNinja ..
ninja
cd ../../..

echo "Building instrumented (HQ-CFI-SafeStack-Sim) SPEC"
cd tests/llvm-test-suite
mkdir build_hq-sim
cd build_hq-sim
cmake -DTEST_SUITE_SUBDIRS=External -DCMAKE_C_COMPILER=$CLANG_CFI -DCMAKE_CXX_COMPILER=$CLANGXX_CFI -C../cmake/caches/O3.cmake -DTEST_SUITE_SPEC2006_ROOT=$SPEC2006 -DTEST_SUITE_SPEC2017_ROOT=$SPEC2017 -DCMAKE_CXX_FLAGS="$CFLAGS_CFI" -DCMAKE_C_FLAGS="$CFLAGS_CFI" -DCMAKE_EXE_LINKER_FLAGS="$LDFLAGS_CFI" -DTEST_SUITE_USE_PERF=ON -DTEST_SUITE_RUN_TYPE=ref -DTEST_SUITE_COLLECT_CODE_SIZE=OFF -GNinja ..
ninja
cd ../../..

echo "Building the simulator (HQ-CFI-SafeStack-Sim)"
cd tests/zsim
scons
cd ../..

