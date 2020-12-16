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

export HQ_INLINE_PATH=$BUILD_PATH/rtlib/rtlib_msg.o
OPT="-fstrict-vtable-pointers -fforce-emit-vtables -fvirtual-function-elimination -fwhole-program-vtables"

CFLAGS_NONE=" --target=x86_64-pc-linux-musl --sysroot=/opt/cross-none --gcc-toolchain=/opt/cross-none -flto -fvisibility=hidden $OPT"
LDFLAGS_NONE=" -Wl,-z,now -Wl,-z,relro --target=x86_64-pc-linux-musl --sysroot=/opt/cross-none --gcc-toolchain=/opt/cross-none -flto -fuse-ld=gold -Wl,-I,/lib/ld-musl-none-x86_64.so.1"

CFLAGS_CFI="-fplugin=$BUILD_PATH/llvm/libcfi.so -flto -fvisibility=hidden -fsanitize=cfi-nvcall,cfi-vcall,cfi-icall,cfi-mfcall,safe-stack $OPT"
LDFLAGS_CFI="-Wl,-z,now -Wl,-z,relro -fplugin=$BUILD_PATH/llvm/libcfi.so -flto -fuse-ld=gold -fsanitize=safe-stack"

echo "Building the main repository"
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Release -DLLVM_DIR=$CLANG_HQ/lib/cmake/llvm -DINTERFACE=MODEL -DBUILD_RTLIB_INLINE=ON ..
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

echo "Building HTTP benchmarking tool"
cd tests/wrk
WITH_OPENSSL=/usr make -j
cd ../..

echo "Building baseline NGINX"
cp -r tests/nginx tests/nginx_none
cd tests/nginx_none
./auto/configure --with-cc=$CLANG_NONE --with-cpp=$CLANGXX_NONE --with-cc-opt="$CFLAGS_NONE -Wno-sign-compare" --with-ld-opt="$LDFLAGS_NONE" --without-http_rewrite_module --without-http_gzip_module --prefix=`pwd`/root
make -j install
cd ../..

echo "Loading kernel module and verifier for NGINX configuration"
sudo insmod $BUILD_PATH/kernel/hq.ko
sudo $BUILD_PATH/verifier/verifier &

echo "Building instrumented (HQ-CFI-SafeStack-Model) NGINX"
cd tests/nginx
./auto/configure --with-cc=$CLANG_CFI --with-cpp=$CLANGXX_CFI --with-cc-opt="$CFLAGS_CFI -Wno-sign-compare" --with-ld-opt="$LDFLAGS_CFI" --without-http_rewrite_module --without-http_gzip_module --prefix=`pwd`/root
make -j install
cd ../..

echo "Unloading verifier and kernel module"
sudo killall verifier
sudo rmmod hq

echo "Building baseline SPEC"
cd tests/llvm-test-suite
mkdir build_none
cd build_none
cmake -DTEST_SUITE_SUBDIRS=External -DCMAKE_C_COMPILER=$CLANG_NONE -DCMAKE_CXX_COMPILER=$CLANGXX_NONE -C../cmake/caches/O3.cmake -DTEST_SUITE_SPEC2006_ROOT=$SPEC2006 -DTEST_SUITE_SPEC2017_ROOT=$SPEC2017 -DCMAKE_CXX_FLAGS="$CFLAGS_NONE" -DCMAKE_C_FLAGS="$CFLAGS_NONE" -DCMAKE_EXE_LINKER_FLAGS="$LDFLAGS_NONE" -DTEST_SUITE_USE_PERF=ON -DTEST_SUITE_RUN_TYPE=ref -DTEST_SUITE_COLLECT_CODE_SIZE=OFF -GNinja ..
ninja
cd ../../..

echo "Building instrumented (HQ-CFI-SafeStack-Model) SPEC"
cd tests/llvm-test-suite
mkdir build_hq
cd build_hq
cmake -DTEST_SUITE_SUBDIRS=External -DCMAKE_C_COMPILER=$CLANG_CFI -DCMAKE_CXX_COMPILER=$CLANGXX_CFI -C../cmake/caches/O3.cmake -DTEST_SUITE_SPEC2006_ROOT=$SPEC2006 -DTEST_SUITE_SPEC2017_ROOT=$SPEC2017 -DCMAKE_CXX_FLAGS="$CFLAGS_CFI" -DCMAKE_C_FLAGS="$CFLAGS_CFI" -DCMAKE_EXE_LINKER_FLAGS="$LDFLAGS_CFI" -DTEST_SUITE_USE_PERF=ON -DTEST_SUITE_RUN_TYPE=ref -DTEST_SUITE_COLLECT_CODE_SIZE=OFF -GNinja ..
ninja
cd ../../..

echo "Building the simulator (HQ-CFI-SafeStack-Sim)"
cd tests/zsim
scons
cd ../..

echo "Building RIPE testsuite"
cd tests/ripe
mkdir build
GCC=$CLANG_NONE CLG=$CLANG_CFI GCC_CFLAGS="$CFLAGS_NONE" GCC_LDFLAGS="$LDFLAGS_NONE" CLG_CFLAGS="$CFLAGS_CFI" CLG_LDFLAGS="$LDFLAGS_CFI" make
cd ../..
