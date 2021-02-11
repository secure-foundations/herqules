# musl with syscall instrumentation
export CROSS=/opt/cross
# musl using CCFI compiler to avoid certain xmm/ymm registers
export CROSS_CCFI=/opt/cross-ccfi
# baseline musl
export CROSS_NONE=/opt/cross-none

export HQ=/home/user/herqules
export LEVEE=/home/user/levee
export CCFI=/home/user/ccfi

# https://github.com/secure-foundations/hw-ccfi
export CLANG_CFI=${HQ}/llvm/llvm-project/llvm/build_release/bin/clang
export CLANGXX_CFI=${HQ}/llvm/llvm-project/llvm/build_release/bin/clang++
export CFLAGS_CFI="-fplugin=${HQ}/build/llvm/libcfi.so -fno-discard-value-names -flto -fstrict-vtable-pointers -fforce-emit-vtables -fvirtual-function-elimination -fwhole-program-vtables -fvisibility=hidden -fsanitize=cfi-nvcall,cfi-vcall,cfi-icall,cfi-mfcall,safe-stack"
export LDFLAGS_CFI="-fplugin=${HQ}/build/llvm/libcfi.so -Wl,-z,now -Wl,-z,relro -flto -fuse-ld=gold -fsanitize=safe-stack"
export HQ_INLINE_PATH="${HQ}/build/rtlib/rtlib_msg.o"

# https://apt.llvm.org/ or Ubuntu repositories
export CLANG_NONE=clang-10
export CLANGXX_NONE=clang++-10
export CFLAGS_NONE="--target=x86_64-pc-linux-musl --sysroot=${CROSS_NONE} --gcc-toolchain=${CROSS_NONE} -fno-discard-value-names -flto -fstrict-vtable-pointers -fforce-emit-vtables -fvirtual-function-elimination -fwhole-program-vtables -fvisibility=hidden"
export CFLAGS_CFI10="${CFLAGS_NONE} -fsanitize=cfi-nvcall,cfi-vcall,cfi-icall,cfi-mfcall,safe-stack -fno-sanitize-trap=cfi -fsanitize-recover=cfi"
export LDFLAGS_NONE="-Wl,-z,now -Wl,-z,relro --target=x86_64-pc-linux-musl --sysroot=${CROSS_NONE} --gcc-toolchain=${CROSS_NONE} -flto -fuse-ld=gold -Wl,--dynamic-linker=/lib/ld-musl-none-x86_64.so.1"
export LDFLAGS_CFI10="${LDFLAGS_NONE} -fsanitize=cfi-nvcall,cfi-vcall,cfi-icall,cfi-mfcall,safe-stack -fno-sanitize-trap=cfi -fsanitize-recover=cfi"

# https://github.com/ddcc/levee
export CLANG_CPI=${LEVEE}/build/bin/clang
export CLANGXX_CPI=${LEVEE}/build/bin/clang++
export CFLAGS_CPI="-target x86_64-pc-linux-musl -gcc-toolchain ${CROSS_NONE} --sysroot=${CROSS_NONE} -flto -fcpi -fsafe-stack -fPIE"
export LDFLAGS_CPI="-pie -Wl,-z,now -Wl,-z,relro -target x86_64-pc-linux-musl -gcc-toolchain ${CROSS_NONE} --sysroot=${CROSS_NONE} -flto -fcpi -fsafe-stack -Wl,--dynamic-linker=/lib/ld-musl-none-x86_64.so.1"

# https://github.com/ddcc/ccfi
export CLANG_CCFI=${CCFI}/Release+Asserts/bin/clang
export CLANGXX_CCFI=${CCFI}/Release+Asserts/bin/clang++
export CFLAGS_CCFI="-target x86_64-pc-linux-musl -gcc-toolchain ${CROSS_CCFI} --sysroot=${CROSS_CCFI} -flto -fPIE"
export LDFLAGS_CCFI="-pie -Wl,-rpath,${CCFI}/Release+Asserts/lib -L${CCFI}/Release+Asserts/lib -lccfi_rt -Wl,-z,now -Wl,-z,relro -target x86_64-pc-linux-musl -gcc-toolchain ${CROSS_CCFI} --sysroot=${CROSS_CCFI} -flto -Wl,--dynamic-linker=/lib/ld-musl-ccfi-x86_64.so.1"
