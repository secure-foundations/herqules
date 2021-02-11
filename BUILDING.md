# Configuration

Adjust the definitions of the macros in the `include/config.h` file.

# Instructions

1. Modify the script to adjust configuration options as desired, then execute it to install all dependencies and configure the system:

```
nano ./scripts/setup.sh
sudo ./scripts/setup.sh
```

## HerQules

1. Select an interface to use for communication between the runtime and verifier:

* `MODEL`: Models the behavior of AppendWrite in software using a [POSIX shared memory](http://man7.org/linux/man-pages/man7/shm_overview.7.html) interface (`/dev/shm/HQ`). For performance testing only; messages are not actually append-only.
* `MODEL_SIM`: Models the behavior of AppendWrite in a hardware simulator, using a dummy instruction for AppendWrite. For simulator performance testing only; messages are not actually sent.
* `OPAE`: Implements AppendWrite in a FPGA using the [OPAE](https://01.org/OPAE) interface. Requires a compatible [Intel Programmable Accelerator Card](https://www.intel.com/content/www/us/en/programmable/solutions/acceleration-hub/platforms.html). Complete [setup instructions below](#intel-programmable-acceleration-card-pac) before continuing.
* `POSIX_FIFO`: Implements a [POSIX named pipe (FIFO)](http://man7.org/linux/man-pages/man7/fifo.7.html) interface (`/tmp/HQ`).
* `POSIX_MQ`: Implements a [POSIX message queue](http://man7.org/linux/man-pages/man7/mq_overview.7.html) interface (`/dev/mqueue/HQ`).
* `POSIX_SHM`: Implements a [POSIX shared memory](http://man7.org/linux/man-pages/man7/shm_overview.7.html) interface (`/dev/shm/HQ`). For performance testing only; messages are not actually append-only.
* `SOCKETS_UNIX`: Implements a [UNIX domain socket](https://man7.org/linux/man-pages/man7/unix.7.html) interface (`/tmp/HQ`).
* `DPDK`: Implements AppendWrite in a NIC using the [DPDK](https://www.dpdk.org) interface. Requires a [compatible multi-port NIC](https://ark.intel.com/content/www/us/en/ark/products/88209/intel-ethernet-converged-network-adapter-x550-t2.html), with each processor core assigned to a unique NIC port, and all assigned ports connected to the same network or loopback. For testing only; suffers from various DPDK limitations. Logs are written to `/tmp/dpdk.<pid>.log`.
* `NONE`: Implements a dummy interface that does not receive or send messages. For testing only.
* `PAGES`: Implements a dummy interface that does not receive messages, but uses a kernel module (`pages`) to send messages to physical memory pages, which can be either write-through, write-combining, or uncached. For testing only.
* `ZERO`: Implements a dummy interface that does not receive messages, but sends them to an anonymous zero page. For testing only.

2. Build or download our modified LLVM compiler toolchain. See [setup instructions below](#compiler-clangllvm).

4. Build and compile the HerQules framework, including FPGA bitstream, compiler instrumentation, runtime library, and verifier application, as follows. To support inlining our messaging interface, also pass `-DBUILD_RTLIB_INLINE=ON` to CMake, but this is not compatible with all interfaces.

```
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Release -DLLVM_DIR=$CLANG_HQ/lib/cmake/llvm -DINTERFACE=<interface> ..
make
export BUILD_PATH=`pwd`
export CFLAGS_CFI+=" -fplugin=$BUILD_PATH/llvm/libcfi.so"
export LDFLAGS_CFI+=" -Wl,-z,now -Wl,-z,relro -fplugin=$BUILD_PATH/llvm/libcfi.so"
```

5. Build our modified standard runtime libraries. See [setup instructions below](#standard-runtimes-musl-libstdc).

6. Initialize the interface and execute the verifier. See [setup instructions below](#verifier).

7. Build and execute applications. See [setup instructions below](#applications).

## Intel Programmable Acceleration Card (PAC)

1. If not installed already by the setup script, install [OPAE](https://github.com/OPAE/opae-sdk) from source:

```
mkdir build
cd build
cmake -DCPACK_GENERATOR=DEB ..
make package_deb
dpkg -i *.deb
```

2. Depending on hardware, install the appropriate Intel Acceleration Stack for Development, including the bundled Quartus Prime, but skip the bundled OPAE, which is likely outdated. If you are using an unsupported version of Ubuntu, you will need to modify the installer `setup.sh` script to set `is_ubuntu=1`:

* Arria 10 GX: [v1.2.0](https://www.intel.com/content/www/us/en/programmable/f/download/accelerator/eula.html?swcode=WWW-SWD-ASD-12) with [v1.2.0 Update 1](https://www.intel.com/content/www/us/en/programmable/f/download/accelerator/eula.html?swcode=WWW-SWD-DCP-A10-GX-PAC-PV-12-UPDATE)
<!-- * Arria 10 GX: [v1.2.1](https://www.intel.com/content/www/us/en/programmable/f/download/accelerator/eula.html?swcode=WWW-SWD-IAS-A10-GX-PAC-PV-DEV-121) -->
* Stratix 10 SX: [v2.0.1](https://www.intel.com/content/www/us/en/programmable/f/download/accelerator/license-agreement-pac-d5005.html?swcode=WWW-SWD-IAS-DEV-201)

3. To simulate the bitstream, [Synopsys VCS-MX](https://www.synopsys.com/verification/simulation/vcs.html) and the `opae-ase` package must be installed. Note that the simulator environment does not support memory mapping or shared access, so any usage of memory-mapped I/O will not work.

4. When [configuring HerQules](#HerQules), pass the following additional arguments to CMake `-DINTEL_PAC_SDK=<sdk path> -DBUILD_FPGA_BITSTREAM=ON -DBUILD_FPGA_SIMULATION=OFF`, as desired. A test OPAE application can also be built by passing `-DBUILD_TESTS_FPGA=ON`, but this requires installation of [BBB_cci_mpf](https://github.com/OPAE/intel-fpga-bbb) and libuuid. Note that a pre-built bitstream for the Arria 10 is available under GitHub Releases.

5. After HerQules has been built, program the bitstream and/or run the simulation, as follows:

* Bitstream: Program the Intel PAC with the bitstream file using `sudo fpgaconf -V build/fpga/bitstream/hq_fifo.gbs`.

* Simulation: Run `make sim` in the `<build>/fpga/simulation` directory to execute the simulator. In another terminal, follow the simulator instructions to set the `ASE_WORKDIR` environment variable, then execute the target program in the simulator using `with_ase <program>`.

## Compiler (Clang/LLVM)

1. Obtain our modified Clang/LLVM compiler toolchain, which supports plugin passes during LTO, includes additional optimizations, does not discard value names and lifetime markers, and is configured with a default target triple and system root directory for musl cross-compilation. Either:

* Use the pre-built binaries under GitHub Releases, and extract to e.g. `llvm/llvm-project/llvm/build_release`.
* Build the `llvm-project` submodule from source, as follows:

```
cd llvm/llvm-project/llvm
mkdir build_release
cd build_release
cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo -DLLVM_CCACHE_BUILD=ON -DLLVM_BINUTILS_INCDIR=/usr/include -DLLVM_ENABLE_PROJECTS=clang -DLLVM_ENABLE_RUNTIMES=compiler-rt -DLLVM_TARGETS_TO_BUILD=X86 -DLLVM_DEFAULT_TARGET_TRIPLE=x86_64-pc-linux-musl -DDEFAULT_SYSROOT=/opt/cross -DLLVM_USE_LINKER=gold -DLLVM_CCACHE_BUILD=ON -DLLVM_OPTIMIZED_TABLEGEN=ON -DLLVM_LINK_LLVM_DYLIB=ON -DLLVM_USE_SPLIT_DWARF=ON -DLLVM_USE_GDB_INDEX=ON -DLLVM_ENABLE_DUMP=ON -GNinja ..
ninja
```

2. Set the appropriate environment variables to refer to the original and modified Clang/LLVM compiler toolchains:

```
export CLANG_NONE="clang-10"
export CLANGXX_NONE="clang++-10"

export CLANG_HQ="<llvm path>"
export CLANG_CFI="$CLANG_HQ/bin/clang"
export CLANGXX_CFI="$CLANG_HQ/bin/clang++"
```

## Standard Runtimes (musl, libstdc++)

1. Obtain a cross-compile environment that uses the musl C runtime library, either:

* Use the pre-built binaries under GitHub Releases, and extract to `/opt/cross`.
* Build the `musl-cross-make` and `musl` submodules from source, as follows:

```
cd rtlib/musl-cross-make
make
sudo make install
sudo rm -r /opt/cross/x86_64-pc-linux-musl/include
cd /opt/cross/x86_64-pc-linux-musl
sudo ln -s ../include include
sudo ln -s /usr/include/sys/queue.h include/sys/queue.h
```

2. Create a copy of this cross-compile environment for baseline experiments, and configure it:

```
sudo cp -r /opt/cross /opt/cross-none
sudo ln -s /opt/cross-none/x86_64-pc-linux-musl/lib/libc.so /lib/ld-musl-none-x86_64.so.1
echo "/opt/cross-none/x86_64-pc-linux-musl/lib" | sudo tee /etc/ld-musl-none-x86_64.path
```

3. Create the instrumented cross-compile environment, by rebuilding the musl C runtime library with the HerQules runtime library and system call instrumentation, overwriting the uninstrumented one, and configuring it:

```
export HQ_SYSCALLS_ONLY=1
cd rtlib/musl
mkdir build
cd build
CC=$CLANG_CFI CXX=$CLANGXX_CFI CFLAGS+=" -fplugin=$BUILD_PATH/llvm/libcfi.so" LDFLAGS+=" -L$BUILD_PATH/rtlib -Wl,--whole-archive -lrtlib -Wl,--no-whole-archive" ../configure
make
sudo cp lib/libc.* /opt/cross/x86_64-pc-linux-musl/lib/
unset HQ_SYSCALLS_ONLY
sudo ln -s /opt/cross/x86_64-pc-linux-musl/lib/libc.so /lib/ld-musl-x86_64.so.1
echo "/opt/cross/x86_64-pc-linux-musl/lib" | sudo tee /etc/ld-musl-x86_64.path
```

## Verifier

1. Load the HerQules kernel interface:

```
sudo insmod kernel/hq.ko
```

2. Initialize the selected message interface, if needed:

* `DPDK`: `sudo modprobe vfio_pci; sudo dpdk-devbind -b vfio-pci <nic pci id>; export XDG_RUNTIME_DIR=/var/run; sudo chmod a+rwx -R /var/run/dpdk; sudo chmod a+rw -R /dev/hugepages; sudo chmod a+rw -R /dev/vfio`
* `OPAE`: `sudo chmod a+rw /dev/intel-fpga-port.0`
* `PAGES`: `sudo insmod kernel/pages/pages.ko`

3. Execute the verifier:

```
sudo ./verifier/verifier
```

## Applications

1. Set the compiler flags for building applications, as shown below. Certain variables are used only to build the baseline (`CLANG_NONE`, `CLANGXX_NONE`, `CFLAGS_NONE`, `LDFLAGS_NONE`), whereas others are used to build with HerQules and CFI (`CLANG_CFI`, `CLANGXX_CFI`, `CFLAGS_CFI`, `LDFLAGS_CFI`). Devirtualization optimizations can be enabled by expanding the `OPT` variable when building. Inlining of the messaging interface can enabled by setting the variable `HQ_INLINE_PATH`: `export HQ_INLINE_PATH=$BUILD_PATH/rtlib/rtlib_msg.o`.

```
export OPT+=" -fstrict-vtable-pointers -fforce-emit-vtables -fvirtual-function-elimination -fwhole-program-vtables"

export CFLAGS_NONE+=" --target=x86_64-pc-linux-musl --sysroot=/opt/cross-none --gcc-toolchain=/opt/cross-none -flto -fvisibility=hidden"
export LDFLAGS_NONE+=" -Wl,-z,now -Wl,-z,relro --target=x86_64-pc-linux-musl --sysroot=/opt/cross-none --gcc-toolchain=/opt/cross-none -flto -fuse-ld=gold -Wl,--dynamic-linker=/lib/ld-musl-none-x86_64.so.1"

export CFLAGS_CFI+=" -flto -fvisibility=hidden -fsanitize=cfi-nvcall,cfi-vcall,cfi-icall,cfi-mfcall,safe-stack"
export LDFLAGS_CFI+=" -flto -fuse-ld=gold -fsanitize=safe-stack"
```

### Sample Application

1. Compile this application with CFI and optimizations, which should produce similar output:

```
$ $CLANGXX_CFI $CFLAGS_CFI $OPT -O3 ../tests/general.cpp -c -o general.o
../tests/general.cpp: Instrumented 0 system calls, function pointers (4 defines, 0 invalidates), vtable pointers (0 defines, 2 invalidates), 10 uses

$ $CLANGXX_CFI $LDFLAGS_CFI $OPT -O3 -o general general.o
ld-temp.o: Finalized away pointers (1 defines, 2 checks, 0 check-invalidates, 0 invalidates), inserted calls (0 copies/moves, 0 frees), and instrumented globals (1 recursion guards, 6 function pointers, 0 vtable pointers | 6 internal, 0 external)
```

2. Execute this application, which should produce similar output:

```
$ ./general
Test: Function pointers
Called: char *f1()
Called: char *f1()
Called: char *f1()
Called: char *f1()
Test: C++ virtual calls
Called: virtual void Bar::f() const
Called: virtual void Bar::f() const
Test: C++ member functions
Called: virtual void Bar::f() const
Test: Dominated load
Called: char *f2()
Called: char *f2()
Called: char *f2()
Called: char *f2()
Test: Longjmp/setjmp
Called: char *f2()
Test: Corrupt
Called: char *f3()
Killed
```

### RIPE

1. Build the attack generator as follows. Note that we repurpose the 'GCC' build as the baseline without HerQules or our CFI scheme.

```
cd tests/ripe
GCC=$CLANG_NONE CLG=$CLANG_CFI GCC_CFLAGS="$CFLAGS_NONE" GCC_LDFLAGS="$LDFLAGS_NONE" CLG_CFLAGS="$CFLAGS_CFI" CLG_LDFLAGS="$LDFLAGS_CFI" make
```

2. Disable ASLR:
```
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
```

3. Run RIPE, with up to 3 tries for each attack.

```
./ripe_tester.py both 3 both
```

### LLVM Test Suite / SPEC Benchmarks

1. Patch the SPEC benchmarks:

```
cd <spec2006_path>; for i in <repo path>/tests/patches/4*.patch; do patch -p1 < $i; done
cd <spec2017_path>; for i in <repo path>/tests/patches/5*.patch; do patch -p1 < $i; done
```

2. Build the test suite, as shown below. Insert `OPT`, and/or substitute the appropriate variables for `CLANG`, `CLANGXX`, `CFLAGS`, and `LDFLAGS`, depending on the desired build configuration. Note that the test suite only supports the Release build mode.

```
cd tests/llvm-test-suite
mkdir build
cd build
cmake -DTEST_SUITE_SUBDIRS=External -DCMAKE_C_COMPILER=$CLANG -DCMAKE_CXX_COMPILER=$CLANGXX -C../cmake/caches/O3.cmake -DTEST_SUITE_SPEC2006_ROOT=<spec2006_path> -DTEST_SUITE_SPEC2017_ROOT=<spec2017_path> -DCMAKE_CXX_FLAGS="$CFLAGS" -DCMAKE_C_FLAGS="$CFLAGS" -DCMAKE_EXE_LINKER_FLAGS="$LDFLAGS" -DTEST_SUITE_USE_PERF=ON -DTEST_SUITE_RUN_TYPE=ref -DTEST_SUITE_COLLECT_CODE_SIZE=OFF -GNinja ..
ninja
```

3. If LLVM was not built from source, install the [lit](https://pypi.org/project/lit/) tool, as shown below. Otherwise, it should already be built as `$CLANG_HQ/bin/llvm-lit`.

```
pip install lit
```

4. Execute all SPEC benchmarks, then run a script to combine user-space performance statistics into `External/out.csv`:

```
<path to lit/llvm-lit> External/SPEC --time-tests -j1
./scripts/combine.py tests/llvm-test-suite/build/External
```

5. Alternatively, to run all benchmarks three times with a specified timeout in seconds, and save results with a given filename prefix:

```
./scripts/run.sh <prefix> <timeout>
```

### NGINX

1. Configure and build NGINX, as shown below. Insert `OPT`, and/or substitute the appropriate variables for `CLANG`, `CLANGXX`, `CFLAGS`, and `LDFLAGS`, depending on the desired build configuration.

```
./configure --with-cc=$CLANG --with-cpp=$CLANGXX --with-cc-opt="$CFLAGS -Wno-sign-compare" --with-ld-opt="$LDFLAGS" --without-http_rewrite_module --without-http_gzip_module --prefix=`pwd`/root
make -j install
```

2. Run NGINX:

```
./root/sbin/nginx
```

#### WRK: HTTP Benchmarking

1. Build the benchmarking tool:

```
cd tests/wrk
make -j
```

2. Run the benchmark against the local NGINX webserver:

```
./wrk --latency -t 1 -d 60s http://localhost:8080
```
