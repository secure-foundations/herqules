These patches are included to fix various compatibility and correctness bugs in the [SPEC CPU2006](https://www.spec.org/cpu2006/) v1.2 and [SPEC CPU2017](https://www.spec.org/cpu2017/) v1.0.5 benchmarks.

|Patch|Benchmark|Type|Description|
|-----|---------|----|-----------|
|`400-perlbench.patch`|400.perlbench|Compatibility|Always include appropriate header file, and avoid accessing non-standard fields from the C runtime library.|
|`400-perlbench-ms.patch`|400.perlbench|Correctness|Avoid out-of-bounds read in string comparison. See [original patch](https://github.com/google/sanitizers/blob/master/address-sanitizer/spec/spec2006-asan.patch).|
|`464-h264ref-ms.patch`|464.h264ref|Correctness|Avoid out-of-bounds reads in integer arrays. See [FAQ entry](https://www.spec.org/cpu2006/Docs/faq.html#Run.05) for the second, the first appears to be unreported.|
|`471-omnetpp.patch`|471.omnetpp|Correctness|Use 'construct on first use idiom' to avoid a [static initialization/destruction order problem](https://isocpp.org/wiki/faq/ctors#static-init-order) that incorrectly uses static objects before they are constructed or after they have been destroyed. Reported in HerQules.|
|`471-omnetpp-asan.patch`|471.omnetpp|Compatibility|Do not override `operator new` and `operator delete`, which are intercepted by [AddressSanitizer](https://github.com/google/sanitizers/wiki/AddressSanitizer).|
|`483-xalancbmk.patch`|483.xalancbmk|Correctness|Do not cast an object to an incorrect type. Miscompiles with devirtualization enabled.|
|`500-perlbench_r.patch`|500.perlbench_r, 600.perlbench_s|Compatibility|See `400-perlbench.patch`.|
|`502-gcc_r.patch`|502.gcc_r, 602.gcc_s|Correctness|Avoid a SPEC-specific macro that generates incorrect code and crashes the program at runtime. Miscompiles with optimizations enabled.|
|`502-gcc_r-ms.patch`|502.gcc_r, 602.gcc_s|Correctness|Avoid out-of-bounds read in operand array. Appears to be unreported, [fixed upstream](https://github.com/gcc-mirror/gcc/commit/6141b7db4599e176bddab4b4573d4e08a8284ed7).|
|`520-omnetpp_r.patch`|520.omnetpp_r, 620.omnetpp_s|Correctness|See `471-omnetpp.patch` and `483-xalancbmk.patch`.|
|N/A|520.omnetpp_r, 620.omnetpp_s|Correctness|Not fixed: on the `defaultList` static object in `cownedobject.cc`, the constructor for the derived class `cDefaultList` is called inside the constructor for the base class `cOwnedObject`. |
|`526-blender_r.patch`|526.blender_r|Compatibility|Do not use the [`execinfo.h`](https://www.gnu.org/software/gnulib/manual/html_node/execinfo_002eh.html) header unless compiling with the [glibc](https://www.gnu.org/software/libc/) C runtime library.|
