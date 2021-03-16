option(BUILD_TESTS_FPGA "Build test executables for FPGA. Requires BBB_cci_mpf and libuuid.")

if (INTERFACE STREQUAL "OPAE")
    message(STATUS "Build FPGA tests: ${BUILD_TESTS_FPGA}")

    if (BUILD_TESTS_FPGA)
        add_subdirectory(fpga)
    endif()
endif()

set(CMAKE_CXX_STANDARD 17)

add_executable(rtt
    rtt.cpp
    ${INTERFACE_RX_SRC}
    ${INTERFACE_TX_SRC}
)

add_dependencies(rtt
    rtlib
)

target_link_libraries(rtt
    ${CMAKE_BINARY_DIR}/rtlib/librtlib.a
    ${INTERFACE_LIBS}
)

if (INTERFACE STREQUAL "DPDK")
    target_include_directories(rtt SYSTEM PRIVATE "/usr/include/dpdk" "/usr/include/x86_64-linux-gnu/dpdk")
    target_compile_options(rtt PRIVATE "-Wno-register" "-DHQ_INTERFACE_DPDK_SAME_PROCESS")
endif()
