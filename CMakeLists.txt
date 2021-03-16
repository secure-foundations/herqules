cmake_minimum_required(VERSION 3.10)
include(${CMAKE_ROOT}/Modules/ExternalProject.cmake)

project(HERQULES)

if (NOT EXISTS ${CMAKE_BINARY_DIR}/CMakeCache.txt)
  if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "RelWithDebInfo" CACHE STRING "" FORCE)
  endif()
endif()

set(INTERFACE "NONE" CACHE STRING "Communication interface between runtime and verifier.")

message(STATUS "Using host C compiler: ${CMAKE_C_COMPILER}")
message(STATUS "Using host C++ compiler: ${CMAKE_CXX_COMPILER}")
message(STATUS "Identified host compiler: ${CMAKE_C_COMPILER_ID} ${CMAKE_C_COMPILER_VERSION}")

# Modify variables directly to ensure they are passed on to e.g. kernel
string(APPEND CMAKE_C_FLAGS " -Wall -march=native -mno-fsgsbase -DINTERFACE_TYPE=INTERFACE_TYPE_${INTERFACE}")
string(APPEND CMAKE_CXX_FLAGS " -Wall -march=native -mno-fsgsbase -fno-rtti -DINTERFACE_TYPE=INTERFACE_TYPE_${INTERFACE}")
# Disable Intel Control-flow Enforcement Technology (CET)
if (CMAKE_C_COMPILER_ID STREQUAL "GNU" AND CMAKE_C_COMPILER_VERSION VERSION_GREATER_EQUAL 8.0)
    string(APPEND CMAKE_C_FLAGS " -fcf-protection=none")
endif()
if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL 8.0)
    string(APPEND CMAKE_CXX_FLAGS " -fcf-protection=none")
endif()

include_directories("include")

add_subdirectory(kernel)

message(STATUS "Using interface: ${INTERFACE}")

if (INTERFACE STREQUAL "DPDK")
    get_filename_component(DPDK_RX_INTERFACE_PATH "interfaces/dpdk-rx.cpp" ABSOLUTE)
    get_filename_component(DPDK_TX_INTERFACE_PATH "interfaces/dpdk-tx.cpp" ABSOLUTE)

    list(APPEND INTERFACE_RX_SRC ${DPDK_RX_INTERFACE_PATH})
    list(APPEND INTERFACE_TX_SRC ${DPDK_TX_INTERFACE_PATH})
    list(APPEND INTERFACE_LIBS "rte_eal" "rte_ethdev" "rte_kvargs" "rte_mbuf" "rte_mempool" "rte_net")
    add_subdirectory(verifier)
elseif (INTERFACE STREQUAL "MODEL")
    get_filename_component(MODEL_RX_INTERFACE_PATH "interfaces/model-rx.cpp" ABSOLUTE)

    list(APPEND INTERFACE_RX_SRC ${MODEL_RX_INTERFACE_PATH})
    list(APPEND INTERFACE_LIBS "rt")
    add_subdirectory(verifier)
elseif (INTERFACE STREQUAL "MODEL_SIM")
    get_filename_component(MODEL_SIM_RX_INTERFACE_PATH "interfaces/model_sim-rx.cpp" ABSOLUTE)

    list(APPEND INTERFACE_RX_SRC ${MODEL_SIM_RX_INTERFACE_PATH})
    list(APPEND INTERFACE_LIBS "rt")
    add_subdirectory(verifier)
elseif (INTERFACE STREQUAL "NONE")
    add_subdirectory(verifier)
elseif (INTERFACE STREQUAL "OPAE")
    if (BUILD_FPGA_SIMULATION)
        string(APPEND CMAKE_C_FLAGS " -DHQ_INTERFACE_OPAE_SIMULATE")
        string(APPEND CMAKE_CXX_FLAGS " -DHQ_INTERFACE_OPAE_SIMULATE")
    endif()

    add_subdirectory(fpga)

    get_filename_component(OPAE_RX_INTERFACE_PATH "interfaces/opae-rx.cpp" ABSOLUTE)

    list(APPEND INTERFACE_RX_SRC ${OPAE_RX_INTERFACE_PATH})
    list(APPEND INTERFACE_LIBS "opae-c" "opae-cxx-core")
    add_subdirectory(verifier)
elseif (INTERFACE STREQUAL "PAGES")
    add_subdirectory(verifier)
elseif (INTERFACE STREQUAL "POSIX_FIFO")
    get_filename_component(POSIX_FIFO_RX_INTERFACE_PATH "interfaces/posix_fifo-rx.cpp" ABSOLUTE)

    list(APPEND INTERFACE_RX_SRC ${POSIX_FIFO_RX_INTERFACE_PATH})
    add_subdirectory(verifier)
elseif (INTERFACE STREQUAL "POSIX_MQ")
    get_filename_component(POSIX_MQ_RX_INTERFACE_PATH "interfaces/posix_mq-rx.cpp" ABSOLUTE)

    list(APPEND INTERFACE_RX_SRC ${POSIX_MQ_RX_INTERFACE_PATH})
    list(APPEND INTERFACE_LIBS "rt")
    add_subdirectory(verifier)
elseif (INTERFACE STREQUAL "POSIX_SHM")
    get_filename_component(POSIX_SHM_RX_INTERFACE_PATH "interfaces/posix_shm-rx.cpp" ABSOLUTE)

    list(APPEND INTERFACE_RX_SRC ${POSIX_SHM_RX_INTERFACE_PATH})
    list(APPEND INTERFACE_LIBS "rt")
    add_subdirectory(verifier)
elseif (INTERFACE STREQUAL "SOCKETS_UNIX")
    get_filename_component(SOCKETS_UNIX_RX_INTERFACE_PATH "interfaces/sockets_unix-rx.cpp" ABSOLUTE)

    list(APPEND INTERFACE_RX_SRC ${SOCKETS_UNIX_RX_INTERFACE_PATH})
    add_subdirectory(verifier)
elseif (INTERFACE STREQUAL "ZERO")
    add_subdirectory(verifier)
else ()
    message(FATAL_ERROR "Must specify valid interface type (DPDK, MODEL, MODEL_SIM, NONE, OPAE, PAGES, POSIX_FIFO, POSIX_MQ, POSIX_SHM, SOCKETS_UNIX, or ZERO)!")
endif()

add_subdirectory(llvm)

# Use external project because of separate compiler
option(BUILD_RTLIB_INLINE "Build interface for inlining.")
ExternalProject_Add(rtlib
    BUILD_ALWAYS ON
    SOURCE_DIR ${CMAKE_SOURCE_DIR}/rtlib
    INSTALL_DIR ${CMAKE_BINARY_DIR}/rtlib
    CMAKE_ARGS -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE} -DCMAKE_INSTALL_PREFIX=<INSTALL_DIR> -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER} -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER} -DINTERFACE=${INTERFACE} -DBUILD_RTLIB_INLINE=${BUILD_RTLIB_INLINE}
    BUILD_BYPRODUCTS ${CMAKE_BINARY_DIR}/rtlib/librtlib.a
)

add_subdirectory(tests)
