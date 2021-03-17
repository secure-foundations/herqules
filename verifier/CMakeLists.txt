include(${CMAKE_ROOT}/Modules/ExternalProject.cmake)

set(CMAKE_CXX_STANDARD 17)

# Build abseil
set(BUILD_TESTING OFF)
add_subdirectory(abseil)

add_executable(verifier
    main.cpp
    process.cpp
    verifier-elf.cpp
    ${INTERFACE_RX_SRC}
)

target_include_directories(verifier
    PRIVATE abseil)

target_link_directories(verifier
    PRIVATE ${CMAKE_BINARY_DIR}/abseil/lib)

if (INTERFACE STREQUAL "DPDK")
    target_include_directories(verifier SYSTEM PRIVATE "/usr/include/dpdk" "/usr/include/x86_64-linux-gnu/dpdk")
    target_compile_options(verifier PRIVATE "-Wno-register")
endif()

if (NOT ${INTERFACE} STREQUAL "OPAE")
    target_compile_options(verifier PRIVATE "-fno-exceptions")
endif()

target_link_libraries(verifier
    absl::node_hash_map
    ${INTERFACE_LIBS}
)
