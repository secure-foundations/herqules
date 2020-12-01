set(CMAKE_CXX_STANDARD 17)

list(APPEND OPAE_LIBS "opae-c" "opae-cxx-core" "uuid")

add_executable(linked_list_malloc
    linked_list_malloc.cpp
    opae_svc_wrapper.cpp
)

target_link_libraries(linked_list_malloc
    ${OPAE_LIBS}
)

add_executable(micro_a
    micro_a.cpp
    opae_svc_wrapper.cpp
)

target_link_libraries(micro_a
    ${OPAE_LIBS}
)

add_executable(micro_b
    micro_b.cpp
    opae_svc_wrapper.cpp
)

target_link_libraries(micro_b
    ${OPAE_LIBS}
)

add_executable(latency
    latency.cpp
    ${INTERFACE_RX_SRC}
    ${INTERFACE_TX_SRC}
)

target_link_libraries(latency
    ${INTERFACE_LIBS}
)

if (INTERFACE STREQUAL "DPDK")
    target_include_directories(latency SYSTEM PRIVATE "/usr/include/dpdk" "/usr/include/x86_64-linux-gnu/dpdk")
    target_compile_options(latency PRIVATE "-Wno-register" "-DHQ_INTERFACE_DPDK_SAME_PROCESS")
endif()
