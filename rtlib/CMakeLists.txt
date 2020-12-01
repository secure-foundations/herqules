cmake_minimum_required(VERSION 3.12)

project(HQ-RTLIB)

set(CMAKE_CXX_STANDARD 17)

message(STATUS "Identified host compiler for runtime libraries: ${CMAKE_C_COMPILER_ID} ${CMAKE_C_COMPILER_VERSION}")

add_compile_options("-Wall" "-march=native" "-fcf-protection=none" "-mno-fsgsbase" "-DINTERFACE_TYPE=INTERFACE_TYPE_${INTERFACE}" "-fPIC" "-fno-rtti" "-fno-exceptions" "-nodefaultlibs" "-nostdlib" "-U_FORTIFY_SOURCE" "-g")

include_directories("../include")

add_library(rtlib STATIC
    init.cpp
    rtlib.cpp
    ${INTERFACE_TX_SRC}
)

if (INTERFACE STREQUAL "DPDK")
    set(RTLIB_DPDK "librtlib-dpdk.a")
    target_include_directories(rtlib SYSTEM PRIVATE "/opt/cross/include/dpdk")

    # Generate a MRI script to instruct the archiver to combine static libraries
    set(MRI_SCRIPT ${CMAKE_CURRENT_BINARY_DIR}/script.mri)
    list(TRANSFORM INTERFACE_LIBS PREPEND "addlib /opt/cross/x86_64-pc-linux-musl/lib/lib" OUTPUT_VARIABLE INTERFACE_LIBS_LIST)
    list(TRANSFORM INTERFACE_LIBS_LIST APPEND ".a")
    list(JOIN INTERFACE_LIBS_LIST "\n" INTERFACE_LIBS_STR)
    file(GENERATE OUTPUT ${MRI_SCRIPT} CONTENT "create $<TARGET_FILE_NAME:rtlib>\naddlib ${RTLIB_DPDK}\n${INTERFACE_LIBS_STR}\nsave\nend\n")

    # Rename the built library
    add_custom_command(TARGET rtlib
        POST_BUILD
        COMMAND ${CMAKE_COMMAND}
        ARGS -E rename $<TARGET_FILE_NAME:rtlib> ${RTLIB_DPDK}
        BYPRODUCTS ${RTLIB_DPDK}
        VERBATIM
    )

    # Combine the built library and its dependencies
    add_custom_command(TARGET rtlib
        POST_BUILD
        COMMAND ${CMAKE_AR}
        ARGS -M < ${MRI_SCRIPT}
        VERBATIM
    )
elseif (INTERFACE STREQUAL "MODEL_SIM")
    target_compile_options(rtlib PRIVATE "-mno-vzeroupper")
endif()

option(BUILD_RTLIB_INLINE "Build interface for inlining.")
message(STATUS "Build interface for inlining: ${BUILD_RTLIB_INLINE}")

if (BUILD_RTLIB_INLINE)
  if (NOT CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    message(FATAL_ERROR "Host compiler must be Clang for interface inlining!")
  endif()

  if (NOT (INTERFACE STREQUAL "MODEL" OR INTERFACE STREQUAL "MODEL_SIM" OR INTERFACE STREQUAL "NONE" OR INTERFACE STREQUAL "OPAE" OR INTERFACE STREQUAL "POSIX_SHM" OR INTERFACE STREQUAL "PAGES" OR INTERFACE STREQUAL "ZERO"))
    message(FATAL_ERROR "Only MODEL, MODEL_SIM, NONE, OPAE, POSIX_SHM, PAGES, and ZERO interfaces are inlinable!")
  endif()

  add_library(rtlib_msg OBJECT
      rtlib.cpp
  )

  # Label functions as always_inline, build for musl, and remove debug information to avoid assertion
  target_compile_options(rtlib_msg PRIVATE "-flto" "-DINLINE" "-g0" "--target=x86_64-pc-linux-musl")

  install(FILES $<TARGET_OBJECTS:rtlib_msg>
    DESTINATION .
    RENAME rtlib_msg.o
  )
endif()

install(TARGETS rtlib
  ARCHIVE
  DESTINATION .
)
