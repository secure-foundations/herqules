cmake_minimum_required(VERSION 3.12)

execute_process(COMMAND uname -r
                OUTPUT_VARIABLE kernel
                OUTPUT_STRIP_TRAILING_WHITESPACE)
set(module_path /lib/modules/${kernel}/build)

file(GLOB sources CONFIGURE_DEPENDS "*.c" "*.h" "*.o" "*.mod.o")

string(TOUPPER ${CMAKE_BUILD_TYPE} CMAKE_BUILD_TYPE_UPPER)
separate_arguments(kernel_cflags UNIX_COMMAND "${CMAKE_C_FLAGS} ${CMAKE_C_FLAGS_${CMAKE_BUILD_TYPE_UPPER}}")

add_custom_command(OUTPUT hq.ko
                   COMMAND ${CMAKE_MAKE_PROGRAM} KCFLAGS="${kernel_cflags}" -C ${module_path} M=${CMAKE_CURRENT_BINARY_DIR} src=${CMAKE_CURRENT_SOURCE_DIR}
                   DEPENDS ${sources} Kbuild
                  )

add_custom_target(kernel ALL DEPENDS hq.ko)

add_subdirectory(pages)
