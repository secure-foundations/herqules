find_package(LLVM REQUIRED CONFIG)

message(STATUS "Building plugin for LLVM (${LLVM_PACKAGE_VERSION}): ${LLVM_DIR}")

add_definitions(${LLVM_DEFINITIONS})
include_directories(${LLVM_INCLUDE_DIRS})

if (NOT LLVM_ENABLE_EH)
  string(APPEND CMAKE_CXX_FLAGS " -fno-exceptions")
endif()

if (NOT LLVM_ENABLE_RTTI)
  string(APPEND CMAKE_CXX_FLAGS " -fno-rtti")
endif()

# Mark nodelete to work around unload bug
if (LLVM_MAJOR_VERSION LESS_EQUAL 5)
  string(APPEND CMAKE_CXX_FLAGS " -Wl,-znodelete")
endif()

add_library(cfi MODULE
    hq-syscall.cpp
    cfi-instrument.cpp
    cfi-finalize.cpp
    cfi-init.cpp
    utils.cpp
)

# Force shared link
llvm_config(cfi USE_SHARED analysis core demangle passes support)
#llvm_map_components_to_libnames(llvm_libs analysis core demangle passes support)
#target_link_libraries(cfi ${LLVM})
