
cmake_minimum_required(VERSION 3.12)

file(GLOB sources CONFIGURE_DEPENDS "*")

option(BUILD_FPGA_BITSTREAM "Build bitstream for FPGA. Requires Intel PAC SDK.")
option(BUILD_FPGA_SIMULATION "Build simulation for FPGA. Requires Intel PAC SDK and Synopsys VCS-MX.")
set(INTEL_PAC_SDK "/opt/inteldevstack" CACHE PATH "Filesystem location of Intel PAC Acceleration Stack for Development.")

message(STATUS "Using Intel PAC SDK: ${INTEL_PAC_SDK}")
message(STATUS "Build FPGA bitstream: ${BUILD_FPGA_BITSTREAM}")
message(STATUS "Build FPGA simulation: ${BUILD_FPGA_SIMULATION}")

if (BUILD_FPGA_BITSTREAM)
    # generate the build_dir/fpga/bitstream directory
    add_custom_command(OUTPUT bitstream
        COMMAND bash -c '. ${INTEL_PAC_SDK}/init_env.sh && afu_synth_setup --source ${CMAKE_CURRENT_SOURCE_DIR}/sources.txt ${CMAKE_CURRENT_BINARY_DIR}/bitstream'
        )

    # synthesize the bitstream inside build_dir/fpga/bitstream
    add_custom_command(OUTPUT bitstream/hq_fifo.gbs
        COMMAND bash -c '. ${INTEL_PAC_SDK}/init_env.sh && run.sh'
        DEPENDS ${sources}
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/bitstream
        )

    add_custom_target(fpga_bitstream ALL DEPENDS bitstream bitstream/hq_fifo.gbs)
endif()

if (BUILD_FPGA_SIMULATION)
    # generate the build_dir/fpga/simulation directory
    add_custom_command(OUTPUT simulation
        COMMAND bash -c '. ${INTEL_PAC_SDK}/init_env.sh && afu_sim_setup -t VCS --source ${CMAKE_CURRENT_SOURCE_DIR}/sources.txt ${CMAKE_CURRENT_BINARY_DIR}/simulation'
        )

    add_custom_command(OUTPUT simulation/csrc/Makefile
        COMMAND bash -c '. ${INTEL_PAC_SDK}/init_env.sh && make || true'
        DEPENDS ${sources}
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/simulation
    )

    # workaround for linking bug in vcs-mx with gcc > 4.8:
    # vcs_save_restore_new.o: relocation R_X86_64_32S against symbol `_sigintr' can not be used when making a PIE object; recompile with -fPIE
    add_custom_command(OUTPUT simulation/work/ase_simv
        COMMAND bash -c '. ${INTEL_PAC_SDK}/init_env.sh && sed -i \"s/^PICLDFLAGS=/&-no-pie /\" Makefile && make product'
        DEPENDS ${sources}
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/simulation/csrc
        )

    add_custom_target(fpga_simulation ALL DEPENDS simulation simulation/csrc/Makefile simulation/work/ase_simv)
endif()
