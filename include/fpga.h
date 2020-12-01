#ifndef _HQ_FPGA_H_
#define _HQ_FPGA_H_

#include <linux/version.h>

// Either use the upstream kernel driver (dfl-afu, etc) or the old Intel driver
// from the opae-intel-fpga-driver package (intel-fpga-afu, etc)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
#define FPGA_PATH "/dev/dfl-port.0"
#else
#define FPGA_PATH "/dev/intel-fpga-port.0"
#endif /* LINUX_VERSION_CODE */

#include "config.h"
#include "messages.h"

// Must keep in sync with 'hq_fifo.json'
#define AFU_UUID                                                               \
    0xcf, 0xba, 0x55, 0x11, 0x28, 0xba, 0x46, 0x2a, 0xb9, 0xac, 0x7c, 0xd2,    \
        0x36, 0x14, 0x99, 0x9f
#define AFU_UUID_STRING "cfba5511-28ba-462a-b9ac-7cd23614999f"

/* 32-bit address space */
// Mandatory OPAE registers
#define REG_DEV_FEATURE_HDR 4 * 0x00
#define REG_AFU_ID_L 4 * 0x02
#define REG_AFU_ID_H 4 * 0x04
#define REG_DFH_RSVD0 4 * 0x06
#define REG_DFH_RSVD1 4 * 0x08

// Must keep in sync with 'hq_fifo_csr.vh'
#define REG_MSG_DROPS 4 * 0x0A

#define REG_HOST_BUF_ADDR 4 * 0x10
#define REG_HOST_BUF_SZ 4 * 0x12

#define REG_MSG0 4 * 0x20
#define REG_MSG1 4 * 0x22
#define REG_MSG2 4 * 0x24

// Cacheline-aligned alias for REG_MSG1
#define REG_MSG1_ALIGN 4 * 0x40
#define REG_MSG2_DEFINE 4 * 0x48
#define REG_MSG2_CHECK 4 * 0x50
#define REG_MSG2_CHECK_INVALIDATE 4 * 0x58
#define REG_MSG2_COPY_BLOCK 4 * 0x60
#define REG_MSG2_INVALIDATE_BLOCK 4 * 0x68
#define REG_MSG2_MOVE_BLOCK 4 * 0x70

#define REG_MSG2_SYSCALL 4 * 0x80
#define REG_MSG2_INIT_GLOBALS 4 * 0x88
#define REG_MSG2_INVALIDATE 4 * 0x90

// Page-aligned to allow kernel memory protection
#define REG_PID 4 * 0x400

#define FPGA_MSG_CONSTANT 0xfeedface

// Must keep in sync with driver
#define FPGA_MMIO_SIZE 0x40000

// Must keep in sync with 'hq_fifo.sv'
struct fpga_msg {
    struct hq_msg msg;
    uint64_t zero;
    uint64_t offset;
    uint64_t counter;
    uint64_t constant;
} __attribute__((__aligned__(64)));

#endif /* _HQ_FPGA_H_ */
