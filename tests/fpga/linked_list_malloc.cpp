//
// Copyright (c) 2017, Intel Corporation
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// Redistributions of source code must retain the above copyright notice, this
// list of conditions and the following disclaimer.
//
// Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// Neither the name of the Intel Corporation nor the names of its contributors
// may be used to endorse or promote products derived from this software
// without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

#include <atomic>
#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string>

#include <unistd.h>

using namespace std;

#include "config.h"
#include "csr_mgr.h"
#include "fpga.h"
#include "messages.h"
#include "opae_svc_wrapper.h"

using namespace opae::fpga::types;

#ifndef CL
#define CL(x) ((x)*64)
#endif
#ifndef MB
#define MB(x) ((x)*1024 * 1024)
#endif // MB
#define CEILING(x, y) (((x) + (y)-1) / (y))

void print(const volatile struct fpga_msg &msg) {
    cout << "Data in buffer: " << msg.msg.pid << " " << msg.msg.op << " "
         << msg.msg.values[0] << " " << msg.msg.values[1]
         << " offset: " << msg.offset << " counter: " << msg.counter
         << ", constant: " << msg.constant << endl;
}

inline void write_tagged(CSR_MGR &csrs, unsigned val0, unsigned val1, unsigned val2) {
    csrs.writeCSR64(REG_MSG1, val1);

    switch (val0) {
    case CFI_MSG_DEFINE:
        csrs.writeCSR64(REG_MSG2_DEFINE, val2);
        break;

    case CFI_MSG_CHECK:
        csrs.writeCSR64(REG_MSG2_CHECK, val2);
        break;

    case HQ_MSG_INVALIDATE:
        csrs.writeCSR64(REG_MSG2_INVALIDATE, val2);
        break;

    case HQ_MSG_COPY_BLOCK:
        csrs.writeCSR64(REG_MSG2_COPY_BLOCK, val2);
        break;

    case HQ_MSG_INVALIDATE_BLOCK:
        csrs.writeCSR64(REG_MSG2_INVALIDATE_BLOCK, val2);
        break;

    case HQ_MSG_MOVE_BLOCK:
        csrs.writeCSR64(REG_MSG2_MOVE_BLOCK, val2);
        break;

    case HQ_MSG_SYSCALL:
        csrs.writeCSR64(REG_MSG2_SYSCALL, val2);
        break;

    default:
        csrs.writeCSR64(REG_MSG0, val0);
        csrs.writeCSR64(REG_MSG2, val2);
        break;
    }
}

int main(int argc, char *argv[]) {
    // Find and connect to the accelerator
    OPAE_SVC_WRAPPER fpga(AFU_UUID_STRING);
    assert(fpga.isOk());

    // Connect the CSR manager
    CSR_MGR csrs(fpga);

    // Spin, waiting for the value in memory to change to something non-zero.
    struct timespec pause;
    // Longer when simulating
    pause.tv_sec = (fpga.hwIsSimulated() ? 1 : 0);
    pause.tv_nsec = 10000;

    auto buffer = fpga.allocBuffer(CL(4096));
    volatile struct fpga_msg *host_buf =
        reinterpret_cast<volatile struct fpga_msg *>(buffer->c_type());

    cout << "Send to buffer start!" << endl;

    size_t max = 8192;
    // unsigned max = 184;
    unsigned capacity = 4096;       // size of the host memory buffer
    unsigned check_interval = 1024; // must be < capacity
    uint64_t checksum = 0, compare = 0;
    // struct timespec mmio_delay;
    // mmio_delay.tv_sec = 0;
    // mmio_delay.tv_nsec = 1;

    csrs.writeCSR64(REG_PID, 0x1234);

    // Starter code for send to buffer server
    csrs.writeCSR64(REG_HOST_BUF_ADDR,
                  buffer->io_address() /
                      CL(1)); // Pointer to in-memory fifo buffer
    csrs.writeCSR64(REG_HOST_BUF_SZ, capacity); // Size of fifo buffer

    size_t head = 0;
    for (size_t i = 0; i < max; i++) {
        csrs.writeCSR64(REG_MSG0, i + 1);
        csrs.writeCSR64(REG_MSG1, i + 2);
        csrs.writeCSR64(REG_MSG2, i + 3);
        cout << "SW sent to FPGA: " << i << endl;
        // nanosleep(&mmio_delay, NULL);
        compare += i + 1;

        if (((i % check_interval) == 0) && (i > 0)) {
            while (host_buf[head % capacity].counter == head + 1) {
                print(host_buf[head % capacity]);
                checksum += host_buf[head % capacity].msg.op;
                ++head;
            }

            nanosleep(&pause, NULL);
        }
    }

    while (head < max) {
        if (host_buf[head % capacity].counter != head + 1) {
            nanosleep(&pause, NULL);
            continue;
        }

        print(host_buf[head % capacity]);
        checksum += host_buf[head % capacity].msg.op;
        ++head;
    }

    cout << "Drops: " << csrs.readCSR64(REG_MSG_DROPS) << endl;
    cout << "Result: checksum " << checksum << ", compare " << compare
         << (checksum == compare ? ", PASS" : ", FAIL") << endl;

    return 0;
}
