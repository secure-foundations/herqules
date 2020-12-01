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

/********
 * Trying to induce fill/message drop in the fpga.
 ********/

#include <assert.h>
#include <malloc.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <iostream>
#include <string>
#include <thread>

using namespace std;

#include "csr_mgr.h"
#include "fpga.h"
#include "opae_svc_wrapper.h"

using namespace opae::fpga::types;

#ifndef CL
#define CL(x) ((x)*64)
#endif
#ifndef MB
#define MB(x) ((x)*1024 * 1024)
#endif // MB
#define CEILING(x, y) (((x) + (y)-1) / (y))

void foo(CSR_MGR *csrs, unsigned start, unsigned last) {}

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
    pause.tv_nsec = 3500000;

    auto buffer = fpga.allocBuffer(CL(4096));
    volatile struct fpga_msg *host_buf =
        reinterpret_cast<volatile struct fpga_msg *>(buffer->c_type());

    cout << "Send to buffer start!" << endl;

    // unsigned max = 184000;
    unsigned capacity = 4096; // size of the host memory buffer
    // unsigned check_interval = 1024; // must be < capacity
    // uint64_t checksum = 0, compare = 0;
    // struct timespec mmio_delay;
    // mmio_delay.tv_sec = 0;
    // mmio_delay.tv_nsec = 1;

    // Starter code for send to buffer server
    csrs.writeCSR64(REG_HOST_BUF_ADDR,
                  buffer->io_address() /
                      CL(1)); // Pointer to in-memory fifo buffer
    csrs.writeCSR64(REG_HOST_BUF_SZ, capacity); // Size of fifo buffer

    nanosleep(&pause, NULL);
    unsigned last = atoi(argv[1]);
    // unsigned num = atoi(argv[2]);
    for (size_t j = 1; j <= last; j++) {
        csrs.writeCSR64(REG_MSG0, j);
        csrs.writeCSR64(REG_MSG1, j + 1);
        csrs.writeCSR64(REG_MSG2, j + 2);
    }

    nanosleep(&pause, NULL);
    nanosleep(&pause, NULL);
    nanosleep(&pause, NULL);
    nanosleep(&pause, NULL);
    nanosleep(&pause, NULL);
    nanosleep(&pause, NULL);
    nanosleep(&pause, NULL);
    nanosleep(&pause, NULL);
    nanosleep(&pause, NULL);
    for (size_t i = 0; i < 1; i++) {
        cout << "Head " << i;
        cout << "Data in buffer: " << host_buf[i].msg.op << " "
             << host_buf[i].msg.values[0] << " " << host_buf[i].msg.values[1]
             << " ";
        cout << "Offset: " << host_buf[i].offset << " ";
        cout << "Counter: " << host_buf[i].counter << " ";
        cout << "REG_MSG_DROPS: " << csrs.readCSR64(REG_MSG_DROPS) << endl;
    }

    return 0;
}
