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
 * Testing RTT of direct writes to FPGA.
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

    // size_t max = 184000;
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
    size_t head = 0;

    nanosleep(&pause, NULL);
    double avg = 0.0;
    double trimmed = 0.0;
    unsigned trimmed_count = 0;
    for (size_t j = 1; j < 1001; j++) {
        auto start = chrono::steady_clock::now();
        csrs.writeCSR64(REG_MSG0, j);
        csrs.writeCSR64(REG_MSG1, j + 1);
        csrs.writeCSR64(REG_MSG2, j + 2);

        for (size_t i = 0;; i++) {
            while (host_buf[head % capacity].counter != head + 1) {
            }

            if (host_buf[head % capacity].msg.op == j) {
                auto end = chrono::steady_clock::now();
                auto diff = end - start;
                auto d = chrono::duration<double, nano>(diff).count();
                cout << i << ": Chrono " << d << " ns" << endl;
                avg += d;
                if (d < 10000.0) {
                    trimmed += d;
                    trimmed_count++;
                }
                cout << "Head " << head;
                cout << "Data in buffer: " << host_buf[head % capacity].msg.op
                     << " " << host_buf[head % capacity].msg.values[0] << " "
                     << host_buf[head % capacity].msg.values[1] << " ";
                cout << "Offset: " << host_buf[head % capacity].offset << " ";
                cout << "Counter: " << host_buf[head % capacity].counter << " ";
                cout << "REG_MSG_DROPS: " << csrs.readCSR64(REG_MSG_DROPS)
                     << endl;
                head++;
                break;
            }
        }
    }
    avg /= 1000;
    trimmed /= trimmed_count;
    cout << "Avg: " << avg << endl;
    cout << "Trimmed: " << trimmed << endl;

    return 0;
}
