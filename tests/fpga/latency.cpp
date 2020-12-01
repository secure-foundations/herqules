/********
 * Measuring FPGA latency
 ********/

#include <array>
#include <chrono>
#include <iostream>

#include <unistd.h>

#include "config.h"
#include "interfaces-rx.h"
#include "interfaces-tx.h"
#include "runtime.h"

rx_interface interface_rx;
tx_interface interface_tx;

int main(int argc, char **argv) {
    if (!interface_rx.open()) {
        std::cerr << "Failed to open RX interface!" << std::endl;
        return -1;
    }

    if (!interface_tx.open()) {
        std::cerr << "Failed to open TX interface!" << std::endl;
        return -1;
    }

    /* Read parameters */
    const unsigned iterations = (argc >= 2 ? std::atoi(argv[1]) : 1000);
    const unsigned interval = (argc >= 3 ? std::atoi(argv[2]) : 100);

    std::chrono::time_point<std::chrono::steady_clock> start, end;
    double diff;

    std::cout << "Message sends, iterations: " << iterations
              << ", interval: " << interval << std::endl;

    start = std::chrono::steady_clock::now();
    for (unsigned i = 0; i < iterations; ++i) {
        if (!(i % interval)) {
            /* Message sends */
            if (!interface_tx.send_msg1(HQ_MSG_INVALIDATE, 0)) {
                std::cerr << "Failed to send message!" << std::endl;
                return -1;
            }
        }
    }
    end = std::chrono::steady_clock::now();
    diff = std::chrono::duration<double, std::nano>(end - start).count();

    std::cout << "Duration: " << diff << ", Average: " << diff / iterations
              << " ns" << std::endl;

    /* Stats */
    std::cout << interface_rx << "\n";

    return 0;
}
