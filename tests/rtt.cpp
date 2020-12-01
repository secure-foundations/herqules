/********
 * Tracking RTT using C++ interface
 ********/

#include <array>
#include <chrono>
#include <iostream>

#include <sys/prctl.h>
#include <unistd.h>

#include "config.h"
#include "interfaces-rx.h"
#include "interfaces-tx.h"
#include "messages.h"
#include "runtime.h"

rx_interface interface_rx;
tx_interface interface_tx;

int main(int argc, char **argv) {
#if INTERFACE_TYPE != INTERFACE_TYPE_PAGES &&                                  \
    INTERFACE_TYPE != INTERFACE_TYPE_ZERO
    if (!interface_rx.open()) {
        std::cerr << "Failed to open RX interface!" << std::endl;
        return -1;
    }
#endif /* INTERFACE_TYPE */

    if (!interface_tx.open()) {
        std::cerr << "Failed to open TX interface!" << std::endl;
        return -1;
    }

    /* Read parameters */
    const unsigned interval = (argc >= 3 ? std::atoi(argv[2]) : 1000);
    const unsigned iterations = (argc >= 2 ? std::atoi(argv[1]) : 10000);

    std::chrono::time_point<std::chrono::steady_clock> start, end;
    double diff;

#if INTERFACE_TYPE == INTERFACE_TYPE_NONE ||                                   \
    INTERFACE_TYPE == INTERFACE_TYPE_OPAE ||                                   \
    INTERFACE_TYPE == INTERFACE_TYPE_PAGES ||                                  \
    INTERFACE_TYPE == INTERFACE_TYPE_ZERO
    /* Register reads */
    start = std::chrono::steady_clock::now();
    for (size_t i = 0; i < iterations; ++i) {
        if (interface_rx.get_drops() == -1) {
            std::cerr << "Failed to read register!" << std::endl;
            return -1;
        }
    }
    end = std::chrono::steady_clock::now();
    diff = std::chrono::duration<double, std::nano>(end - start).count();

    std::cout << "Register read: iterations " << iterations << ", duration "
              << diff << ", average " << diff / iterations << " ns"
              << std::endl;
#endif /* INTERFACE_TYPE */

#if INTERFACE_TYPE == INTERFACE_TYPE_NONE ||                                   \
    INTERFACE_TYPE == INTERFACE_TYPE_OPAE ||                                   \
    INTERFACE_TYPE == INTERFACE_TYPE_PAGES ||                                  \
    INTERFACE_TYPE == INTERFACE_TYPE_ZERO
    /* Register writes */
    start = std::chrono::steady_clock::now();
    for (size_t i = 0; i < iterations; ++i) {
        if (!interface_tx.send_msg1(HQ_MSG_INVALIDATE, 0)) {
            std::cerr << "Failed to write register!" << std::endl;
            return -1;
        }
    }
    end = std::chrono::steady_clock::now();
    diff = std::chrono::duration<double, std::nano>(end - start).count();

    std::cout << "Register write: iterations " << iterations << ", duration "
              << diff << ", average " << diff / iterations << " ns"
              << std::endl;
#endif /* INTERFACE_TYPE */

    /* Message send */
    start = std::chrono::steady_clock::now();
    for (size_t i = 0; i < iterations; ++i) {
        if (!interface_tx.send_msg2(CFI_MSG_DEFINE, 0, 0)) {
            std::cerr << "Failed to send message!" << std::endl;
            return -1;
        }
    }
    end = std::chrono::steady_clock::now();
    diff = std::chrono::duration<double, std::nano>(end - start).count();

    std::cout << "Message send: iterations " << iterations << ", duration "
              << diff << ", average " << diff / iterations << " ns"
              << std::endl;

    /* Message receive */
    size_t sum = 0;
    start = std::chrono::steady_clock::now();
    while (sum < iterations) {
        auto it = interface_rx.begin(), it_end = interface_rx.get_msgs();
        if (!it_end) {
            std::cerr << "Failed to receive message!" << std::endl;
            return -1;
        }

        // Iterator may do work; cannot take difference
        while (it != it_end) {
            ++it;
            ++sum;
        }

#if INTERFACE_TYPE == INTERFACE_TYPE_POSIX_SHM
        // Needs the next call to update the shared read counter
        it_end = interface_rx.get_msgs();
#endif /* INTERFACE_TYPE == INTERFACE_TYPE_POSIX_SHM */
    }
    end = std::chrono::steady_clock::now();
    diff = std::chrono::duration<double, std::nano>(end - start).count();

    std::cout << "Message receive: iterations " << iterations << ", duration "
              << diff << ", average " << diff / iterations << " ns"
              << std::endl;

    /* Message send and receive */
    start = std::chrono::steady_clock::now();
    for (size_t i = 0; i < iterations; ++i) {
        if (!interface_tx.send_msg2(CFI_MSG_DEFINE, 0, 0)) {
            std::cerr << "Failed to send message!" << std::endl;
            return -1;
        }

        while (1) {
            auto it = interface_rx.begin(), it_end = interface_rx.get_msgs();
            if (!it_end) {
                std::cerr << "Failed to receive message!" << std::endl;
                return -1;
            }

            if (it != it_end) {
                ++it;
                break;
            }
        }
    }
    end = std::chrono::steady_clock::now();
    diff = std::chrono::duration<double, std::nano>(end - start).count();

    std::cout << "Message send and receive: iterations " << iterations
              << ", read interval " << interval << ", duration " << diff
              << ", average " << diff / iterations << " ns" << std::endl;

    /* Stats */
    std::cout << interface_rx << "\n";

    return 0;
}
