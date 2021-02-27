#include <csignal>
#include <iostream>
#include <signal.h>

#include "interfaces-rx.h"
#include "interfaces-verifier.h"
#include "messages.h"
#include "verifier.h"

static volatile sig_atomic_t execute = true;

static void interrupt_handler(int sig, siginfo_t *info, void *ucontext) {
    if (sig == SIGINT)
        execute = false;
}

verifier_interface int_verify;
rx_interface int_app;

int main(int argc, char **argv) {
    // Create the verifier
    if (!int_verify.open()) {
        std::cerr << "Error opening verifier interface!" << std::endl;
        return -1;
    }

    // Create the int_app interface
    if (!int_app.open()) {
        std::cerr << "Error opening application interface!" << std::endl;
        return -1;
    }

    HQ::Verifier<verifier_interface, rx_interface> verifier(int_verify,
                                                            int_app);
    // Check verifier can kill
    if (!verifier.can_kill()) {
        std::cerr << "Error checking for capability CAP_KILL!" << std::endl;
        return -1;
    }

    // Register signal handler
    struct sigaction sa;
    sa.sa_sigaction = interrupt_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_SIGINFO;
    if (sigaction(SIGINT, &sa, nullptr) == -1) {
        std::cerr << "Error registering signal handler!" << std::endl;
        return -1;
    }

    std::cout << "Awaiting messages..." << std::endl;

    // Read and loop on messages
    while (execute) {
        // Parse verifier message(s) if available
        if (!verifier.get_verifier_msgs(int_verify))
            return -1;

        auto app_end = int_app.get_msgs();
        while (!app_end) {
            std::cerr << "Error receiving application messages, resetting!"
                      << std::endl;

            verifier.kill_all();
            if (!int_app.reset())
                return -1;

            app_end = int_app.get_msgs();
        }

        auto app_begin = int_app.begin();
        if (!verifier.parse_app_msgs(app_begin, app_end)) {
            std::cerr << "Error parsing application messages!" << std::endl;
            return -1;
        }
    }

    // Kill all remaining processes
    verifier.kill_all();

    // Print stats before exit
    decltype(verifier)::const_iterator it, end;
    std::tie(it, end) = verifier.get_processes();
    verifier.print_header(std::cout);
    while (it != end)
        std::cout << *it++;
    std::cout << int_app << std::endl;

    return 0;
}
