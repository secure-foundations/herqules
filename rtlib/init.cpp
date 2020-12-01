#include <cstdint>
#include <cstdlib>
#include <new>
#include <type_traits>

#include <immintrin.h>
#include <signal.h>
#include <unistd.h>

#include "config.h"
#include "interfaces-tx.h"
#include "runtime.h"
#include "syscalls.h"

#include "init.h"
#include "rtlib.h"

/* Internal variables */

// Use a statically allocated buffer with placement new to prevent destructor
// from automatically being called. Otherwise, internal libc cleanup functions
// will not be able to make system calls, because the interface will have been
// automatically destroyed.
static std::aligned_storage<sizeof(tx_interface), alignof(tx_interface)>::type
    buffer;
tx_interface &interface = *reinterpret_cast<tx_interface *>(&buffer);

#if defined(HQ_INTERFACE_UNSAFE_PID) ||                                        \
    defined(HQ_INTERFACE_UNSAFE_PID_CONCURRENT)
static gs_data global_gs;
#endif /* HQ_INTERFACE_UNSAFE_PID || HQ_INTERFACE_UNSAFE_PID_CONCURRENT */

/* Helper function implementations */
#ifdef HQ_INTERFACE_UNSAFE_BATCH
static constexpr int SIGNALS[] = {SIGABRT, SIGFPE,  SIGILL,
                                  SIGINT,  SIGSEGV, SIGTERM};
static struct sigaction old_handlers[NSIG];

static void signal_handler(int sig, siginfo_t *si, void *unused) {
    interface.flush();

    // Unregister and re-raise the signal handler
    sigaction(sig, &old_handlers[sig], nullptr);
    raise(sig);
}
#endif /* HQ_INTERFACE_UNSAFE_BATCH */

extern "C" {

/* Function implementations */
// These functions cannot be inlined because they are called directly by musl
// while loading the program, so put them here.

void PID_UPDATE_FUNCTION() {
#if defined(HQ_INTERFACE_UNSAFE_PID) ||                                        \
    defined(HQ_INTERFACE_UNSAFE_PID_CONCURRENT)
    global_gs.pid = RAW_SYSCALL(0, SYS_getpid);
    // Must whitelist this system call in the kernel, because it is also used by
    // the child after a clone/fork to retrieve its own PID
    PID_SEND_FUNCTION();
#endif /* HQ_INTERFACE_UNSAFE_PID || HQ_INTERFACE_UNSAFE_PID_CONCURRENT */
}

void INIT_FUNCTION() {
    // Skip duplicate initializations
    if (interface)
        return;

    // Initialize via placement new
    new (&buffer) tx_interface();
    if (!interface.open()) {
        constexpr static char err[] = "Error opening interface!\n";
        RAW_SYSCALL(3, SYS_write, STDERR_FILENO,
                    reinterpret_cast<uintptr_t>(err), sizeof(err));
        RAW_SYSCALL(1, SYS_exit_group, -1);
    }

#if defined(HQ_INTERFACE_UNSAFE_PID) ||                                        \
    defined(HQ_INTERFACE_UNSAFE_PID_CONCURRENT)
    void *gs = reinterpret_cast<void *>(global_gs.get_gs());
    if ((gs && gs != &global_gs) || !global_gs.set_gs()) {
        constexpr static char err[] = "Error setting GS segment!\n";
        RAW_SYSCALL(3, SYS_write, STDERR_FILENO,
                    reinterpret_cast<uintptr_t>(err), sizeof(err));
        RAW_SYSCALL(1, SYS_exit_group, -1);
    }
#endif /* HQ_INTERFACE_UNSAFE_PID || HQ_INTERFACE_UNSAFE_PID_CONCURRENT */

    // Enable HQ
    if (RAW_SYSCALL(5, SYS_prctl, PR_HQ, 1, 0, 0, 0)) {
        constexpr static char err[] = "Error enabling HQ!\n";
        RAW_SYSCALL(3, SYS_write, STDERR_FILENO,
                    reinterpret_cast<uintptr_t>(err), sizeof(err));
        RAW_SYSCALL(1, SYS_exit_group, -1);
    }

    // Normal library functions are now available since the interface is up

#if defined(HQ_INTERFACE_UNSAFE_PID) ||                                        \
    defined(HQ_INTERFACE_UNSAFE_PID_CONCURRENT)
    PID_UPDATE_FUNCTION();
#endif /* HQ_INTERFACE_UNSAFE_PID || HQ_INTERFACE_UNSAFE_PID_CONCURRENT */

    // Set a signal handler to flush batched messages
#ifdef HQ_INTERFACE_UNSAFE_BATCH
    struct sigaction sa;
    sa.sa_sigaction = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_SIGINFO;

    for (auto &s : SIGNALS) {
        if (sigaction(s, &sa, &old_handlers[s])) {
            constexpr static char err[] = "Error registering signal handler!\n";
            RAW_SYSCALL(3, SYS_write, STDERR_FILENO,
                        reinterpret_cast<uintptr_t>(err), sizeof(err));
            RAW_SYSCALL(1, SYS_exit_group, -1);
        }
    }
#endif /* HQ_INTERFACE_UNSAFE_BATCH */

    // Block on dummy syscall until verifier catches up
    getuid();
}
}
