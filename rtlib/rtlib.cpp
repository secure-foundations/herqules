#include <algorithm>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <type_traits>

#include <elf.h>
#include <malloc.h>
#include <sys/auxv.h>
#include <unistd.h>

#include "config.h"
#include "interfaces-tx.h"
#include "syscalls.h"

#include "init.h"
#include "rtlib.h"

#ifdef __x86_64__
using Elf_Ehdr = Elf64_Ehdr;
#elif defined(__i386__)
using Elf_Ehdr = Elf32_Ehdr;
#else
#error "Unsupported architecture!"
#endif

extern tx_interface &interface;

/* Explicitly declare these external functions to be pure so that their call
 * sites can be optimized out, if applicable */
size_t malloc_usable_size(void *ptr) __attribute__((pure));

/* Function implementations */

extern "C" {

void POINTER_CHECK_FUNCTION(const void **pp, const void *p) {
#ifndef NDEBUG
    printf("Checking pointer %p with value %p...\n", pp, p);
#endif /* NDEBUG */

    if (!interface.send_msg2(CFI_MSG_CHECK,
                             reinterpret_cast<const uintptr_t>(pp),
                             reinterpret_cast<const uintptr_t>(p))) {
        constexpr static char err[] = "Error sending POINTER_CHECK!\n";
        RAW_SYSCALL(3, SYS_write, STDERR_FILENO,
                    reinterpret_cast<uintptr_t>(err), sizeof(err));
        RAW_SYSCALL(1, SYS_exit_group, -1);
    }
}

void POINTER_CHECK_INVALIDATE_FUNCTION(const void **pp, const void *p) {
#ifndef NDEBUG
    printf("Check-invalidating pointer %p with value %p...\n", pp, p);
#endif /* NDEBUG */

    if (!interface.send_msg2(CFI_MSG_CHECK_INVALIDATE,
                             reinterpret_cast<const uintptr_t>(pp),
                             reinterpret_cast<const uintptr_t>(p))) {
        constexpr static char err[] =
            "Error sending POINTER_CHECK_INVALIDATE!\n";
        RAW_SYSCALL(3, SYS_write, STDERR_FILENO,
                    reinterpret_cast<uintptr_t>(err), sizeof(err));
        RAW_SYSCALL(1, SYS_exit_group, -1);
    }
}

void CFI_POINTER_DEFINE_FUNCTION(const void **pp, const void *p) {
#ifndef NDEBUG
    printf("Defining pointer %p with value %p...\n", pp, p);
#endif /* NDEBUG */

    if (!interface.send_msg2(CFI_MSG_DEFINE,
                             reinterpret_cast<const uintptr_t>(pp),
                             reinterpret_cast<const uintptr_t>(p))) {
        constexpr static char err[] = "Error sending POINTER_DEFINE!\n";
        RAW_SYSCALL(3, SYS_write, STDERR_FILENO,
                    reinterpret_cast<uintptr_t>(err), sizeof(err));
        RAW_SYSCALL(1, SYS_exit_group, -1);
    }
}

void POINTER_INVALIDATE_FUNCTION(const void **pp) {
#ifndef NDEBUG
    printf("Invalidating pointer %p...\n", pp);
#endif /* NDEBUG */

    if (!interface.send_msg1(HQ_MSG_INVALIDATE,
                             reinterpret_cast<const uintptr_t>(pp))) {
        constexpr static char err[] = "Error sending POINTER_INVALIDATE!\n";
        RAW_SYSCALL(3, SYS_write, STDERR_FILENO,
                    reinterpret_cast<uintptr_t>(err), sizeof(err));
        RAW_SYSCALL(1, SYS_exit_group, -1);
    }
}

void POINTER_MEMCPY_FUNCTION(void *dst, const void *src, uint64_t sz) {
#ifndef NDEBUG
    printf("Copying pointer region %p to %p with size 0x%lx...\n", src, dst,
           sz);
#endif /* NDEBUG */

    assert(ADDRESS_FROM_EMBED(
               EMBED_ADDRESS_SIZE_HIGH(reinterpret_cast<uintptr_t>(dst), -1)) ==
               reinterpret_cast<uintptr_t>(dst) &&
           ADDRESS_FROM_EMBED(EMBED_ADDRESS_SIZE_LOW(
               reinterpret_cast<const uintptr_t>(src), -1)) ==
               reinterpret_cast<const uintptr_t>(src) &&
           SIZE_FROM_EMBED(EMBED_ADDRESS_SIZE_HIGH(-1, sz),
                           EMBED_ADDRESS_SIZE_LOW(-1, sz)) == sz);
    if (!interface.send_msg2(
            HQ_MSG_COPY_BLOCK,
            EMBED_ADDRESS_SIZE_HIGH(reinterpret_cast<uintptr_t>(dst), sz),
            EMBED_ADDRESS_SIZE_LOW(reinterpret_cast<const uintptr_t>(src),
                                   sz))) {
        constexpr static char err[] = "Error sending POINTER_BLOCK_MEMCOPY!\n";
        RAW_SYSCALL(3, SYS_write, STDERR_FILENO,
                    reinterpret_cast<uintptr_t>(err), sizeof(err));
        RAW_SYSCALL(1, SYS_exit_group, -1);
    }
}

void POINTER_MEMMOVE_FUNCTION(void *dst, const void *src, uint64_t sz) {
#ifndef NDEBUG
    printf("Copying pointer region %p to %p with size 0x%lx...\n", src, dst,
           sz);
#endif /* NDEBUG */

    assert(ADDRESS_FROM_EMBED(
               EMBED_ADDRESS_SIZE_HIGH(reinterpret_cast<uintptr_t>(dst), -1)) ==
               reinterpret_cast<uintptr_t>(dst) &&
           ADDRESS_FROM_EMBED(EMBED_ADDRESS_SIZE_LOW(
               reinterpret_cast<const uintptr_t>(src), -1)) ==
               reinterpret_cast<const uintptr_t>(src) &&
           SIZE_FROM_EMBED(EMBED_ADDRESS_SIZE_HIGH(-1, sz),
                           EMBED_ADDRESS_SIZE_LOW(-1, sz)) == sz);
    if (!interface.send_msg2(
            HQ_MSG_COPY_BLOCK,
            EMBED_ADDRESS_SIZE_HIGH(reinterpret_cast<uintptr_t>(dst), sz),
            EMBED_ADDRESS_SIZE_LOW(reinterpret_cast<const uintptr_t>(src),
                                   sz))) {
        constexpr static char err[] = "Error sending POINTER_BLOCK_MEMMOVE!\n";
        RAW_SYSCALL(3, SYS_write, STDERR_FILENO,
                    reinterpret_cast<uintptr_t>(err), sizeof(err));
        RAW_SYSCALL(1, SYS_exit_group, -1);
    }
}

void POINTER_FREE_FUNCTION(void *ptr) {
    const size_t sz = malloc_usable_size(ptr);
#ifndef NDEBUG
    printf("Freeing pointer %p with size 0x%lx...\n", ptr, sz);
#endif /* NDEBUG */
    free(ptr);

    if (!interface.send_msg2(HQ_MSG_INVALIDATE_BLOCK,
                             reinterpret_cast<uintptr_t>(ptr), sz)) {
        constexpr static char err[] =
            "Error sending POINTER_BLOCK_INVALIDATE!\n";
        RAW_SYSCALL(3, SYS_write, STDERR_FILENO,
                    reinterpret_cast<uintptr_t>(err), sizeof(err));
        RAW_SYSCALL(1, SYS_exit_group, -1);
    }
}

void *POINTER_REALLOC_FUNCTION(void *src, uint64_t new_sz) {
    const size_t old_sz = malloc_usable_size(src);
    void *dst = realloc(src, new_sz);
#ifndef NDEBUG
    printf("Moving pointer region %p to %p with sizes 0x%lx, 0x%lx...\n", src,
           dst, old_sz, new_sz);
#endif /* NDEBUG */

    // Simple or failed allocation
    if (!dst || !src)
        return dst;

    if (!new_sz || src == dst) {
        // Free the difference if the reallocation is in-place, or the entire
        // allocation if the requested size is zero
        uintptr_t base;
        size_t diff;
        if (!new_sz) {
            base = reinterpret_cast<uintptr_t>(src);
            diff = old_sz;
        } else if (old_sz > new_sz) {
            base = reinterpret_cast<uintptr_t>(dst) + new_sz;
            diff = old_sz - new_sz;
        } else if (old_sz < new_sz) {
            base = reinterpret_cast<uintptr_t>(dst) + old_sz;
            diff = new_sz - old_sz;
        } else
            return dst;

        if (!interface.send_msg2(HQ_MSG_INVALIDATE_BLOCK, base, diff)) {
            constexpr static char err[] =
                "Error sending POINTER_BLOCK_INVALIDATE!\n";
            RAW_SYSCALL(3, SYS_write, STDERR_FILENO,
                        reinterpret_cast<uintptr_t>(err), sizeof(err));
            RAW_SYSCALL(1, SYS_exit_group, -1);
        }
    } else {
        // Move the common length of the allocation
        const size_t sz = std::min(old_sz, new_sz);

        assert(ADDRESS_FROM_EMBED(EMBED_ADDRESS_SIZE_HIGH(
                   reinterpret_cast<uintptr_t>(dst), -1)) ==
                   reinterpret_cast<uintptr_t>(dst) &&
               ADDRESS_FROM_EMBED(EMBED_ADDRESS_SIZE_LOW(
                   reinterpret_cast<uintptr_t>(src), -1)) ==
                   reinterpret_cast<uintptr_t>(src) &&
               SIZE_FROM_EMBED(EMBED_ADDRESS_SIZE_HIGH(-1, sz),
                               EMBED_ADDRESS_SIZE_LOW(-1, sz)) == sz);

        if (!interface.send_msg2(
                HQ_MSG_MOVE_BLOCK,
                EMBED_ADDRESS_SIZE_HIGH(reinterpret_cast<uintptr_t>(dst), sz),
                EMBED_ADDRESS_SIZE_LOW(reinterpret_cast<uintptr_t>(src), sz))) {
            constexpr static char err[] = "Error sending POINTER_BLOCK_MOVE!\n";
            RAW_SYSCALL(3, SYS_write, STDERR_FILENO,
                        reinterpret_cast<uintptr_t>(err), sizeof(err));
            RAW_SYSCALL(1, SYS_exit_group, -1);
        }
    }

    return dst;
}

#if defined(HQ_INTERFACE_UNSAFE_PID) ||                                        \
    defined(HQ_INTERFACE_UNSAFE_PID_CONCURRENT)
void PID_SEND_FUNCTION() {
    pid_t __seg_gs *pid =
        reinterpret_cast<pid_t __seg_gs *>(offsetof(class gs_data, pid));
    if (!interface.set_pid(*pid)) {
        constexpr static char err[] = "Error setting pid!\n";
        RAW_SYSCALL(3, SYS_write, STDERR_FILENO,
                    reinterpret_cast<uintptr_t>(err), sizeof(err));
        RAW_SYSCALL(1, SYS_exit_group, -1);
    }
}
#endif /* HQ_INTERFACE_UNSAFE_PID || HQ_INTERFACE_UNSAFE_PID_CONCURRENT */

void SYSCALL_FUNCTION() {
    if (!interface.send_msg1(HQ_MSG_SYSCALL, 0)) {
        constexpr static char err[] = "Error sending SYSCALL!\n";
        RAW_SYSCALL(3, SYS_write, STDERR_FILENO,
                    reinterpret_cast<uintptr_t>(err), sizeof(err));
        RAW_SYSCALL(1, SYS_exit_group, -1);
    }
}

static inline __attribute__((always_inline)) void
init_globals_function(const hq_init_t *init_int, const size_t int_sz,
                      const hq_init_t *init_ext, const size_t ext_sz) {
#ifndef NDEBUG
    printf("Initializing global variables, internals from %p, size %ld, "
           "externals from %p, size %ld...\n",
           init_int, int_sz, init_ext, ext_sz);
#endif /* NDEBUG */

    if (int_sz >= HQ_GLOBALS_INTERNAL_THRESHOLD) {
        unsigned long base = getauxval(AT_PHDR);

        if (base && !interface.send_msg1(CFI_MSG_INIT_GLOBALS,
                                         base - sizeof(Elf_Ehdr))) {
            constexpr static char err[] = "Error sending GLOBAL_INIT!\n";
            RAW_SYSCALL(3, SYS_write, STDERR_FILENO,
                        reinterpret_cast<uintptr_t>(err), sizeof(err));
            RAW_SYSCALL(1, SYS_exit_group, -1);
        }
    } else {
        for (size_t i = 0; i < int_sz; ++i)
            CFI_POINTER_DEFINE_FUNCTION(
                reinterpret_cast<const void **>(init_int[i].ptr),
                reinterpret_cast<const void *>(init_int[i].val));
    }

    // TODO: External symbols are relocated relative to the base address of
    // their dynamic shared object. Having the verifier track each of these
    // and load them appropriately is more complicated, so just fall back to
    // initializing them at program startup.
    for (size_t i = 0; i < ext_sz; ++i) {
        CFI_POINTER_DEFINE_FUNCTION(
            reinterpret_cast<const void **>(init_ext[i].ptr),
            reinterpret_cast<const void *>(init_ext[i].val));
    }
}

void CFI_INIT_GLOBALS_FUNCTION(const hq_init_t *init_int, const size_t int_sz,
                               const hq_init_t *init_ext, const size_t ext_sz) {
    init_globals_function(init_int, int_sz, init_ext, ext_sz);
}
}
