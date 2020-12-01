#include <unistd.h>

#include "model.h"

namespace HQ::MODEL {

bool RX::open() {
    // Set and then restore previous umask
    mode_t old = umask(0);
    int fd = ::open(SHM_PATH, O_CREAT | O_RDWR | O_TRUNC,
                    S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
    umask(old);

    if (fd <= 0)
        return false;

    if (ftruncate(fd, sizeof(*map)))
        goto out;

    if ((map = reinterpret_cast<struct ring_buffer *>(
             mmap(NULL, sizeof(*map), PROT_READ | PROT_WRITE,
                  MAP_SHARED_VALIDATE | MAP_POPULATE |
                      get_hugetlb_flags(sizeof(*map)),
                  fd, 0))))
        goto out;

out:
    close(fd);
    if (!*this && fd > 0)
        unlink(SHM_PATH);
    return *this;
}

RX::const_iterator RX::get_msgs() {
    size_t offset;

#ifndef NDEBUG
    if (__builtin_expect(!*this, 0))
        return nullptr;
#endif /* !NDEBUG */

    if (__builtin_expect(read == BUFFER_SIZE, 0))
        reset();

#ifdef HQ_INTERFACE_FUTEX
    const struct timespec timeout { .tv_sec = HQ_INTERFACE_FUTEX };
    if (RAW_SYSCALL(
            6, SYS_futex,
            reinterpret_cast<uintptr_t>(const_cast<size_t *>(&map->write)),
            FUTEX_WAIT, static_cast<uint32_t>(read),
            reinterpret_cast<const uintptr_t>(&timeout), 0, 0) == -ETIMEDOUT) {
        offset = read;
        goto done;
    }
#endif /* HQ_INTERFACE_FUTEX */

#ifdef HQ_INTERFACE_UNSAFE_PID_CONCURRENT
    offset = __atomic_load_n(&map->write, __ATOMIC_ACQUIRE);
#else
    offset = map->write;
#endif /* HQ_INTERFACE_UNSAFE_PID_CONCURRENT */

#ifdef HQ_INTERFACE_FUTEX
done:
#endif /* HQ_INTERFACE_FUTEX */
    return const_iterator(&map->msgs[offset], map->msgs, &read);
}

std::ostream &operator<<(std::ostream &os, const RX &rx) {
    return os << "MODEL::RX = Map: "
              << static_cast<const void *>(
                     const_cast<struct ring_buffer *>(rx.map))
              << ", Read: " << rx.read;
}

} // namespace HQ::MODEL
