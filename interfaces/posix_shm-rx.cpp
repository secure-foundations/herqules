#include <unistd.h>

#include "posix_shm.h"

namespace HQ::POSIX_SHM {

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
#ifndef NDEBUG
    if (__builtin_expect(!*this, 0))
        return nullptr;
#endif /* !NDEBUG */

    size_t read = __atomic_load_n(&map->read, __ATOMIC_ACQUIRE),
           next = __atomic_load_n(&map->write, __ATOMIC_ACQUIRE);
    return const_iterator(&map->msgs[(next - read) % BUFFER_SIZE], map->msgs,
                          &map->read);
}

std::ostream &operator<<(std::ostream &os, const RX &rx) {
    return os << "POSIX_SHM::RX = Map: "
              << static_cast<const void *>(
                     const_cast<struct ring_buffer *>(rx.map))
              << ", Read: " << __atomic_load_n(&rx.map->read, __ATOMIC_ACQUIRE)
              << ", Write: "
              << __atomic_load_n(&rx.map->write, __ATOMIC_ACQUIRE);
}

} // namespace HQ::POSIX_SHM
