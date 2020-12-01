#include <fcntl.h>
#include <sys/stat.h>

#include "posix_fifo.h"

namespace HQ::POSIX_FIFO {

bool RX::open() {
    // Set and then restore previous umask
    mode_t old = umask(0);
    int ret = mkfifo(FIFO_PATH, S_IRUSR | S_IWUSR | S_IWOTH);
    umask(old);

    if (ret == -1 && errno != EEXIST)
        return -1;

    // Open the FIFO read/write so that there is always at least one writer,
    // ensuring that reads will always block. Otherwise, attempting to read
    // after all writers have exited will return 0 (EOF).
    fd = ::open(FIFO_PATH, O_CLOEXEC | O_RDWR);
    if (!*this)
        return false;

    // Up to /proc/sys/fs/pipe-max-size
    return fcntl(fd, F_SETPIPE_SZ, BUFFER_SIZE * sizeof(msgs[0])) != -1;
}

RX::const_iterator RX::get_msgs() {
    constexpr size_t max = BUFFER_SIZE * sizeof(msgs[0]);

#ifndef NDEBUG
    if (__builtin_expect(!*this, 0))
        return nullptr;
#endif /* !NDEBUG */

    size_t rbytes = 0;
    uint8_t *buf = reinterpret_cast<uint8_t *>(msgs.data());
    do {
        ssize_t bytes = ::read(fd, buf, max - rbytes);
        if (__builtin_expect(bytes < 0, 0)) {
            // Reads on FIFO are blocking, ignore interruptions by signals
            if (errno != EINTR)
                return nullptr;
            break;
        }

        buf += static_cast<size_t>(bytes);
        rbytes += static_cast<size_t>(bytes);
    } while (rbytes < max && rbytes % sizeof(msgs[0]));

    read = rbytes / sizeof(msgs[0]);
    return &msgs[read];
}

std::ostream &operator<<(std::ostream &os, const RX &rx) {
    return os << "POSIX_FIFO::RX = FD: " << rx.fd << ", Read: " << rx.read;
}

} // namespace HQ::POSIX_FIFO
