#include "sockets_unix.h"

namespace HQ::SOCKETS_UNIX {

bool RX::open() {
    fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (!*this)
        return false;

    unlink(SADDR.sun_path);
    if (bind(fd, reinterpret_cast<const struct sockaddr *>(&SADDR),
             sizeof(SADDR)) < 0)
        return false;

    return true;
}

RX::const_iterator RX::get_msgs() {
    size_t i = 0;

#ifndef NDEBUG
    if (__builtin_expect(!*this, 0))
        return nullptr;
#endif /* !NDEBUG */

    // Up to /proc/sys/net/unix/max_dgram_qlen
    while (i < msgs.size()) {
        ssize_t ret = recv(fd, &msgs[i], sizeof(msgs[i]), 0);
        if (__builtin_expect(ret != sizeof(msgs[i]), 0))
            break;

        ++i;
    }

    return &msgs[i];
}

std::ostream &operator<<(std::ostream &os, const RX &rx) {
    return os << "SOCKETS_UNIX::RX = FD " << rx.fd;
}

} // namespace HQ::SOCKETS_UNIX
