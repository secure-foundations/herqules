#include <fcntl.h>
#include <sys/resource.h>
#include <sys/stat.h>

#include "posix_mq.h"

namespace HQ::POSIX_MQ {

bool RX::open() {
    // Up to /proc/sys/fs/mqueue/msg_max
    constexpr struct mq_attr attrs = {.mq_flags = 0,
                                      .mq_maxmsg = BUFFER_SIZE,
                                      .mq_msgsize = sizeof(struct hq_msg)};

    // Increase byte limit for kernel message queue implementation
    constexpr struct rlimit rlim = {.rlim_cur = RLIM_INFINITY,
                                    .rlim_max = RLIM_INFINITY};
    setrlimit(RLIMIT_MSGQUEUE, &rlim);

    // Set and then restore previous umask
    mode_t old = umask(0);
    queue = mq_open(QUEUE_NAME,
                    O_CLOEXEC | O_CREAT | O_RDONLY | O_EXCL | O_NONBLOCK,
                    S_IRUSR | S_IRGRP | S_IWUSR | S_IWOTH, &attrs);
    umask(old);

    return *this;
}

RX::const_iterator RX::get_msgs() {
    size_t i = 0;

#ifndef NDEBUG
    if (__builtin_expect(!*this, 0))
        return nullptr;
#endif /* !NDEBUG */

    while (i < msgs.size()) {
        ssize_t ret = mq_receive(queue, reinterpret_cast<char *>(&msgs[i]),
                                 sizeof(msgs[i]), nullptr);
        if (__builtin_expect(ret != sizeof(msgs[i]), 0))
            break;

        ++i;
    }

    return &msgs[i];
}

std::ostream &operator<<(std::ostream &os, const RX &rx) {
    return os << "POSIX_MQ::RX = Queue: " << rx.queue;
}

} // namespace HQ::POSIX_MQ
