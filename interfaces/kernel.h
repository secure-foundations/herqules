#ifndef _HQ_INTERFACES_KERNEL_H_
#define _HQ_INTERFACES_KERNEL_H_

#include <array>

#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/user.h>
#include <unistd.h>

#include "compat.h"
#include "config.h"
#include "messages-verifier.h"
#include "messages.h"
#include "syscalls.h"

namespace HQ::KERNEL {

class Verifier {
    static constexpr size_t BUFFER_SIZE =
        HQ_INTERFACE_KERNEL_SIZE / sizeof(struct hq_verifier_msg);
    static constexpr char DEVICE_NAME[] = "/dev/hq-verifier-0";

    int fd = -1;
    struct hq_verifier_notify *notify = nullptr;
    std::array<struct hq_verifier_msg, BUFFER_SIZE> msgs;

  public:
    using const_iterator = decltype(msgs)::const_iterator;

    Verifier() = default;

    Verifier(const Verifier &other) = delete;

    Verifier(Verifier &&old) { *this = std::move(old); }

    Verifier &operator=(Verifier &&old) {
        if (this != &old) {
            if (*this)
                close(fd);

            fd = old.fd;
            notify = old.notify;
            old.fd = -1;
            old.notify = nullptr;
        }

        return *this;
    }

    ~Verifier() {
        if (*this)
            close(fd);

        if (notify) {
            unmap(notify, NOTIFY_MAP_SIZE);
            notify = nullptr;
        }
    }

    bool open() {
        static_assert(sizeof(struct hq_verifier_msg) == 32,
                      "Messages from kernel must be fixed size!");

        fd = ::open(DEVICE_NAME, O_CLOEXEC | O_SYNC | O_RDWR);
        return *this;
    }

    bool kill(pid_t pid) {
        return ioctl(fd, IOCTL_KILL_TGID, pid) == 0;
    }

    void *map(size_t sz) {
        if (!*this)
            return nullptr;

        void *map = mmap(nullptr, sz, PROT_WRITE,
                   MAP_SHARED_VALIDATE | MAP_POPULATE, fd, 0);
        return map != MAP_FAILED ? map : nullptr;
    }

    static void unmap(void *map, size_t sz) { munmap(map, sz); }

    const_iterator begin() { return msgs.begin(); }

    const_iterator get_msgs() {
        constexpr size_t max = BUFFER_SIZE * sizeof(msgs[0]);
        size_t readn = 0;

#ifndef NDEBUG
        if (__builtin_expect(!*this, 0))
            return nullptr;
#endif /* !NDEBUG */

        uint8_t *buf = reinterpret_cast<uint8_t *>(msgs.data());
        do {
            ssize_t next = read(fd, buf, max - readn);
            if (__builtin_expect(next < 0, 0))
                return nullptr;
            buf += static_cast<size_t>(next);
            readn += static_cast<size_t>(next);
        } while (readn < max && readn % sizeof(msgs[0]));

        return &msgs[readn / sizeof(msgs[0])];
    }

    bool get_pending() const {
        // Initial message provides the notify page
        if (__builtin_expect(!notify, 0))
            return true;

        return notify->rd_counter != notify->wr_counter;
    }

    void set_complete(size_t sz) {
        size_t buf = sz;
        write(fd, &buf, sizeof(buf));
    }

    bool set_notify(struct hq_verifier_notify *ptr) {
        if (notify)
            return false;

        notify = ptr;
        return true;
    }

    operator bool() const { return fd > 0; }
};

} // namespace HQ::KERNEL

#endif /* _HQ_INTERFACES_KERNEL_H_ */
