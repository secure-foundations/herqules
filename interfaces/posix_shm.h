#ifndef _HQ_INTERFACES_POSIX_SHM_H_
#define _HQ_INTERFACES_POSIX_SHM_H_

#include <array>
#include <cassert>
#include <cstdint>
#include <iterator>
#include <ostream>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "compat.h"
#include "config.h"
#include "messages.h"
#include "syscalls.h"

// Reads will not block, and writes will block if underlying buffer is full
namespace HQ::POSIX_SHM {

// Must ensure final data structure is multiple of hugepage size
static constexpr size_t BUFFER_SIZE =
    ((HQ_INTERFACE_APPLICATION_SIZE - CACHELINE_BYTES) / sizeof(struct hq_msg));

struct ring_buffer {
    struct alignas(CACHELINE_BYTES) {
#ifdef HQ_INTERFACE_UNSAFE_PID_CONCURRENT
        bool lock;
#endif /* HQ_INTERFACE_UNSAFE_PID_CONCURRENT */
        size_t read, write;
    };
    struct hq_msg msgs[BUFFER_SIZE];
};

static constexpr unsigned get_hugetlb_flags(size_t sz) {
    if (!(sz % 1073741824))
        return MAP_HUGETLB | MAP_HUGE_1GB;
    else if (!(sz % 2097152))
        return MAP_HUGETLB | MAP_HUGE_2MB;
    return 0;
}

static constexpr const char *get_shm_path(size_t sz) {
    const auto flags = get_hugetlb_flags(sz);
    if ((flags & MAP_HUGE_1GB) == MAP_HUGE_1GB)
        return "/mnt/huge_1GB/HQ";
    else if ((flags & MAP_HUGE_2MB) == MAP_HUGE_2MB)
        return "/mnt/huge_2MB/HQ";
    return "/dev/shm/HQ";
}

static constexpr const char *SHM_PATH =
    get_shm_path(sizeof(struct ring_buffer));

class RX {
    volatile struct ring_buffer *map = nullptr;

  public:
    // Must use custom iterator for circular buffer and subfield access
    template <typename T, size_t SZ> class iterator {
      public:
        using difference_type = std::ptrdiff_t;
        using pointer = T *;
        using reference = T &;
        using value_type = T;
        using iterator_category = std::forward_iterator_tag;

        iterator(std::nullptr_t) : base(nullptr), read(nullptr) {}
        iterator(pointer _ptr, pointer _base, volatile size_t *_read)
            : ptr(_ptr), base(_base), read(_read) {}
        iterator(const iterator &other) = delete;
        iterator(iterator &&old) : base(old.base), read(old.read) {
            *this = std::move(old);
        }

        iterator &operator=(iterator &&old) {
            if (this != &old) {
                assert(base == old.base && sz == old.sz);

                ptr = old.ptr;
                old.ptr = nullptr;
            }

            return *this;
        }

        iterator &operator++() {
            if (__builtin_expect(++ptr >= base + SZ, 0))
                ptr -= SZ;

            __atomic_add_fetch(read, 1, __ATOMIC_ACQ_REL);
            return *this;
        }

        reference operator*() const { return *ptr; }
        pointer operator->() const { return ptr; }

        operator bool() const { return ptr; }
        bool operator==(const iterator &other) const {
            return ptr == other.ptr
#ifndef NDEBUG
                   && base == other.base && read == other.read && sz == other.sz
#endif /* NDEBUG */
                ;
        }
        bool operator!=(const iterator &other) const {
            return !(*this == other);
        }
        bool operator>(const iterator &other) const { return ptr > other.ptr; }
        bool operator<(const iterator &other) const { return ptr < other.ptr; }

      private:
        pointer ptr = nullptr;
        const pointer base;
        volatile size_t *const read = nullptr;
        const size_t sz = SZ;
    };

    using const_iterator = iterator<const volatile struct hq_msg, BUFFER_SIZE>;

    RX() = default;

    RX(const RX &other) = delete;

    RX(RX &&old) { *this = std::move(old); }

    RX &operator=(RX &&old) {
        if (this != &old) {
            if (*this)
                munmap(const_cast<struct ring_buffer *>(map), sizeof(*map));

            map = old.map;

            old.map = nullptr;
        }

        return *this;
    }

    ~RX() {
        if (*this) {
            munmap(const_cast<struct ring_buffer *>(map), sizeof(*map));
            unlink(SHM_PATH);
        }
    }

    bool open();
    const_iterator begin() {
        return const_iterator(
            &map->msgs[__atomic_load_n(&map->read, __ATOMIC_ACQUIRE) %
                       BUFFER_SIZE],
            map->msgs, &map->read);
    }
    const_iterator get_msgs();
    bool reset() { return false; }

    operator bool() const { return map && map != MAP_FAILED; }

    friend std::ostream &operator<<(std::ostream &os, const RX &rx);
};

class TX {
#if defined(HQ_INTERFACE_UNSAFE_PID) ||                                        \
    defined(HQ_INTERFACE_UNSAFE_PID_CONCURRENT)
    pid_t pid = -1;
#endif /* HQ_INTERFACE_UNSAFE_PID || HQ_INTERFACE_UNSAFE_PID_CONCURRENT */
    void *map = nullptr;

    // Must be hugepage aligned
    static constexpr uintptr_t MAP_ADDRESS = 0x80000000ULL;
#define MAP reinterpret_cast<volatile struct ring_buffer *>(MAP_ADDRESS)

  public:
    TX() = default;

    TX(const TX &other) = delete;

    TX(TX &&old) { *this = std::move(old); }

    TX &operator=(TX &&old) {
        if (this != &old) {
#if defined(HQ_INTERFACE_UNSAFE_PID) ||                                        \
    defined(HQ_INTERFACE_UNSAFE_PID_CONCURRENT)
            pid = old.pid;
#endif /* HQ_INTERFACE_UNSAFE_PID || HQ_INTERFACE_UNSAFE_PID_CONCURRENT */
            map = old.map;

            old.map = nullptr;
        }

        return *this;
    }

    ~TX() {
        if (*this)
            RAW_SYSCALL(2, SYS_munmap, MAP_ADDRESS, sizeof(*MAP));
    }

    bool open() {
        int fd = RAW_SYSCALL(3, SYS_open, reinterpret_cast<uintptr_t>(SHM_PATH),
                             O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0);
        if (fd <= 0)
            return false;

        map = reinterpret_cast<struct ring_buffer *>(RAW_SYSCALL(
            6, SYS_mmap, MAP_ADDRESS, sizeof(*MAP), PROT_READ | PROT_WRITE,
            MAP_FIXED | MAP_SHARED_VALIDATE | MAP_POPULATE |
                get_hugetlb_flags(sizeof(*MAP)),
            fd, 0));

        RAW_SYSCALL(1, SYS_close, fd);
        return *this;
    }

    inline bool send_msg2(const enum hq_msg_op op, const uintptr_t pointer,
                          const uintptr_t value) {
#ifndef NDEBUG
        if (__builtin_expect(!*this, 0))
            return false;
#endif /* !NDEBUG */

#ifdef HQ_INTERFACE_UNSAFE_PID_CONCURRENT
        // Spin while another thread is writing
        while (__atomic_test_and_set(&MAP->lock, __ATOMIC_ACQ_REL))
            ;
#endif /* HQ_INTERFACE_UNSAFE_PID_CONCURRENT */

        size_t write = __atomic_load_n(&MAP->write, __ATOMIC_ACQUIRE);
        // Spin while buffer is full
        while (write - __atomic_load_n(&MAP->read, __ATOMIC_ACQUIRE) ==
               BUFFER_SIZE)
            ;

#if defined(HQ_INTERFACE_UNSAFE_PID) ||                                        \
    defined(HQ_INTERFACE_UNSAFE_PID_CONCURRENT)
        MAP->msgs[write % BUFFER_SIZE].pid = pid;
#endif /* HQ_INTERFACE_UNSAFE_PID || HQ_INTERFACE_UNSAFE_PID_CONCURRENT */
        MAP->msgs[write % BUFFER_SIZE].op = op;
        MAP->msgs[write % BUFFER_SIZE].values[0] = pointer;
        MAP->msgs[write % BUFFER_SIZE].values[1] = value;

        __atomic_add_fetch(&MAP->write, 1, __ATOMIC_ACQ_REL);

#ifdef HQ_INTERFACE_UNSAFE_PID_CONCURRENT
        // Unlock for other writers
        __atomic_clear(&MAP->lock, __ATOMIC_RELEASE);
#endif /* HQ_INTERFACE_UNSAFE_PID_CONCURRENT */
        return true;
    }

    inline bool send_msg1(const enum hq_msg_op op, const uintptr_t value) {
        return send_msg2(op, 0, value);
    }

#if defined(HQ_INTERFACE_UNSAFE_PID) ||                                        \
    defined(HQ_INTERFACE_UNSAFE_PID_CONCURRENT)
    bool set_pid(pid_t p) {
        pid = p;
        return true;
    }
#endif /* HQ_INTERFACE_UNSAFE_PID || HQ_INTERFACE_UNSAFE_PID_CONCURRENT */

    operator bool() const { return map == MAP; }
};

} // namespace HQ::POSIX_SHM

#endif /* _HQ_INTERFACES_POSIX_SHM_H_ */
