#ifndef _HQ_VERIFIER_PROCESS_H_
#define _HQ_VERIFIER_PROCESS_H_

#include <array>
#include <atomic>
#include <ostream>
#include <string>

#include <sys/mman.h>
#include <sys/user.h>

#include "absl/container/btree_map.h"

#include "config.h"
#include "interfaces-verifier.h"
#include "messages-verifier.h"
#include "messages.h"
#include "stats.h"

namespace HQ {
std::ostream &operator<<(std::ostream &os, const volatile hq_msg &msg);

class Process {
    std::string name;
    absl::btree_map<uintptr_t, uintptr_t> entries;

    std::array<std::atomic<unsigned int>, HQ_NUM_STATS> stats = {
        ATOMIC_VAR_INIT(0)};

    struct hq_syscall *syscall = nullptr;
#ifdef HQ_PRESERVE_STATS
    bool dead = false;
#endif /* HQ_PRESERVE_STATS */

  public:
    Process(std::string &&s) : name(s) {}

    ~Process() { cleanup(); }

    Process(const Process &other) : name(other.name), entries(other.entries) {}

    Process(Process &&old) { *this = std::move(old); }

    Process &operator=(Process &&old) {
        if (this != &old) {
            name = std::move(old.name);
            entries = std::move(old.entries);
            for (unsigned i = 0; i < old.stats.size(); ++i)
                stats[i] = old.stats[i].load();
            syscall = old.syscall;
#ifdef HQ_PRESERVE_STATS
            dead = old.dead;
#endif /* HQ_PRESERVE_STATS */

            old.syscall = nullptr;
        }

        return *this;
    }

    void cleanup() {
        if (syscall) {
            verifier_interface::unmap(syscall);
            syscall = nullptr;
        }

#ifdef HQ_PRESERVE_STATS
        clear_entries();
        set_dead();
#endif /* HQ_PRESERVE_STATS */
    }

#ifdef HQ_PRESERVE_STATS
    bool is_dead() const { return dead; }
    void set_dead() { dead = true; }
#endif /* HQ_PRESERVE_STATS */

    void clear_entries() { entries.clear(); }
    bool parse_msg(const pid_t pid, const volatile struct hq_msg &);

    struct hq_syscall *get_syscall() const {
        return syscall;
    }
    void set_syscall(struct hq_syscall *s) { syscall = s; }

    const std::string get_name() const { return name; }
    unsigned get_stat(enum hq_stats stat) const { return stats.at(stat); }

    friend std::ostream &operator<<(std::ostream &,
                                    const std::pair<const pid_t, Process> &);
};

} // namespace HQ

#endif /* _HQ_VERIFIER_PROCESS_H_ */
