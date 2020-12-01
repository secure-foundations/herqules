#ifndef _HQ_VERIFIER_H_
#define _HQ_VERIFIER_H_

#include <cassert>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <type_traits>

#include <sys/capability.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/user.h>

#include "absl/container/node_hash_map.h"

#include "config.h"
#include "messages-verifier.h"
#include "messages.h"
#include "stats.h"

#include "process.h"

#if !defined(HQ_INTERFACE_UNSAFE_PID) &&                                       \
    !defined(HQ_INTERFACE_UNSAFE_PID_CONCURRENT) &&                            \
    INTERFACE_TYPE != INTERFACE_TYPE_OPAE
#warning "Assuming previous PID for unsafe interface, may be racy!"
#define HQ_INTERFACE_UNSAFE_PID
#endif /* !HQ_INTERFACE_UNSAFE_PID && !HQ_INTERFACE_UNSAFE_PID_CONCURRENT &&   \
          INTERFACE_TYPE != OPAE */

namespace HQ {

template <typename T> struct HasIsValid {
    typedef char yes[1];
    typedef char no[2];

    template <typename C> static yes &test(decltype(&C::is_valid));
    template <typename C> static no &test(...);

  public:
    enum { value = sizeof(test<T>(0)) == sizeof(yes) };
};

template <typename V, typename RX> class Verifier {
    V &kernel;
    RX &application;
    absl::node_hash_map<pid_t, Process> processes;

    // Cache the previous process to avoid lookup overhead
    typename decltype(processes)::iterator previous = processes.end();

  public:
    using iterator = typename decltype(processes)::iterator;
    using const_iterator = typename decltype(processes)::const_iterator;
    using pair_const_iterator = std::pair<const_iterator, const_iterator>;

    Verifier(V &k, RX &rx) : kernel(k), application(rx) {}

    pair_const_iterator get_processes() const {
        return std::make_pair(processes.begin(), processes.end());
    }

    void kill_all() {
        for (auto it = processes.begin(), ie = processes.end(); it != ie;
             ++it) {
#ifdef HQ_PRESERVE_STATS
            if (it->second.is_dead())
                continue;
#endif /* HQ_PRESERVE_STATS */

            kill_process(it);
        }
    }

    bool parse_app_msgs(typename RX::const_iterator &begin,
                        const typename RX::const_iterator &end) {
        // Process application messages unless there are pending kernel
        // message(s)
        while (begin != end) {
            // Invalidate iterator if next message is not valid
            if constexpr (HasIsValid<typename RX::const_iterator>::value) {
                if (!begin.is_valid())
                    break;
            }

#ifdef HQ_INTERFACE_UNSAFE_PID
            // FIXME: Messages may not be read until after the process has died.
            // When HQ_PRESERVE_STATS is set, dead processes are not
            // immediately erased and this is fine, because the will be read and
            // ignored. But if not set, they won't be read until a new process
            // connects, which results in incorrect behavior.
            if (previous == processes.end())
                break;
#else
            const pid_t pid = begin->pid;
            assert(pid != 0);

            if (previous == processes.end() || previous->first != begin->pid) {
                previous = processes.find(pid);
                if (previous == processes.end()) {
                    std::cout << "PID: " << std::dec << pid << " Unrecognized!"
                              << std::endl;
                    return false;
                }
            }
#endif /* HQ_INTERFACE_UNSAFE_PID */

            // Dispatch the message for processing
#ifndef NDEBUG
            std::cout << "PID: " << std::dec << previous->first << ", message "
                      << *begin << std::endl;
#endif /* NDEBUG */
            if (!previous->second.parse_msg(previous->first, *begin)) {
                if (!kill_process(previous)) {
                    std::cerr << "PID: " << std::dec << previous->first
                              << " Unable to kill!" << std::endl;
                    return false;
                }
            }

            ++begin;
        }

        return true;
    }

    bool parse_verifier_msgs(typename V::const_iterator &begin,
                             const typename V::const_iterator &end) {
        while (begin != end) {
            const auto pid = begin->pid;
            auto it = processes.find(pid);

            switch (begin->op) {
            case HQ_VERIFIER_MSG_NOTIFY: {
                void *notify;
                if (!(notify = kernel.map())) {
                    std::cerr << "Failed to map notify page!" << std::endl;
                    return false;
                }

                return kernel.set_notify(
                    reinterpret_cast<struct hq_verifier_notify *>(notify));
            } break;

            case HQ_VERIFIER_MSG_CLONE: {
                if (it == processes.end()) {
                    std::cerr << "PID: " << std::dec << pid << " Unknown!"
                              << std::endl;
                    return false;
                }

                // Duplicate the existing process with new PID
                auto res = processes.try_emplace(begin->value, it->second);
                if (!res.second) {
                    std::cerr << "PID: " << std::dec << pid
                              << " Clone already exists!" << std::endl;
                    return false;
                } else
                    previous = res.first;

                std::cout << "PID: " << std::dec << pid << " ("
                          << res.first->second.get_name() << ") cloned to "
                          << begin->value << "!" << std::endl;

#ifdef HQ_CHECK_SYSCALL
                void *page;
                // Set the system call buffer
                if (!(page = kernel.map())) {
                    std::cerr << "PID: " << std::dec << pid
                              << " Failed to map syscall page(s)!" << std::endl;
                    return false;
                }

                res.first->second.set_syscall(
                    reinterpret_cast<struct hq_syscall *>(page));
#endif /* HQ_CHECK_SYSCALL */
            } break;

            case HQ_VERIFIER_MSG_SYSCALL_PAGE: {
                bool insert;
                // Create new process
                std::tie(it, insert) =
                    processes.try_emplace(pid, process_name(pid));
                if (!insert) {
                    std::cerr << "PID: " << std::dec << pid
                              << " Already exists!" << std::endl;
                    return false;
                } else
                    previous = it;

                std::cout << "PID: " << std::dec << pid << " ("
                          << it->second.get_name() << ") connected!"
                          << std::endl;

#ifdef HQ_CHECK_SYSCALL
                void *page;
                // Set the system call buffer
                if (!(page = kernel.map())) {
                    std::cerr << "PID: " << std::dec << pid
                              << " Failed to map syscall page(s)!" << std::endl;
                    return false;
                }

                previous->second.set_syscall(
                    reinterpret_cast<struct hq_syscall *>(page));
#endif /* HQ_CHECK_SYSCALL */
            } break;

            case HQ_VERIFIER_MSG_TERMINATE:
                if (it == processes.end()) {
                    std::cerr << "PID: " << std::dec << pid << " Unknown!"
                              << std::endl;
                    return false;
                }

                std::cout << "PID: " << std::dec << it->first << " ("
                          << it->second.get_name() << ") exited!\n"
                          << *it << std::endl;
#ifdef HQ_PRESERVE_STATS
                it->second.clear_entries();
                it->second.set_dead();
#else
                processes.erase(it);
                if (previous == it)
                    previous = processes.end();
#endif /* HQ_PRESERVE_STATS */
                break;

            default:
                return false;
                break;
            }

            ++begin;
        }

        return true;
    }

    static bool can_kill() {
#ifdef HQ_ENFORCE_CHECKS
        cap_flag_value_t can_kill = CAP_CLEAR;
        cap_t cap = cap_get_proc();

        cap_get_flag(cap, CAP_KILL, CAP_PERMITTED, &can_kill);

        cap_free(cap);
        return can_kill == CAP_SET;
#else
        return true;
#endif /* HQ_ENFORCE_CHECKS */
    }

    static bool kill_process(iterator it) {
#ifdef HQ_ENFORCE_CHECKS
        if (it->first <= 0)
            return false;

        std::cout << "PID: " << std::dec << it->first << " ("
                  << it->second.get_name() << ") killing..." << std::endl;
        if (kill(it->first, SIGKILL) && errno != ESRCH)
            return false;

#ifdef HQ_PRESERVE_STATS
        it->second.clear_entries();
        it->second.set_dead();
#endif /* HQ_PRESERVE_STATS */
#endif /* HQ_ENFORCE_CHECKS */
        return true;
    }

    static std::string process_name(pid_t pid) {
        std::string out = "<unknown>";
        std::stringstream path;
        std::ifstream file;

        // Concatenate path
        path << "/proc/" << pid << "/comm";

        // Read file
        file.open(path.str(), std::ifstream::in);
        if (file.good())
            std::getline(file, out);
        return out;
    }

    static void print_header(std::ostream &os) {
        os << "tid,name," << std::dec;
#define HQ_STAT(x) os << #x ",";
        HQ_STATS_LIST
#undef HQ_STAT
        os << std::endl;
    }
};

} // namespace HQ

#endif /* _HQ_VERIFIER_H_ */
