#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <vector>

#include <signal.h>

#include "config.h"
#include "messages.h"
#include "stats.h"
#include "verifier-elf.h"

#include "process.h"

namespace HQ {
std::ostream &operator<<(std::ostream &os, const volatile hq_msg &msg) {
    os << std::dec << "PID: " << msg.pid << " ";

    switch (msg.op) {
    case HQ_MSG_EMPTY:
        os << "EMPTY (" << msg.op << ")";
        break;
    case HQ_MSG_SYSCALL:
        os << "SYSCALL (" << msg.op << ")";
        break;
    case HQ_MSG_INVALIDATE:
        os << "INVALIDATE (" << msg.op << ") " << std::hex << msg.values[1];
        break;
    case HQ_MSG_COPY_BLOCK: {
        const uintptr_t dst = ADDRESS_FROM_EMBED(msg.values[0]),
                        src = ADDRESS_FROM_EMBED(msg.values[1]),
                        sz = SIZE_FROM_EMBED(msg.values[0], msg.values[1]);
        os << "COPY-BLOCK (" << msg.op << ") " << std::hex << "[" << src << ", "
           << src + sz << ") -> [" << dst << ", " << dst + sz << ")";
        break;
    }
    case HQ_MSG_INVALIDATE_BLOCK: {
        const uintptr_t ptr = msg.values[0], sz = msg.values[1];
        os << "INVALIDATE-BLOCK (" << msg.op << ") " << std::hex << "[" << ptr
           << ", " << ptr + sz << ")";
        break;
    }
    case HQ_MSG_MOVE_BLOCK: {
        const uintptr_t dst = ADDRESS_FROM_EMBED(msg.values[0]),
                        src = ADDRESS_FROM_EMBED(msg.values[1]),
                        sz = SIZE_FROM_EMBED(msg.values[0], msg.values[1]);
        os << "MOVE-BLOCK (" << msg.op << ") " << std::hex << "[" << src << ", "
           << src + sz << ") -> [" << dst << ", " << dst + sz << ")";
        break;
    }
    case CFI_MSG_DEFINE: {
        const uintptr_t ptr = msg.values[0], val = msg.values[1];
        os << "CFI-DEFINE (" << msg.op << ") " << std::hex << ptr << " = "
           << val;
        break;
    }
    case CFI_MSG_CHECK: {
        const uintptr_t ptr = msg.values[0], val = msg.values[1];
        os << "CFI-CHECK (" << msg.op << ") " << std::hex << ptr
           << " == " << val;
        break;
    }
    case CFI_MSG_CHECK_INVALIDATE: {
        const uintptr_t ptr = msg.values[0], val = msg.values[1];
        os << "CFI-CHECK-INVALIDATE (" << msg.op << ") " << std::hex << ptr
           << " == " << val;
        break;
    }
    case CFI_MSG_INIT_GLOBALS:
        os << "CFI-INIT-GLOBALS (" << msg.op << ") " << std::hex
           << msg.values[1];
        break;
    default:
        os << "UNKNOWN (" << msg.op << ") " << std::hex << msg.values[0] << " "
           << msg.values[1];
        break;
    }

    return os;
}

void Process::clear_entries() { entries.clear(); }

bool Process::parse_msg(const pid_t pid, const volatile struct hq_msg &msg) {
#ifdef HQ_PRESERVE_STATS
    if (dead)
        return true;
#endif /* HQ_PRESERVE_STATS */

    switch (msg.op) {
    case CFI_MSG_DEFINE: {
        const uintptr_t ptr = msg.values[0], val = msg.values[1];

        stats[HQ_STAT_NUM_DEFINES]++;

        // Check for pointer alignment
        if (__builtin_expect(POINTER_IS_MISALIGNED(ptr), 0)) {
            std::cerr << "Define failed on unaligned pointer " << std::hex
                      << ptr << std::endl;
            stats[HQ_STAT_NUM_FAILS]++;
            return false;
        }

        entries.insert_or_assign(ptr, val);

        auto old_sz = stats[HQ_STAT_MAX_ENTRIES].load();
        auto new_sz = entries.size();
        while (
            old_sz < new_sz &&
            !stats[HQ_STAT_MAX_ENTRIES].compare_exchange_weak(old_sz, new_sz)) {
        }

        return true;
    }

    case CFI_MSG_CHECK: {
        const uintptr_t ptr = msg.values[0], val = msg.values[1];

        stats[HQ_STAT_NUM_CHECKS]++;

        auto it = entries.find(ptr);
        if (__builtin_expect(it != entries.end(), 1)) {
            if (__builtin_expect(it->second == val, 1))
                return true;

#ifndef NDEBUG
            std::cerr << "Check failed on pointer " << std::hex << ptr
                      << ", values " << val << " != " << it->second
                      << std::endl;
#endif /* NDEBUG */
        } else {
#ifndef NDEBUG
            std::cerr << "Check failed on missing pointer " << std::hex << ptr
                      << ", values " << val << std::endl;
#endif /* NDEBUG */
        }

#ifdef NDEBUG
        if (!stats[HQ_STAT_NUM_FAILS])
            std::cerr << "Check failed on pointer!" << std::endl;
#endif /* NDEBUG */
        stats[HQ_STAT_NUM_FAILS]++;
        return false;
    }

    case HQ_MSG_INVALIDATE: {
        const uintptr_t ptr = msg.values[1];

        stats[HQ_STAT_NUM_INVALIDATES]++;

        entries.erase(ptr);
        return true;
    }

    case CFI_MSG_CHECK_INVALIDATE: {
        const uintptr_t ptr = msg.values[0], val = msg.values[1];

        stats[HQ_STAT_NUM_CHECK_INVALIDATES]++;

        auto it = entries.find(ptr);
        if (__builtin_expect(it != entries.end(), 1)) {
            if (__builtin_expect(it->second == val, 1)) {
                entries.erase(it);
                return true;
            }

#ifndef NDEBUG
            std::cerr << "Check-invalidate failed on pointer " << std::hex
                      << ptr << ", values " << val << " != " << it->second
                      << std::endl;
#endif /* NDEBUG */
            entries.erase(it);
        } else {
#ifndef NDEBUG
            std::cerr << "Check-invalidate failed on missing pointer "
                      << std::hex << ptr << ", values " << val << std::endl;
#endif /* NDEBUG */
        }

#ifdef NDEBUG
        if (!stats[HQ_STAT_NUM_FAILS])
            std::cerr << "Check-invalidate failed on pointer!" << std::endl;
#endif /* NDEBUG */
        stats[HQ_STAT_NUM_FAILS]++;
        return false;
    }

    case HQ_MSG_COPY_BLOCK: {
        std::vector<decltype(entries)::value_type> copy;
        const uintptr_t dst = ADDRESS_FROM_EMBED(msg.values[0]),
                        src = ADDRESS_FROM_EMBED(msg.values[1]),
                        sz = SIZE_FROM_EMBED(msg.values[0], msg.values[1]);

        stats[HQ_STAT_NUM_COPIES]++;

        // Check for same offset or empty size
        if (__builtin_expect(dst == src || !sz, 0))
            return true;

        // Check for overflow
        if (__builtin_expect(dst + sz < dst || src + sz < src, 0)) {
            std::cerr << "Copy failed on range " << std::hex << std::hex << src
                      << ",sz=" << sz << " to " << dst << " due to overflow!"
                      << std::endl;
            stats[HQ_STAT_NUM_FAILS]++;
            return false;
        }

        // Copy existing entries in old region - may overlap
        const auto ub = entries.lower_bound(src + sz);
        for (auto it = entries.lower_bound(src); it != ub; ++it) {
            assert(it->first >= src && it->first < src + sz);
            copy.emplace_back((it->first - src) + dst, it->second);
        }

        // Delete matching entries in new region
        entries.erase(entries.lower_bound(dst), entries.lower_bound(dst + sz));

        // Insert entries into new region
        entries.insert(copy.begin(), copy.end());

        auto old_sz = stats[HQ_STAT_MAX_ENTRIES].load();
        auto new_sz = entries.size();
        while (
            old_sz < new_sz &&
            !stats[HQ_STAT_MAX_ENTRIES].compare_exchange_weak(old_sz, new_sz)) {
        }

        return true;
    }

    case HQ_MSG_INVALIDATE_BLOCK: {
        const uintptr_t ptr = msg.values[0], sz = msg.values[1];

        stats[HQ_STAT_NUM_FREES]++;

        // Check for null pointer or empty size
        if (__builtin_expect(!ptr || !sz, 0))
            return true;

        // Check for overflow
        if (__builtin_expect(ptr + sz < ptr, 0)) {
            std::cerr << "Invalidate failed on range " << std::hex << ptr
                      << ",sz=" << sz << " due to overflow!" << std::endl;
            stats[HQ_STAT_NUM_FAILS]++;
            return false;
        }

        // Delete matching entries in new region
        entries.erase(entries.lower_bound(ptr), entries.lower_bound(ptr + sz));

        return true;
    }

    case HQ_MSG_MOVE_BLOCK: {
        const uintptr_t dst = ADDRESS_FROM_EMBED(msg.values[0]),
                        src = ADDRESS_FROM_EMBED(msg.values[1]),
                        sz = SIZE_FROM_EMBED(msg.values[0], msg.values[1]);

        stats[HQ_STAT_NUM_MOVES]++;

        // Check for null destination, same offset, or empty size
        if (__builtin_expect(!dst || dst == src || !sz, 0))
            return true;

        // Check for range overlap or overflow
        if (__builtin_expect((src < dst + sz && src + sz > dst) ||
                                 dst + sz < dst || src + sz < src,
                             0)) {
            std::cerr << "Relocate failed on range " << std::hex << src
                      << ",sz=" << sz << " to " << dst << " due to overflow!"
                      << std::endl;
            stats[HQ_STAT_NUM_FAILS]++;
            return false;
        }

        // Delete matching entries in new region
        entries.erase(entries.lower_bound(dst), entries.lower_bound(dst + sz));

        // Move existing entries in old region
        const uintptr_t ub = src + sz;
        typename decltype(entries)::iterator it;
        while ((it = entries.lower_bound(src)) != entries.lower_bound(ub)) {
            assert(it->first >= src && it->first < src + sz);
            auto entry = entries.extract(it);
            entry.key() = (entry.key() - src) + dst;

            // Insert the new entry
            auto ins = entries.insert(std::move(entry));
            assert(ins.inserted);
        }

        auto old_sz = stats[HQ_STAT_MAX_ENTRIES].load();
        auto new_sz = entries.size();
        while (
            old_sz < new_sz &&
            !stats[HQ_STAT_MAX_ENTRIES].compare_exchange_weak(old_sz, new_sz)) {
        }

        return true;
    }

    case HQ_MSG_SYSCALL: {
        stats[HQ_STAT_NUM_SYSCALLS]++;

#ifdef HQ_CHECK_SYSCALL
        if (__builtin_expect(!syscall, 0)) {
            std::cerr << "Missing syscall buffer!" << std::endl;
            stats[HQ_STAT_NUM_FAILS]++;
            return false;
        }

        __atomic_store_n(&syscall->ok, 1, __ATOMIC_RELEASE);
#endif /* HQ_CHECK_SYSCALL */
        return true;
    } break;

    case CFI_MSG_INIT_GLOBALS: {
        const uintptr_t base = msg.values[1];
        ELF elf(pid);

        if (__builtin_expect(entries.size(), 0)) {
            std::cerr << "Pointers are already defined!" << std::endl;
            return false;
        }

        if (__builtin_expect(!elf.load(), 0)) {
            std::cerr << "Failed to read ELF header!" << std::endl;
            return false;
        }

        ELF::iterator it, ie;
        auto hint = entries.begin();
        for (std::tie(it, ie) = elf.get_globals(); it != ie; ++it) {
            hint = entries.emplace_hint(hint, base + it->ptr, base + it->val);
            stats[HQ_STAT_NUM_INIT_GLOBALS]++;
        }

        auto old_sz = stats[HQ_STAT_MAX_ENTRIES].load();
        auto new_sz = entries.size();
        while (
            old_sz < new_sz &&
            !stats[HQ_STAT_MAX_ENTRIES].compare_exchange_weak(old_sz, new_sz)) {
        }

        return true;
    } break;

    default:
        std::cerr << "Unrecognized message " << std::hex << msg.values[0] << " "
                  << msg.values[1] << "!" << std::endl;
        stats[HQ_STAT_NUM_FAILS]++;
        break;
    }

    return false;
}

#ifdef HQ_PRESERVE_STATS
bool Process::is_dead() const { return dead; }

void Process::set_dead() { dead = true; }
#endif /* HQ_PRESERVE_STATS */

void Process::set_syscall(struct hq_syscall *s) { syscall = s; }

const std::string &Process::get_name() const { return name; }

unsigned Process::get_stat(enum hq_stats stat) const { return stats.at(stat); }

std::ostream &operator<<(std::ostream &os,
                         const std::pair<const pid_t, Process> &p) {
    os << std::dec << p.first << "," << p.second.name << ",";
#define HQ_STAT(x) os << p.second.stats.at(HQ_STAT_##x).load() << ",";
    HQ_STATS_LIST
#undef HQ_STAT
    os << std::endl;

    return os;
}

} // namespace HQ
