#ifndef _HQ_VERIFIER_ELF_H_
#define _HQ_VERIFIER_ELF_H_

#include <utility>

#include <sys/mman.h>

#include "messages.h"
#include "runtime.h"

namespace HQ {
class ELF {
    pid_t pid = -1;
    const uint8_t *map = nullptr;
    size_t size = 0;

  public:
    using iterator = const hq_init_t *;

    ELF(pid_t p) : pid(p) {}

    ~ELF() {
        if (map)
            munmap(const_cast<uint8_t *>(map), size);
    }

    bool load();
    std::pair<iterator, iterator> get_globals();
};

} // namespace HQ

#endif /* _HQ_VERIFIER_ELF_H_ */
