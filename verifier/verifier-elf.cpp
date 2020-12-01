#include <cstring>
#include <string>

#include <elf.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "parser-elf.h"
#include "verifier-elf.h"

namespace HQ {
bool ELF::load() {
    int fd;
    bool ret = true;

    std::string path("/proc/" + std::to_string(pid) + "/exe");
    if ((fd = open(path.c_str(), O_RDONLY)) <= 0)
        return false;

    struct stat sb;
    if (fstat(fd, &sb) == -1) {
        ret = false;
        goto out_fd;
    }

    size = sb.st_size;
    if ((map = reinterpret_cast<uint8_t *>(mmap(
             nullptr, size, PROT_READ, MAP_PRIVATE, fd, 0))) == MAP_FAILED) {
        map = nullptr;
        ret = false;
        goto out_fd;
    }

    if (!validate_ehdr(reinterpret_cast<const Elf_Ehdr *>(map), size)) {
        ret = false;
        goto out_fd;
    }

out_fd:
    close(fd);
    return ret;
}

std::pair<ELF::iterator, ELF::iterator> ELF::get_globals() {
    const auto *ehdr = reinterpret_cast<const Elf_Ehdr *>(map);
    const auto *shdr = reinterpret_cast<const Elf_Shdr *>(map + ehdr->e_shoff);
    const char *strtab;
    unsigned shnum, stridx;
    size_t strsz;

    if (!(shnum = get_shnum(ehdr, shdr)))
        goto out;

    if (!(stridx = get_stridx(ehdr, shdr)))
        goto out;

    if (!validate_strshdr(&shdr[stridx], size))
        goto out;

    strsz = shdr[stridx].sh_size;
    strtab = reinterpret_cast<const char *>(map + shdr[stridx].sh_offset);
    for (unsigned i = 1; i < shnum; ++i) {
        if (is_cfi_globals(&shdr[i], strtab, strsz, size)) {
            return std::make_pair(
                reinterpret_cast<ELF::iterator>(map + shdr[i].sh_offset),
                reinterpret_cast<ELF::iterator>(map + shdr[i].sh_offset +
                                                shdr[i].sh_size));
        }
    }

out:
    return std::make_pair(nullptr, nullptr);
}

} // namespace HQ
