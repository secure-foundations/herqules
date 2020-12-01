#ifndef _HQ_PARSER_ELF_H_
#define _HQ_PARSER_ELF_H_

#include "runtime.h"

/* Architecture-specific definitions */
/* See linux/Documentation/x86/x86_64/mm.txt */
#ifdef __x86_64__
typedef Elf64_Addr Elf_Addr;
typedef Elf64_Off Elf_Off;
typedef Elf64_Word Elf_Word;
typedef Elf64_Xword Elf_Xword;
typedef Elf64_Ehdr Elf_Ehdr;
typedef Elf64_Phdr Elf_Phdr;
typedef Elf64_Shdr Elf_Shdr;
#define IS_ELF_MACHINE(x) ((x) == EM_X86_64)
#elif defined(__i386__)
typedef Elf32_Addr Elf_Addr;
typedef Elf32_Off Elf_Off;
typedef Elf32_Word Elf_Word;
typedef Elf32_Word Elf_Xword;
typedef Elf32_Ehdr Elf_Ehdr;
typedef Elf32_Phdr Elf_Phdr;
typedef Elf32_Shdr Elf_Shdr;
#define IS_ELF_MACHINE(x) ((x) == EM_386 || (x) == EM_486)
#else
#error "Unsupported architecture!"
#endif

static bool validate_ehdr(const Elf_Ehdr *ehdr, size_t sz) {
    return !memcmp(ehdr->e_ident, ELFMAG, SELFMAG) &&
           (ehdr->e_type == ET_EXEC || ehdr->e_type == ET_DYN) &&
           IS_ELF_MACHINE(ehdr->e_machine) &&
           ehdr->e_shnum * sizeof(Elf_Shdr) < sz && ehdr->e_shoff < sz &&
           ehdr->e_shstrndx < ehdr->e_shnum &&
           ehdr->e_ehsize == sizeof(Elf_Ehdr) &&
           ehdr->e_phentsize == sizeof(Elf_Phdr);
}

static unsigned get_stridx(const Elf_Ehdr *ehdr, const Elf_Shdr *shdr) {
    if (ehdr->e_shstrndx == SHN_UNDEF)
        return 0;
    return ehdr->e_shstrndx == SHN_HIRESERVE ? shdr->sh_link : ehdr->e_shstrndx;
}

static unsigned get_shnum(const Elf_Ehdr *ehdr, const Elf_Shdr *shdr) {
    if (!ehdr->e_shoff)
        return 0;
    return !ehdr->e_shnum ? shdr->sh_size : ehdr->e_shnum;
}

static bool validate_strshdr(const Elf_Shdr *shdr, size_t sz) {
    return shdr->sh_type == SHT_STRTAB && !shdr->sh_flags &&
           shdr->sh_offset + shdr->sh_size < sz;
}

static bool is_cfi_globals(const Elf_Shdr *shdr, const char *strtab,
                           size_t strsz, size_t sz) {
    return shdr->sh_type == SHT_PROGBITS &&
           shdr->sh_offset + shdr->sh_size < sz && shdr->sh_name < strsz &&
           !strncmp(&strtab[shdr->sh_name], STR(INIT_SECTION_INTERNAL),
                    strsz - shdr->sh_name);
}

#endif /* _HQ_PARSER_ELF_H_ */
