#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>

static const char msg1[] = "hello ";
static const char msg2[] = "world!\n";

# define SYSCALL32_1(num, a1)                          ({ unsigned long _ret; asm volatile ("int $0x80\n\t" : "=a"(_ret) : "0"(num), "b"(a1) : "memory"); _ret; })
# define SYSCALL64_3(num, a1, a2, a3)                  ({ unsigned long long _ret; asm volatile ("syscall" : "=a"(_ret) : "0"(num), "D"(a1), "S"(a2), "d"(a3) : "memory", "cc", "r11", "rcx"); _ret; })

int write1(int fd, const char *buf, size_t sz) {
    return SYSCALL64_3(SYS_write, fd, buf, sz);
}

int write2(int fd, const char *buf, size_t sz) {
    return syscall(SYS_write, fd, buf, sz);
}

int exit_group(int status) {
    // SYS_exit_group, 32-bit
    return SYSCALL32_1(0xfc, status);
}

int main(int argc, char **argv) {
    write1(STDOUT_FILENO, msg1, sizeof(msg1));
    write1(STDOUT_FILENO, msg2, sizeof(msg2));
    exit_group(EXIT_SUCCESS);
    return 0;
}
