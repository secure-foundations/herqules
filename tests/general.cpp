#include <cstdlib>
#include <cstring>
#include <iostream>

#include <setjmp.h>
#include <unistd.h>

typedef union {
    char c;
    char str[8];
    uint8_t u8;
    uint32_t u32;
    uint64_t u64;
    unsigned __int128 u128;
    void *ptr;
    void (*fptr)();
    float f;
    double d;
    long double ld;
    float _Complex fc;
    double _Complex dc;
    long double _Complex ldc;
} union_t;

typedef struct {
    char str[8];
    uint8_t u8;
    uint32_t u32;
    uint64_t u64;
    unsigned __int128 u128;
    void *ptr;
    void (*fptr)();
    float f;
    double d;
    long double ld;
    float _Complex fc;
    double _Complex dc;
    long double _Complex ldc;
} struct_t;

class Foo {
    union_t un;

  public:
    virtual ~Foo() = default;

    void operator=(char c) { un.c = c; }

    virtual void f() const { printf("Called: %s\n", __PRETTY_FUNCTION__); }

    bool test() { return un.fptr; }
};

class Bar : public Foo {
  public:
    void f() const override { printf("Called: %s\n", __PRETTY_FUNCTION__); }
};

class Baz : public Foo {
  public:
    void f() const override { printf("Called: %s\n", __PRETTY_FUNCTION__); }
};

char buf[] = "hello world";
char *__attribute__((noinline)) f1(void) {
    printf("Called: %s\n", __PRETTY_FUNCTION__);
    return &buf[0];
}
char *__attribute__((noinline)) f2(void) {
    printf("Called: %s\n", __PRETTY_FUNCTION__);
    return &buf[1];
}
char *__attribute__((noinline)) f3(void) {
    printf("Called: %s\nThis message should NOT be displayed!\n",
           __PRETTY_FUNCTION__);
    return &buf[1];
}

static struct_t values = { "abcdefg", 'h', 1, 2, 3, (void *)4, (void (*)())5, 6, 7, 8, 9, 10, 11 };

static char *(*gfp)(void);

// Test for function pointers
void __attribute__((noinline)) fp() {
    char *(*fp)();
    void *ptr = (void *)f1;

    // Assignment
    fp = f1;
    fp();

    // memcpy
    memcpy(&fp, &ptr, sizeof(fp));
    fp();

    // Round-trip
    ptr = (char *)fp;
    fp = (decltype(fp))ptr;
    fp();

    // Invalidation
    fp = NULL;
}

char __attribute__((noinline)) * (*ret_fp(void))() { return *gfp; }

// Test for C++ virtual calls
void __attribute__((noinline)) cpp_virt(Foo *f) {
#pragma nounroll
    for (unsigned i = 0; i < 2; ++i)
        f->f();
}

// Test for C++ pointer to member function
void __attribute__((noinline)) cpp_mf(Foo *f) {
    void (Foo::*mp)() const = &Foo::f;
    (f->*mp)();
}

// Test for runtime recursion check and dominated load elision
// Not supported by built-in LLVM optimizations: GVN due to GlobalVariable
// 'gfp', GlobalOpt/Mem2Reg due to possible recursion from indirect calls
unsigned __attribute__((noinline)) loop(unsigned n) {
    char *ptr;
    unsigned counter = 0;

#pragma nounroll
    for (unsigned i = 0; i < n; ++i) {
#pragma nounroll
        for (unsigned j = 0; j < n; ++j) {
            ptr = gfp();

            counter = *ptr++;
            counter = *ptr++;
        }
    }

    return counter;
}

void __attribute__((noinline)) store_loop(unsigned n) {
    gfp = n % 2 ? f1 : f2;
    loop(n);
}

void __attribute__((noinline)) lsjmp() {
    jmp_buf buf;

    if (setjmp(buf)) {
        f2();
        return;
    } else {
        longjmp(buf, 1);
    }
}

void __attribute__((noinline)) corrupt() {
    *((uint64_t *)&gfp) = (uintptr_t)f3 & ~(1ULL << 63);
}

int main(int argc, char **argv) {
    unsigned n = argc > 1 ? atoi(argv[1]) : 2;

    memset(&values, 0, sizeof(values));

    /* Function pointer tests */
    printf("Test: Function pointers\n");
    fp();
    gfp = f1;
    (ret_fp())();

    /* C++ tests */
    Bar *b = new Bar();
    printf("Test: C++ virtual calls\n");
    cpp_virt(b);

    printf("Test: C++ member functions\n");
    cpp_mf(b);
    delete b;

    /* Dominated load test */
    printf("Test: Dominated load\n");
    store_loop(n);

    /* Longjmp/setjmp test */
    printf("Test: Longjmp/setjmp\n");
    lsjmp();

    /* Corrupt */
    printf("Test: Corrupt\n");
    corrupt();
    gfp();

    return 0;
}
