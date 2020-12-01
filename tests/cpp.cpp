#include <iostream>
#include <memory>

class G {
  public:
    __attribute__((noinline)) virtual char getType() { return 'G'; }
};

class F {
  public:
    __attribute__((noinline)) F();

    __attribute__((noinline)) virtual ~F();

    __attribute__((noinline)) virtual char getType() = 0;
};

F::F() { printf("constructing F\n"); }

F::~F() {}

class E {
    char vE;

  public:
    __attribute__((noinline)) E(char s);
};

E::E(char s) : vE(s) { printf("constructing E\n"); }

class D : virtual public F {
    char vD;
    std::unique_ptr<E> ptrE;

  public:
    __attribute__((noinline)) D(char s);

    __attribute__((noinline)) virtual ~D();

    __attribute__((noinline)) virtual char getType() { return 'D'; }

  protected:
    __attribute__((noinline)) void compute() {
        printf("computing in %c\n", vD);
    }
};

D::D(char s) : vD(s) {
    printf("constructing D\n");

    ptrE = std::make_unique<E>('e');
    compute();
}

D::~D() { ptrE.reset(); }

class C : virtual public F {
  public:
    __attribute__((noinline)) C();
};

C::C() { printf("constructing C\n"); }

class B : public C, public D {
    char vB;

  public:
    __attribute__((noinline)) B();
};

B::B() : C(), D('D'), vB('B') { printf("constructing B\n"); }

class A : public B {
    char vA;

  public:
    __attribute__((noinline)) A(char s);

    __attribute__((noinline)) char getType() { return 'A'; }
};

A::A(char s) : vA(s) { printf("constructing A\n"); }

static G staticG;

int main(int argc, char **argv) {
    A *ptrA = new A('A');

    printf("%c\n", ptrA->getType());

    delete ptrA;

    printf("%c\n", staticG.getType());

    return 0;
}
