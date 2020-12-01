#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

const unsigned NUM_THREADS = 8;

void __attribute__((noinline)) print(pthread_t id) {
    printf("%p Called: %s\n", id, __PRETTY_FUNCTION__);
}

static void (*gfp)(pthread_t);

void *thread(void *arg) {
    ((void (*)(pthread_t))arg)(pthread_self());
    return NULL;
}

int main(int argc, char **argv) {
    pthread_t threads[NUM_THREADS];

    gfp = print;
    #pragma nounroll
    for (unsigned i = 0; i < NUM_THREADS; ++i)
        pthread_create(&threads[i], NULL, &thread, gfp);
    #pragma nounroll
    for (unsigned i = 0; i < NUM_THREADS; ++i)
        pthread_join(threads[i], NULL);
    return 0;
}
