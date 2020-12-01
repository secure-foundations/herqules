/********
 * Tracking RTT + syscall using C++ interface (compile with instrumentation)
 ********/

#include <chrono>
#include <iostream>

#include <unistd.h>

int main(int argc, char **argv) {
    const unsigned iterations = (argc >= 2 ? std::atoi(argv[1]) : 10000);
    std::cout << "Iterations: " << iterations << std::endl;

    auto start = std::chrono::steady_clock::now();
    for (size_t i = 0; i < iterations; i++)
        getuid();
    auto end = std::chrono::steady_clock::now();
    auto diff = end - start;

    auto d = std::chrono::duration<double, std::nano>(diff).count();
    std::cout << "Duration: " << d << ", Average: " << d / iterations << " ns"
              << std::endl;
    return 0;
}
