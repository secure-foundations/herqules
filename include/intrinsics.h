#ifndef _HQ_INTRINSICS_H_
#define _HQ_INTRINSICS_H_

#include <emmintrin.h>
#include <immintrin.h>
#include <xmmintrin.h>

namespace HQ {

#ifdef __AVX__
#define AVX_FEATURE __attribute__((target("avx")))
#else
#define AVX_FEATURE
#endif /* __AVX__ */

#ifdef __AVX512F__
#define AVX512F_FEATURE __attribute__((target("avx512f")))
#else
#define AVX512F_FEATURE
#endif /* __AVX512F__ */

#ifdef __SSE__
#define SSE_FEATURE __attribute__((target("sse")))
#else
#define SSE_FEATURE
#endif /* __SSE__ */

#ifdef __SSE2__
#define SSE2_FEATURE __attribute__((target("sse2")))
#else
#define SSE2_FEATURE
#endif /* __SSE2__ */

#ifdef __CLWB__
#define FLUSH_FEATURE __attribute__((target("clwb")))
#elif defined(__CLFLUSHOPT__)
#define FLUSH_FEATURE __attribute__((target("clflushopt")))
#else
#define FLUSH_FEATURE SSE2_FEATURE
#endif /* __CLWB__ */

inline uint64_t read64(volatile uint8_t *mmio, unsigned offset) {
    return *reinterpret_cast<volatile uint64_t *>(mmio + offset);
}

inline void write64(volatile uint8_t *mmio, unsigned offset, uint64_t value) {
    volatile auto *ptr = reinterpret_cast<volatile uint64_t *>(mmio + offset);
    *ptr = value;
}

SSE2_FEATURE inline void write64nt(volatile uint8_t *mmio, unsigned offset,
                                   uint64_t value) {
    volatile auto *ptr =
        reinterpret_cast<volatile long long int *>(mmio + offset);
    _mm_stream_si64(const_cast<long long int *>(ptr), value);
}

SSE2_FEATURE inline void write128nt(volatile uint8_t *mmio, unsigned offset,
                                    __m128i value) {
    volatile auto *ptr = reinterpret_cast<volatile __m128i *>(mmio + offset);
    _mm_stream_si128(const_cast<__m128i *>(ptr), value);
}

SSE2_FEATURE inline __m128i fill128(uint64_t i0, uint64_t i1) {
    return _mm_set_epi64x(i0, i1);
}

AVX_FEATURE inline void write256(volatile uint8_t *mmio, unsigned offset,
                                 __m256i value) {
    volatile auto *ptr = reinterpret_cast<volatile __m256i *>(mmio + offset);
    _mm256_store_si256(const_cast<__m256i *>(ptr), value);
}

AVX_FEATURE inline void write256nt(volatile uint8_t *mmio, unsigned offset,
                                   __m256i value) {
    volatile auto *ptr = reinterpret_cast<volatile __m256i *>(mmio + offset);
    _mm256_stream_si256(const_cast<__m256i *>(ptr), value);
}

AVX_FEATURE inline __m256i fill256(uint64_t i0, uint64_t i1, uint64_t i2,
                                   uint64_t i3) {
    return _mm256_set_epi64x(i0, i1, i2, i3);
}

AVX512F_FEATURE inline void write512nt(volatile uint8_t *mmio, unsigned offset,
                                       __m512i value) {
    volatile auto *ptr = reinterpret_cast<volatile __m512i *>(mmio + offset);
    _mm512_stream_si512(const_cast<__m512i *>(ptr), value);
}

FLUSH_FEATURE inline void flush512(volatile uint8_t *mmio, unsigned offset) {
    auto *ptr =
        reinterpret_cast<uint64_t *>(const_cast<uint8_t *>(mmio + offset));
#ifdef __CLWB__
    _mm_clwb(ptr);
#elif defined(__CLFLUSHOPT__)
    _mm_clflushopt(ptr);
#else
    _mm_clflush(ptr);
#endif /* __CLWB__ */
}

AVX_FEATURE inline __m256i zero256() { return _mm256_setzero_si256(); }

SSE_FEATURE inline void sfence() { _mm_sfence(); }

static inline uint64_t rdmsr(uint64_t msr) {
    uint32_t low, high;
    asm volatile("rdmsr" : "=a"(low), "=d"(high) : "c"(msr));

    return ((uint64_t)high << 32) | low;
}

static inline void wrmsr(uint64_t msr, uint64_t value) {
    asm volatile("wrmsr"
                 :
                 : "c"(msr), "a"(value & 0xFFFFFFFF), "d"(value >> 32));
}

} // namespace HQ

#endif /* _HQ_INTRINSICS_H_ */
