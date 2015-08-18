#include <string>

void __attribute__((noinline)) memcpy_noinline(void *dst, void *src, size_t size)
{
    memcpy(dst,src,size);
}

void __attribute__((noinline)) memset_noinline(void *dst, int value, size_t size)
{
    memset(dst, value, size);
}

uint64_t __attribute__((noinline)) sum(volatile void *src, size_t size)
{
    uint64_t *src_ptr = (uint64_t*)src;
    uint64_t sum = 0;
    size_t len = size / sizeof(uint64_t);
    for (size_t i = 0; i < len; i+=1)
        sum += src_ptr[i];
    return sum;
}
