#include <iostream>
#include <chrono>
#include <vector>
#include <algorithm>
#include <numeric>
#include <stdlib.h>
#include <memory>
#include <cmath>
#include <string>

using namespace std;

const size_t size_start = 64;
const size_t size_end = 16 * (1ull << 20);
const size_t samples = 2048;
size_t size_per_test = 64 * (1ull << 20);
size_t tot_sum = 0;

void __attribute__((noinline)) memcpy_noinline(void *dst, void *src, size_t size);
void __attribute__((noinline)) memset_noinline(void *dst, int value, size_t size);
uint64_t __attribute__((noinline)) sum(volatile void *src, size_t size);

enum BenchType {
    MemcpyBench,
    MemsetBench,
    SumBench,
};

int main(int argc, char *argv[])
{
    BenchType type;
    if (argc <= 1) {
        cerr << "memcpy_perf [--memcpy|--memset|--sum]" << endl;
        return 0;
    }
    if (string(argv[1]) == string("--memcpy")) {
        type = MemcpyBench;
    } else if (string(argv[1]) == string("--memset")) {
        type = MemsetBench;
    } else if (string(argv[1]) == string("--sum")) {
        type = SumBench;
    } else {
        type = MemcpyBench;
    }

    unique_ptr<uint8_t[]> src(new uint8_t[size_end]);
    unique_ptr<uint8_t[]> dst(new uint8_t[size_end]);
    memset(src.get(), 1, size_end);

    double start_pow = log10(size_start);
    double end_pow = log10(size_end);
    double pow_inc = (end_pow - start_pow) / samples;

    //cout << "src: " << (uintptr_t)src.get() << endl;
    //cout << "dst: " <<  (uintptr_t)dst.get() << endl;

    for (double cur_pow = start_pow; cur_pow <= end_pow; cur_pow += pow_inc) {
        chrono::time_point<chrono::high_resolution_clock> copy_start, copy_end;

        size_t cur_size = (size_t)pow(10.0, cur_pow);
        size_t iter_per_size = size_per_test / cur_size;

        // run benchmark
        switch (type) {
            case MemsetBench: {
                memcpy_noinline(src.get(), dst.get(), cur_size);
                memset_noinline(dst.get(), 0xdeadbeef, cur_size);
                copy_start = chrono::high_resolution_clock::now();
                for (int i = 0; i < iter_per_size; i++) {
                    memset_noinline(dst.get(), 0xdeadbeef, cur_size);
                }
                copy_end = chrono::high_resolution_clock::now();
                break;
            }
            case MemcpyBench: {
                memcpy_noinline(dst.get(), src.get(), cur_size);
                memcpy_noinline(src.get(), dst.get(), cur_size);
                copy_start = chrono::high_resolution_clock::now();
                for (int i = 0; i < iter_per_size; i++) {
                    memcpy_noinline(dst.get(), src.get(), cur_size);
                }
                copy_end = chrono::high_resolution_clock::now();
                break;
            }
            case SumBench: {
                uint64_t s = 0;
                s += sum(src.get(), cur_size);
                copy_start = chrono::high_resolution_clock::now();
                for (int i = 0; i < iter_per_size; i++) {
                    s += sum(src.get(), cur_size);
                }
                copy_end = chrono::high_resolution_clock::now();
                tot_sum += s;
                break;
            }
        }

        double ns_per_copy = chrono::duration_cast<chrono::nanoseconds>(copy_end - copy_start).count() / double(iter_per_size);
        double gb_per_sec = ((double)cur_size / (1ull<<30)) / (ns_per_copy / 1.0E9);
        if (type == MemcpyBench)
            gb_per_sec *= 2.0;
        cout << "size: " << cur_size << ", perf: " << gb_per_sec << "GB/s, iter: " << iter_per_size << endl;
    }
    return 0;
}
