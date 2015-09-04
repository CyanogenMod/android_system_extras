#include <string>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <iostream>
#include <vector>
#include <tuple>

#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>

using namespace std;
static const size_t pageSize = 4096;

class Fd {
    int m_fd = -1;
public:
    int get() { return m_fd; }
    void set(int fd) { m_fd = fd; }
    Fd() {}
    Fd(int fd) : m_fd{fd} {}
    ~Fd() {
        if (m_fd >= 0)
            close(m_fd);
    }
};

int dummy = 0;

void fillPageJunk(void *ptr)
{
    uint64_t seed = (unsigned long long)rand() | ((unsigned long long)rand() << 32);
    uint64_t *target = (uint64_t*)ptr;
    for (int i = 0; i < pageSize / sizeof(uint64_t); i++) {
        *target = seed ^ (uint64_t)(uintptr_t)target;
        seed = (seed << 1) | ((seed >> 63) & 1);
        target++;
    }
}

class FileMap {
    string m_name;
    size_t m_size;
    void *m_ptr = nullptr;
    Fd m_fileFd;
public:
    enum Hint {
       FILE_MAP_HINT_NONE,
       FILE_MAP_HINT_RAND,
       FILE_MAP_HINT_LINEAR,
    };
    FileMap(const string &name, size_t size, Hint hint = FILE_MAP_HINT_NONE) : m_name{name}, m_size{size} {
        int fd = open(name.c_str(), O_CREAT | O_RDWR, S_IRWXU);
        if (fd < 0) {
            cerr << "open failed: " << fd << endl;
            return;
        }
        m_fileFd.set(fd);
        fallocate(m_fileFd.get(), 0, 0, size);
        unlink(name.c_str());
        m_ptr = mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_SHARED, m_fileFd.get(), 0);
        if ((int)(uintptr_t)m_ptr == -1) {
            cerr << "mmap failed: " << (int)(uintptr_t)m_ptr << endl;
            m_ptr = nullptr;
            return;
        }
        switch (hint) {
        case FILE_MAP_HINT_NONE: break;
        case FILE_MAP_HINT_RAND:
            madvise(m_ptr, m_size, MADV_RANDOM);
            break;
        case FILE_MAP_HINT_LINEAR:
            madvise(m_ptr, m_size, MADV_SEQUENTIAL);
            break;
        }
        for (int i = 0; i < m_size / pageSize; i++) {
            uint8_t *targetPtr = (uint8_t*)m_ptr + 4096ull * i;
            fillPageJunk(targetPtr);
        }
    }
    void benchRandom(bool write) {
        size_t pagesTotal = m_size / pageSize;
        size_t pagesToHit = pagesTotal / 128;
        uint64_t nsTotal = 0;

        chrono::time_point<chrono::high_resolution_clock> start, end;
        start = chrono::high_resolution_clock::now();
        for (int j = 0; j < pagesToHit; j++) {
            int targetPage = rand() % pagesTotal;
            uint8_t *targetPtr = (uint8_t*)m_ptr + 4096ull * targetPage;
            if (write) {
                *targetPtr = dummy;
            }
            else {
                dummy += *targetPtr;
            }
        }
        end = chrono::high_resolution_clock::now();
        nsTotal += chrono::duration_cast<chrono::nanoseconds>(end - start).count();
        //cout << "random: " << nsTotal / 1000.0 / (pagesToHit) << "us/page" << endl;
        cout << "random " << (write ? "write" : "read") << ": " << ((4096.0 * pagesToHit) / (1 << 20)) / (nsTotal / 1.0E9) << "MB/s" << endl;
    }
    void benchLinear(bool write) {
        int pagesTotal = m_size / pageSize;
        int iterations = 4;
        uint64_t nsTotal = 0;

        chrono::time_point<chrono::high_resolution_clock> start, end;
        start = chrono::high_resolution_clock::now();
        for (int i = 0; i < iterations; i++) {
            for (int j = 0; j < pagesTotal; j++) {
                uint8_t *targetPtr = (uint8_t*)m_ptr + 4096ull * j;
                if (write) {
                    *targetPtr = dummy;
                }
                else {
                    dummy += *targetPtr;
                }
            }
        }
        end = chrono::high_resolution_clock::now();
        nsTotal += chrono::duration_cast<chrono::nanoseconds>(end - start).count();
        //cout << "linear: " << nsTotal / 1000.0 / (pagesTotal * iterations) << "us/page" << endl;
        cout << "linear " << (write ? "write" : "read") << ": " << ((4096.0 * pagesTotal * iterations) / (1 << 20)) / (nsTotal / 1.0E9 ) << "MB/s" << endl;
    }
    void dropCache() {
        int ret1 = msync(m_ptr, m_size, MS_SYNC | MS_INVALIDATE);
        madvise(m_ptr, m_size, MADV_DONTNEED);
        (void)ret1;
    }
    ~FileMap() {
        if (m_ptr)
            munmap(m_ptr, m_size);
    }

};

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;
    srand(0);

    {
        FileMap file{"/data/local/tmp/mmap_test", 16000 * (1ull << 20)};
        file.benchRandom(false);
    }
    {
        FileMap file{"/data/local/tmp/mmap_test", 16000 * (1ull << 20)};
        file.benchLinear(false);
    }
    {
        FileMap file{"/data/local/tmp/mmap_test", 16000 * (1ull << 20)};
        file.benchRandom(true);
    }
    {
        FileMap file{"/data/local/tmp/mmap_test", 16000 * (1ull << 20)};
        file.benchLinear(true);
    }
    return 0;
}
