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
            cout << "Error: open failed for " << name << ": " << strerror(errno) << endl;
            exit(1);
        }
        m_fileFd.set(fd);
        fallocate(m_fileFd.get(), 0, 0, size);
        unlink(name.c_str());
        m_ptr = mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_SHARED, m_fileFd.get(), 0);
        if ((int)(uintptr_t)m_ptr == -1) {
            cout << "Error: mmap failed: " << (int)(uintptr_t)m_ptr << ": " << strerror(errno) << endl;
            exit(1);
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
    double benchRandom(bool write) {
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
        return ((4096.0 * pagesToHit) / (1 << 20)) / (nsTotal / 1.0E9);
    }
    double benchLinear(bool write) {
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
        return ((4096.0 * pagesTotal * iterations) / (1 << 20)) / (nsTotal / 1.0E9 );
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
    double randomRead, randomWrite, linearRead, linearWrite;
    size_t fsize = 0;
    srand(0);

    if (argc == 1)
        fsize = 1024 * (1ull << 20);
    else if (argc == 2) {
        long long sz = atoll(argv[1]);
        if (sz > 0 && (sz << 20) < SIZE_MAX)
            fsize = atoll(argv[1]) * (1ull << 20);
    }

    if (fsize <= 0) {
        cout << "Error: invalid argument" << endl;
        cerr << "Usage: " << argv[0] << " [fsize_in_MB]" << endl;
        exit(1);
    }
    cerr << "Using filesize=" << fsize << endl;

    {
        cerr << "Running random_read..." << endl;
        FileMap file{"/data/local/tmp/mmap_test", fsize};
        randomRead = file.benchRandom(false);
    }
    {
        cerr << "Running linear_read..." << endl;
        FileMap file{"/data/local/tmp/mmap_test", fsize};
        linearRead = file.benchLinear(false);
    }
    {
        cerr << "Running random_write..." << endl;
        FileMap file{"/data/local/tmp/mmap_test", fsize};
        randomWrite = file.benchRandom(true);
    }
    {
        cerr << "Running linear_write..." << endl;
        FileMap file{"/data/local/tmp/mmap_test", fsize};
        linearWrite = file.benchLinear(true);
    }
    cout << "Success" << endl;
    cout << "random_read : " << randomRead << " : MB/s" << endl;
    cout << "linear_read : " << linearRead << " : MB/s" << endl;
    cout << "random_write : " << randomWrite << " : MB/s" << endl;
    cout << "linear_write : " << linearWrite << " : MB/s" << endl;
    return 0;
}
