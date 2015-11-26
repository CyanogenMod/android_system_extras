#include <iostream>
#include <chrono>
#include <numeric>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <unistd.h>
#include <sys/swap.h>

using namespace std;

const char zram_blkdev_path[] = "/dev/block/zram0";
const size_t sector_size = 512;
const size_t page_size = 4096;

void fillPageRand(uint32_t *page) {
    int start = rand();
    for (int i = 0; i < page_size / sizeof(int); i++) {
        page[i] = start+i;
    }
}
void fillPageCompressible(uint32_t *page) {
    int val = rand() & 0xfff;
    for (int i = 0; i < page_size / sizeof(int); i++) {
        page[i] = val;
    }
}

class AlignedAlloc {
    void *m_ptr;
public:
    AlignedAlloc(size_t size, size_t align) {
        posix_memalign(&m_ptr, align, size);
    }
    ~AlignedAlloc() {
        free(m_ptr);
    }
    void *ptr() {
        return m_ptr;
    }
};

class BlockFd {
    int m_fd = -1;
public:
    BlockFd(const char *path, bool direct) {
        m_fd = open(path, O_RDWR | (direct ? O_DIRECT : 0));
    }
    size_t getSize() {
        size_t blockSize = 0;
        int result = ioctl(m_fd, BLKGETSIZE, &blockSize);
        if (result < 0) {
            cout << "ioctl failed" << endl;
        }
        return blockSize * sector_size;
    }
    ~BlockFd() {
        if (m_fd >= 0) {
            close(m_fd);
        }
    }
    void fillWithCompressible() {
        size_t devSize = getSize();
        AlignedAlloc page(page_size, page_size);
        for (uint64_t offset = 0; offset < devSize; offset += page_size) {
            fillPageCompressible((uint32_t*)page.ptr());
            ssize_t ret = write(m_fd, page.ptr(), page_size);
            if (ret != page_size) {
                cout << "write() failed" << endl;
            }
        }
    }
    void benchSequentialRead() {
        chrono::time_point<chrono::high_resolution_clock> start, end;
        size_t devSize = getSize();
        size_t passes = 4;
        AlignedAlloc page(page_size, page_size);

        start = chrono::high_resolution_clock::now();
        for (int i = 0; i < passes; i++) {
            for (uint64_t offset = 0; offset < devSize; offset += page_size) {
                if (offset == 0)
                    lseek(m_fd, offset, SEEK_SET);
                ssize_t ret = read(m_fd, page.ptr(), page_size);
                if (ret != page_size) {
                    cout << "read() failed" << endl;
                }
            }
        }
        end = chrono::high_resolution_clock::now();
        size_t duration = chrono::duration_cast<chrono::microseconds>(end - start).count();
        cout << "read: " << (double)devSize * passes / 1024.0 / 1024.0 / (duration / 1000.0 / 1000.0) << "MB/s" << endl;
    }
    void benchSequentialWrite() {
        chrono::time_point<chrono::high_resolution_clock> start, end;
        size_t devSize = getSize();
        size_t passes = 4;
        AlignedAlloc page(page_size, page_size);

        start = chrono::high_resolution_clock::now();
        for (int i = 0; i < passes; i++) {
            for (uint64_t offset = 0; offset < devSize; offset += page_size) {
                fillPageCompressible((uint32_t*)page.ptr());
                if (offset == 0)
                    lseek(m_fd, offset, SEEK_SET);
                ssize_t ret = write(m_fd, page.ptr(), page_size);
                if (ret != page_size) {
                    cout << "write() failed" << endl;
                }
            }
        }
        end = chrono::high_resolution_clock::now();
        size_t duration = chrono::duration_cast<chrono::microseconds>(end - start).count();
        cout << "write: " << (double)devSize * passes / 1024.0 / 1024.0 / (duration / 1000.0 / 1000.0) << "MB/s" << endl;

    }
};

int bench(bool direct)
{
    BlockFd zramDev{zram_blkdev_path, direct};

    zramDev.fillWithCompressible();
    zramDev.benchSequentialRead();
    zramDev.benchSequentialWrite();
    return 0;
}

int main(int argc, char *argv[])
{
    int result = swapoff(zram_blkdev_path);
    if (result < 0) {
        cout << "swapoff failed: " << strerror(errno) << endl;
    }

    bench(1);

    result = system((string("mkswap ") + string(zram_blkdev_path)).c_str());
    if (result < 0) {
        cout << "mkswap failed: " <<  strerror(errno) << endl;
        return -1;
    }

    result = swapon(zram_blkdev_path, 0);
    if (result < 0) {
        cout << "swapon failed: " <<  strerror(errno) << endl;
        return -1;
    }
    return 0;
}
