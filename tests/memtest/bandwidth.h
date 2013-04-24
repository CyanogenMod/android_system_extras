/*
 * Copyright (C) 2013 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __BANDWIDTH_H__
#define __BANDWIDTH_H__

#include "memtest.h"

// Bandwidth Class definitions.
class BandwidthBenchmark {
public:
    BandwidthBenchmark(size_t size)
        : _size(size),
          _num_warm_loops(DEFAULT_NUM_WARM_LOOPS),
          _num_loops(DEFAULT_NUM_LOOPS) {}
    virtual ~BandwidthBenchmark() {}

    void run() {
        bench(_num_warm_loops);

        nsecs_t t = system_time();
        bench(_num_loops);
        t = system_time() - t;

        _mb_per_sec = (_size*(_num_loops/_BYTES_PER_MB))/(t/_NUM_NS_PER_SEC);
    }

    virtual const char *getName() = 0;

    virtual bool verify() = 0;

    // Accessors/mutators.
    double mb_per_sec() { return _mb_per_sec; }
    size_t num_warm_loops() { return _num_warm_loops; }
    size_t num_loops() { return _num_loops; }
    size_t size() { return _size; }

    void set_num_warm_loops(size_t num_warm_loops) {
        _num_warm_loops = num_warm_loops;
    }
    void set_num_loops(size_t num_loops) { _num_loops = num_loops; }

    // Static constants
    static const unsigned int DEFAULT_NUM_WARM_LOOPS = 1000000;
    static const unsigned int DEFAULT_NUM_LOOPS = 20000000;

protected:
    virtual void bench(size_t num_loops) = 0;

    double _mb_per_sec;
    size_t _size;
    size_t _num_warm_loops;
    size_t _num_loops;

private:
    // Static constants
    static const double _NUM_NS_PER_SEC = 1000000000.0;
    static const double _BYTES_PER_MB = 1024.0* 1024.0;
};

class CopyBandwidthBenchmark : public BandwidthBenchmark {
public:
    CopyBandwidthBenchmark(size_t size) : BandwidthBenchmark(size) {
        if (_size == 0) {
            _size = DEFAULT_COPY_SIZE;
        }
        _src = reinterpret_cast<char*>(memalign(64, _size));
        if (!_src) {
          perror("Failed to allocate memory for test.");
          exit(1);
        }
        _dst = reinterpret_cast<char*>(memalign(64, _size));
        if (!_dst) {
          perror("Failed to allocate memory for test.");
          exit(1);
        }
    }
    virtual ~CopyBandwidthBenchmark() { free(_src); free(_dst); }

    bool verify() {
        memset(_src, 0x23, _size);
        memset(_dst, 0, _size);
        bench(1);
        if (memcmp(_src, _dst, _size) != 0) {
            printf("Strings failed to compare after one loop.\n");
            return false;
        }

        memset(_src, 0x23, _size);
        memset(_dst, 0, _size);
        _num_loops = 2;
        bench(2);
        if (memcmp(_src, _dst, _size) != 0) {
            printf("Strings failed to compare after two loops.\n");
            return false;
        }

        return true;
    }

protected:
    char *_src;
    char *_dst;

    static const unsigned int DEFAULT_COPY_SIZE = 8000;
};

class CopyLdrdStrdBenchmark : public CopyBandwidthBenchmark {
public:
    CopyLdrdStrdBenchmark(size_t size) : CopyBandwidthBenchmark(size) { }
    virtual ~CopyLdrdStrdBenchmark() {}

    const char *getName() { return "ldrd/strd"; }

protected:
    // Copy using ldrd/strd instructions.
    void bench(size_t num_loops) {
        asm volatile(
            "stmfd sp!, {r0,r1,r2,r3,r4,r6,r7}\n"

            "mov r0, %0\n"
            "mov r1, %1\n"
            "mov r2, %2\n"
            "mov r3, %3\n"

            "0:\n"
            "mov r4, r2, lsr #6\n"

            "1:\n"
            "ldrd r6, r7, [r0]\n"
            "strd r6, r7, [r1]\n"
            "ldrd r6, r7, [r0, #8]\n"
            "strd r6, r7, [r1, #8]\n"
            "ldrd r6, r7, [r0, #16]\n"
            "strd r6, r7, [r1, #16]\n"
            "ldrd r6, r7, [r0, #24]\n"
            "strd r6, r7, [r1, #24]\n"
            "ldrd r6, r7, [r0, #32]\n"
            "strd r6, r7, [r1, #32]\n"
            "ldrd r6, r7, [r0, #40]\n"
            "strd r6, r7, [r1, #40]\n"
            "ldrd r6, r7, [r0, #48]\n"
            "strd r6, r7, [r1, #48]\n"
            "ldrd r6, r7, [r0, #56]\n"
            "strd r6, r7, [r1, #56]\n"

            "add  r0, r0, #64\n"
            "add  r1, r1, #64\n"
            "subs r4, r4, #1\n"
            "bgt 1b\n"

            "sub r0, r0, r2\n"
            "sub r1, r1, r2\n"
            "subs r3, r3, #1\n"
            "bgt 0b\n"

            "ldmfd sp!, {r0,r1,r2,r3,r4,r6,r7}\n"
        :: "r" (_src), "r" (_dst), "r" (_size), "r" (num_loops) : "r0", "r1", "r2", "r3");
    }
};

class CopyLdmiaStmiaBenchmark : public CopyBandwidthBenchmark {
public:
    CopyLdmiaStmiaBenchmark(size_t size) : CopyBandwidthBenchmark(size) { }
    virtual ~CopyLdmiaStmiaBenchmark() {}

    const char *getName() { return "ldmia/stmia"; }

protected:
    // Copy using ldmia/stmia instructions.
    void bench(size_t num_loops) {
        asm volatile(
            "stmfd sp!, {r0,r1,r2,r3,r4,r5,r6,r7,r8,r9,r10,r11,r12}\n"

            "mov r0, %0\n"
            "mov r1, %1\n"
            "mov r2, %2\n"
            "mov r3, %3\n"

            "0:\n"
            "mov r4, r2, lsr #6\n"

            "1:\n"
            "ldmia r0!, {r5, r6, r7, r8, r9, r10, r11, r12}\n"
            "stmia r1!, {r5, r6, r7, r8, r9, r10, r11, r12}\n"
            "subs r4, r4, #1\n"
            "ldmia r0!, {r5, r6, r7, r8, r9, r10, r11, r12}\n"
            "stmia r1!, {r5, r6, r7, r8, r9, r10, r11, r12}\n"
            "bgt 1b\n"

            "sub r0, r0, r2\n"
            "sub r1, r1, r2\n"
            "subs r3, r3, #1\n"
            "bgt 0b\n"

            "ldmfd sp!, {r0,r1,r2,r3,r4,r5,r6,r7,r8,r9,r10,r11,r12}\n"
        :: "r" (_src), "r" (_dst), "r" (_size), "r" (num_loops) : "r0", "r1", "r2", "r3");
    }
};

class CopyVldVstBenchmark : public CopyBandwidthBenchmark {
public:
    CopyVldVstBenchmark(size_t size) : CopyBandwidthBenchmark(size) { }
    virtual ~CopyVldVstBenchmark() {}

    const char *getName() { return "vld/vst"; }

protected:
    // Copy using vld/vst instructions.
    void bench(size_t num_loops) {
        asm volatile(
            "stmfd sp!, {r0,r1,r2,r3,r4}\n"

            "mov r0, %0\n"
            "mov r1, %1\n"
            "mov r2, %2\n"
            "mov r3, %3\n"

            "0:\n"
            "mov r4, r2, lsr #6\n"

            "1:\n"
            "vld1.8 {d0-d3}, [r0]!\n"
            "vld1.8 {d4-d7}, [r0]!\n"
            "subs r4, r4, #1\n"
            "vst1.8 {d0-d3}, [r1:128]!\n"
            "vst1.8 {d4-d7}, [r1:128]!\n"
            "bgt 1b\n"

            "sub r0, r0, r2\n"
            "sub r1, r1, r2\n"
            "subs r3, r3, #1\n"
            "bgt 0b\n"

            "ldmfd sp!, {r0,r1,r2,r3,r4}\n"
        :: "r" (_src), "r" (_dst), "r" (_size), "r" (num_loops) : "r0", "r1", "r2", "r3");
    }
};

class CopyVldmiaVstmiaBenchmark : public CopyBandwidthBenchmark {
public:
    CopyVldmiaVstmiaBenchmark(size_t size) : CopyBandwidthBenchmark(size) { }
    virtual ~CopyVldmiaVstmiaBenchmark() {}

    const char *getName() { return "vldmia/vstmia"; }

protected:
    // Copy using vld/vst instructions.
    void bench(size_t num_loops) {
        asm volatile(
            "stmfd sp!, {r0,r1,r2,r3,r4}\n"

            "mov r0, %0\n"
            "mov r1, %1\n"
            "mov r2, %2\n"
            "mov r3, %3\n"

            "0:\n"
            "mov r4, r2, lsr #6\n"

            "1:\n"
            "vldmia r0!, {d0-d7}\n"
            "subs r4, r4, #1\n"
            "vstmia r1!, {d0-d7}\n"
            "bgt 1b\n"

            "sub r0, r0, r2\n"
            "sub r1, r1, r2\n"
            "subs r3, r3, #1\n"
            "bgt 0b\n"

            "ldmfd sp!, {r0,r1,r2,r3,r4}\n"
        :: "r" (_src), "r" (_dst), "r" (_size), "r" (num_loops) : "r0", "r1", "r2", "r3");
    }
};

class MemcpyBenchmark : public CopyBandwidthBenchmark {
public:
    MemcpyBenchmark(size_t size) : CopyBandwidthBenchmark(size) { }
    virtual ~MemcpyBenchmark() {}

    const char *getName() { return "memcpy"; }

protected:
    void bench(size_t num_loops) {
        for (size_t i = 0; i < num_loops; i++) {
            memcpy(_dst, _src, _size);
        }
    }
};

class WriteBandwidthBenchmark : public BandwidthBenchmark {
public:
    WriteBandwidthBenchmark(size_t size) : BandwidthBenchmark(size) {
        if (_size == 0) {
            _size = DEFAULT_WRITE_SIZE;
        }

        _buffer = reinterpret_cast<char*>(memalign(64, _size));
        if (!_buffer) {
          perror("Failed to allocate memory for test.");
          exit(1);
        }
        memset(_buffer, 0, _size);
    }
    virtual ~WriteBandwidthBenchmark() { free(_buffer); }

    bool verify() {
        memset(_buffer, 0, _size);
        bench(1);
        for (size_t i = 0; i < _size; i++) {
            if (_buffer[i] != 1) {
                printf("Strings failed to compare after one loop.\n");
                return false;
            }
        }

        memset(_buffer, 0, _size);
        bench(2);
        for (size_t i = 0; i < _size; i++) {
            if (_buffer[i] != 2) {
                printf("Strings failed to compare after two loops.\n");
                return false;
            }
        }

        return true;
    }

protected:
    char *_buffer;

    static const unsigned int DEFAULT_WRITE_SIZE = 16000;
};

class WriteStrdBenchmark : public WriteBandwidthBenchmark {
public:
    WriteStrdBenchmark(size_t size) : WriteBandwidthBenchmark(size) { }
    virtual ~WriteStrdBenchmark() {}

    const char *getName() { return "strd"; }

protected:
    // Write a given value using strd.
    void bench(size_t num_loops) {
        asm volatile(
            "stmfd sp!, {r0,r1,r2,r3,r4,r5}\n"

            "mov r0, %0\n"
            "mov r1, %1\n"
            "mov r2, %2\n"

            "mov r4, #0\n"
            "mov r5, #0\n"

            "0:\n"
            "mov r3, r1, lsr #5\n"

            "add r4, r4, #0x01010101\n"
            "mov r5, r4\n"

            "1:\n"
            "subs r3, r3, #1\n"
            "strd r4, r5, [r0]\n"
            "strd r4, r5, [r0, #8]\n"
            "strd r4, r5, [r0, #16]\n"
            "strd r4, r5, [r0, #24]\n"
            "add  r0, r0, #32\n"
            "bgt 1b\n"

            "sub r0, r0, r1\n"
            "subs r2, r2, #1\n"
            "bgt 0b\n"

            "ldmfd sp!, {r0,r1,r2,r3,r4,r5}\n"
          :: "r" (_buffer), "r" (_size), "r" (num_loops) : "r0", "r1", "r2");
    }
};

class WriteStmiaBenchmark : public WriteBandwidthBenchmark {
public:
    WriteStmiaBenchmark(size_t size) : WriteBandwidthBenchmark(size) { }
    virtual ~WriteStmiaBenchmark() {}

    const char *getName() { return "stmia"; }

protected:
      // Write a given value using stmia.
      void bench(size_t num_loops) {
          asm volatile(
              "stmfd sp!, {r0,r1,r2,r3,r4,r5,r6,r7,r8,r9,r10,r11}\n"

              "mov r0, %0\n"
              "mov r1, %1\n"
              "mov r2, %2\n"

              "mov r4, #0\n"

              "0:\n"
              "mov r3, r1, lsr #5\n"

              "add r4, r4, #0x01010101\n"
              "mov r5, r4\n"
              "mov r6, r4\n"
              "mov r7, r4\n"
              "mov r8, r4\n"
              "mov r9, r4\n"
              "mov r10, r4\n"
              "mov r11, r4\n"

              "1:\n"
              "subs r3, r3, #1\n"
              "stmia r0!, {r4, r5, r6, r7, r8, r9, r10, r11}\n"
              "bgt 1b\n"

              "sub r0, r0, r1\n"
              "subs r2, r2, #1\n"
              "bgt 0b\n"

              "ldmfd sp!, {r0,r1,r2,r3,r4,r5,r6,r7,r8,r9,r10,r11}\n"
        :: "r" (_buffer), "r" (_size), "r" (num_loops) : "r0", "r1", "r2");
    }
};

class WriteVstBenchmark : public WriteBandwidthBenchmark {
public:
    WriteVstBenchmark(size_t size) : WriteBandwidthBenchmark(size) { }
    virtual ~WriteVstBenchmark() {}

    const char *getName() { return "vst"; }

protected:
    // Write a given value using vst.
    void bench(size_t num_loops) {
        asm volatile(
            "stmfd sp!, {r0,r1,r2,r3,r4}\n"

            "mov r0, %0\n"
            "mov r1, %1\n"
            "mov r2, %2\n"
            "mov r4, #0\n"

            "0:\n"
            "mov r3, r1, lsr #5\n"

            "add r4, r4, #1\n"
            "vdup.8 d0, r4\n"
            "vmov d1, d0\n"
            "vmov d2, d0\n"
            "vmov d3, d0\n"

            "1:\n"
            "subs r3, r3, #1\n"
            "vst1.8 {d0-d3}, [r0:128]!\n"
            "bgt 1b\n"

            "sub r0, r0, r1\n"
            "subs r2, r2, #1\n"
            "bgt 0b\n"

            "ldmfd sp!, {r0,r1,r2,r3,r4}\n"
        :: "r" (_buffer), "r" (_size), "r" (num_loops) : "r0", "r1", "r2");
    }
};

class WriteVstmiaBenchmark : public WriteBandwidthBenchmark {
public:
    WriteVstmiaBenchmark(size_t size) : WriteBandwidthBenchmark(size) { }
    virtual ~WriteVstmiaBenchmark() {}

    const char *getName() { return "vstmia"; }

protected:
    // Write a given value using vstmia.
    void bench(size_t num_loops) {
        asm volatile(
            "stmfd sp!, {r0,r1,r2,r3,r4}\n"

            "mov r0, %0\n"
            "mov r1, %1\n"
            "mov r2, %2\n"
            "mov r4, #0\n"

            "0:\n"
            "mov r3, r1, lsr #5\n"

            "add r4, r4, #1\n"
            "vdup.8 d0, r4\n"
            "vmov d1, d0\n"
            "vmov d2, d0\n"
            "vmov d3, d0\n"

            "1:\n"
            "subs r3, r3, #1\n"
            "vstmia r0!, {d0-d3}\n"
            "bgt 1b\n"

            "sub r0, r0, r1\n"
            "subs r2, r2, #1\n"
            "bgt 0b\n"

            "ldmfd sp!, {r0,r1,r2,r3,r4}\n"
        :: "r" (_buffer), "r" (_size), "r" (num_loops) : "r0", "r1", "r2");
    }
};

class MemsetBenchmark : public WriteBandwidthBenchmark {
public:
    MemsetBenchmark(size_t size) : WriteBandwidthBenchmark(size) { }
    virtual ~MemsetBenchmark() {}

    const char *getName() { return "memset"; }

protected:
    void bench(size_t num_loops) {
        for (size_t i = 0; i < num_loops; i++) {
            memset(_buffer, (i % 255) + 1, _size);
        }
    }
};

#endif  // __BANDWIDTH_H__
