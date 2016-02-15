/*
 * Copyright (C) 2015 The Android Open Source Project
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

#ifndef SIMPLE_PERF_RECORD_H_
#define SIMPLE_PERF_RECORD_H_

#include <stdio.h>
#include <sys/types.h>

#include <memory>
#include <queue>
#include <string>
#include <vector>

#include "build_id.h"
#include "perf_event.h"

struct KernelMmap;
struct ModuleMmap;
struct ThreadComm;
struct ThreadMmap;

enum user_record_type {
  PERF_RECORD_ATTR = 64,
  PERF_RECORD_EVENT_TYPE,
  PERF_RECORD_TRACING_DATA,
  PERF_RECORD_BUILD_ID,
  PERF_RECORD_FINISHED_ROUND,
};

struct PerfSampleIpType {
  uint64_t ip;
};

struct PerfSampleTidType {
  uint32_t pid, tid;
};

struct PerfSampleTimeType {
  uint64_t time;
};

struct PerfSampleAddrType {
  uint64_t addr;
};

struct PerfSampleIdType {
  uint64_t id;
};

struct PerfSampleStreamIdType {
  uint64_t stream_id;
};

struct PerfSampleCpuType {
  uint32_t cpu, res;
};

struct PerfSamplePeriodType {
  uint64_t period;
};

struct PerfSampleCallChainType {
  std::vector<uint64_t> ips;
};

struct PerfSampleRawType {
  std::vector<char> data;
};

struct PerfSampleBranchStackType {
  struct BranchStackItemType {
    uint64_t from;
    uint64_t to;
    uint64_t flags;
  };
  std::vector<BranchStackItemType> stack;
};

struct PerfSampleRegsUserType {
  uint64_t abi;
  uint64_t reg_mask;
  std::vector<uint64_t> regs;
};

struct PerfSampleStackUserType {
  std::vector<char> data;
  uint64_t dyn_size;
};

// SampleId is optional at the end of a record in binary format. Its content is determined by
// sample_id_all and sample_type in perf_event_attr. To avoid the complexity of referring to
// perf_event_attr each time, we copy sample_id_all and sample_type inside the SampleId structure.
struct SampleId {
  bool sample_id_all;
  uint64_t sample_type;

  PerfSampleTidType tid_data;             // Valid if sample_id_all && PERF_SAMPLE_TID.
  PerfSampleTimeType time_data;           // Valid if sample_id_all && PERF_SAMPLE_TIME.
  PerfSampleIdType id_data;               // Valid if sample_id_all && PERF_SAMPLE_ID.
  PerfSampleStreamIdType stream_id_data;  // Valid if sample_id_all && PERF_SAMPLE_STREAM_ID.
  PerfSampleCpuType cpu_data;             // Valid if sample_id_all && PERF_SAMPLE_CPU.

  SampleId();

  // Create the content of sample_id. It depends on the attr we use.
  size_t CreateContent(const perf_event_attr& attr);

  // Parse sample_id from binary format in the buffer pointed by p.
  void ReadFromBinaryFormat(const perf_event_attr& attr, const char* p, const char* end);

  // Write the binary format of sample_id to the buffer pointed by p.
  void WriteToBinaryFormat(char*& p) const;
  void Dump(size_t indent) const;
  size_t Size() const;
};

// Usually one record contains the following three parts in order in binary format:
//   perf_event_header (at the head of a record, containing type and size information)
//   data depends on the record type
//   sample_id (optional part at the end of a record)
// We hold the common parts (perf_event_header and sample_id) in the base class Record, and
// hold the type specific data part in classes derived from Record.
struct Record {
  perf_event_header header;
  SampleId sample_id;

  Record();
  Record(const perf_event_header* pheader);

  virtual ~Record() {
  }

  size_t size() const {
    return header.size;
  }

  uint32_t type() const {
    return header.type;
  }

  void Dump(size_t indent = 0) const;
  virtual std::vector<char> BinaryFormat() const = 0;
  virtual uint64_t Timestamp() const;

 protected:
  virtual void DumpData(size_t) const = 0;
};

struct MmapRecord : public Record {
  struct MmapRecordDataType {
    uint32_t pid, tid;
    uint64_t addr;
    uint64_t len;
    uint64_t pgoff;
  } data;
  std::string filename;

  MmapRecord() {  // For CreateMmapRecord.
  }

  MmapRecord(const perf_event_attr& attr, const perf_event_header* pheader);
  std::vector<char> BinaryFormat() const override;
  void AdjustSizeBasedOnData();

 protected:
  void DumpData(size_t indent) const override;
};

struct Mmap2Record : public Record {
  struct Mmap2RecordDataType {
    uint32_t pid, tid;
    uint64_t addr;
    uint64_t len;
    uint64_t pgoff;
    uint32_t maj;
    uint32_t min;
    uint64_t ino;
    uint64_t ino_generation;
    uint32_t prot, flags;
  } data;
  std::string filename;

  Mmap2Record() {
  }

  Mmap2Record(const perf_event_attr& attr, const perf_event_header* pheader);
  std::vector<char> BinaryFormat() const override;
  void AdjustSizeBasedOnData();

 protected:
  void DumpData(size_t indent) const override;
};

struct CommRecord : public Record {
  struct CommRecordDataType {
    uint32_t pid, tid;
  } data;
  std::string comm;

  CommRecord() {
  }

  CommRecord(const perf_event_attr& attr, const perf_event_header* pheader);
  std::vector<char> BinaryFormat() const override;

 protected:
  void DumpData(size_t indent) const override;
};

struct ExitOrForkRecord : public Record {
  struct ExitOrForkRecordDataType {
    uint32_t pid, ppid;
    uint32_t tid, ptid;
    uint64_t time;
  } data;

  ExitOrForkRecord() {
  }
  ExitOrForkRecord(const perf_event_attr& attr, const perf_event_header* pheader);
  std::vector<char> BinaryFormat() const override;

 protected:
  void DumpData(size_t indent) const override;
};

struct ExitRecord : public ExitOrForkRecord {
  ExitRecord(const perf_event_attr& attr, const perf_event_header* pheader)
      : ExitOrForkRecord(attr, pheader) {
  }
};

struct ForkRecord : public ExitOrForkRecord {
  ForkRecord() {
  }
  ForkRecord(const perf_event_attr& attr, const perf_event_header* pheader)
      : ExitOrForkRecord(attr, pheader) {
  }
};

struct SampleRecord : public Record {
  uint64_t sample_type;  // sample_type is a bit mask determining which fields below are valid.

  PerfSampleIpType ip_data;               // Valid if PERF_SAMPLE_IP.
  PerfSampleTidType tid_data;             // Valid if PERF_SAMPLE_TID.
  PerfSampleTimeType time_data;           // Valid if PERF_SAMPLE_TIME.
  PerfSampleAddrType addr_data;           // Valid if PERF_SAMPLE_ADDR.
  PerfSampleIdType id_data;               // Valid if PERF_SAMPLE_ID.
  PerfSampleStreamIdType stream_id_data;  // Valid if PERF_SAMPLE_STREAM_ID.
  PerfSampleCpuType cpu_data;             // Valid if PERF_SAMPLE_CPU.
  PerfSamplePeriodType period_data;       // Valid if PERF_SAMPLE_PERIOD.

  PerfSampleCallChainType callchain_data;       // Valid if PERF_SAMPLE_CALLCHAIN.
  PerfSampleRawType raw_data;                   // Valid if PERF_SAMPLE_RAW.
  PerfSampleBranchStackType branch_stack_data;  // Valid if PERF_SAMPLE_BRANCH_STACK.
  PerfSampleRegsUserType regs_user_data;        // Valid if PERF_SAMPLE_REGS_USER.
  PerfSampleStackUserType stack_user_data;      // Valid if PERF_SAMPLE_STACK_USER.

  SampleRecord(const perf_event_attr& attr, const perf_event_header* pheader);
  std::vector<char> BinaryFormat() const override;
  void AdjustSizeBasedOnData();
  uint64_t Timestamp() const override;

 protected:
  void DumpData(size_t indent) const override;
};

// BuildIdRecord is defined in user-space, stored in BuildId feature section in record file.
struct BuildIdRecord : public Record {
  uint32_t pid;
  BuildId build_id;
  std::string filename;

  BuildIdRecord() {
  }

  BuildIdRecord(const perf_event_header* pheader);
  std::vector<char> BinaryFormat() const override;

 protected:
  void DumpData(size_t indent) const override;
};

// UnknownRecord is used for unknown record types, it makes sure all unknown records
// are not changed when modifying perf.data.
struct UnknownRecord : public Record {
  std::vector<char> data;

  UnknownRecord(const perf_event_header* pheader);
  std::vector<char> BinaryFormat() const override;

 protected:
  void DumpData(size_t indent) const override;
};

// RecordCache is a cache used when receiving records from the kernel.
// It sorts received records based on type and timestamp, and pops records
// in sorted order. Records from the kernel need to be sorted because
// records may come from different cpus at the same time, and it is affected
// by the order in which we collect records from different cpus.
// RecordCache pushes records and pops sorted record online. It uses two checks to help
// ensure that records are popped in order. Each time we pop a record A, it is the earliest record
// among all records in the cache. In addition, we have checks for min_cache_size and
// min_time_diff. For min_cache_size check, we check if the cache size >= min_cache_size,
// which is based on the assumption that if we have received (min_cache_size - 1) records
// after record A, we are not likely to receive a record earlier than A. For min_time_diff
// check, we check if record A is generated min_time_diff ns earlier than the latest
// record, which is based on the assumption that if we have received a record for time t,
// we are not likely to receive a record for time (t - min_time_diff) or earlier.
class RecordCache {
 public:
  RecordCache(const perf_event_attr& attr, size_t min_cache_size = 1000u,
              uint64_t min_time_diff_in_ns = 1000000u);
  ~RecordCache();
  void Push(const char* data, size_t size);
  void Push(std::unique_ptr<Record> record);
  std::unique_ptr<Record> Pop();
  std::vector<std::unique_ptr<Record>> PopAll();

 private:
  struct RecordWithSeq {
    uint32_t seq;
    Record *record;

    bool IsHappensBefore(const RecordWithSeq& other) const;
  };

  struct RecordComparator {
    bool operator()(const RecordWithSeq& r1, const RecordWithSeq& r2);
  };

  RecordWithSeq CreateRecordWithSeq(Record *r);

  const perf_event_attr attr_;
  bool has_timestamp_;
  size_t min_cache_size_;
  uint64_t min_time_diff_in_ns_;
  uint64_t last_time_;
  uint32_t cur_seq_;
  std::priority_queue<RecordWithSeq, std::vector<RecordWithSeq>,
      RecordComparator> queue_;
};

std::vector<std::unique_ptr<Record>> ReadRecordsFromBuffer(const perf_event_attr& attr,
                                                           const char* buf, size_t buf_size);
std::unique_ptr<Record> ReadRecordFromFile(const perf_event_attr& attr, FILE* fp);
MmapRecord CreateMmapRecord(const perf_event_attr& attr, bool in_kernel, uint32_t pid, uint32_t tid,
                            uint64_t addr, uint64_t len, uint64_t pgoff,
                            const std::string& filename);
CommRecord CreateCommRecord(const perf_event_attr& attr, uint32_t pid, uint32_t tid,
                            const std::string& comm);
ForkRecord CreateForkRecord(const perf_event_attr& attr, uint32_t pid, uint32_t tid, uint32_t ppid,
                            uint32_t ptid);
BuildIdRecord CreateBuildIdRecord(bool in_kernel, pid_t pid, const BuildId& build_id,
                                  const std::string& filename);

#endif  // SIMPLE_PERF_RECORD_H_
