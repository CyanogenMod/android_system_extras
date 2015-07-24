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

#include "record.h"

#include <inttypes.h>
#include <algorithm>
#include <unordered_map>

#include <base/logging.h>
#include <base/stringprintf.h>

#include "environment.h"
#include "perf_regs.h"
#include "utils.h"

static std::string RecordTypeToString(int record_type) {
  static std::unordered_map<int, std::string> record_type_names = {
      {PERF_RECORD_MMAP, "mmap"},         {PERF_RECORD_LOST, "lost"},
      {PERF_RECORD_COMM, "comm"},         {PERF_RECORD_EXIT, "exit"},
      {PERF_RECORD_THROTTLE, "throttle"}, {PERF_RECORD_UNTHROTTLE, "unthrottle"},
      {PERF_RECORD_FORK, "fork"},         {PERF_RECORD_READ, "read"},
      {PERF_RECORD_SAMPLE, "sample"},     {PERF_RECORD_BUILD_ID, "build_id"},
      {PERF_RECORD_MMAP2, "mmap2"},
  };

  auto it = record_type_names.find(record_type);
  if (it != record_type_names.end()) {
    return it->second;
  }
  return android::base::StringPrintf("unknown(%d)", record_type);
}

template <class T>
void MoveFromBinaryFormat(T* data_p, size_t n, const char*& p) {
  size_t size = n * sizeof(T);
  memcpy(data_p, p, size);
  p += size;
}

template <class T>
void MoveToBinaryFormat(const T& data, char*& p) {
  *reinterpret_cast<T*>(p) = data;
  p += sizeof(T);
}

SampleId::SampleId() {
  memset(this, 0, sizeof(SampleId));
}

// Return sample_id size in binary format.
size_t SampleId::CreateContent(const perf_event_attr& attr) {
  sample_id_all = attr.sample_id_all;
  sample_type = attr.sample_type;
  // Other data are not necessary. TODO: Set missing SampleId data.
  size_t size = 0;
  if (sample_id_all) {
    if (sample_type & PERF_SAMPLE_TID) {
      size += sizeof(PerfSampleTidType);
    }
    if (sample_type & PERF_SAMPLE_TIME) {
      size += sizeof(PerfSampleTimeType);
    }
    if (sample_type & PERF_SAMPLE_ID) {
      size += sizeof(PerfSampleIdType);
    }
    if (sample_type & PERF_SAMPLE_STREAM_ID) {
      size += sizeof(PerfSampleStreamIdType);
    }
    if (sample_type & PERF_SAMPLE_CPU) {
      size += sizeof(PerfSampleCpuType);
    }
  }
  return size;
}

void SampleId::ReadFromBinaryFormat(const perf_event_attr& attr, const char* p, const char* end) {
  sample_id_all = attr.sample_id_all;
  sample_type = attr.sample_type;
  if (sample_id_all) {
    if (sample_type & PERF_SAMPLE_TID) {
      MoveFromBinaryFormat(tid_data, p);
    }
    if (sample_type & PERF_SAMPLE_TIME) {
      MoveFromBinaryFormat(time_data, p);
    }
    if (sample_type & PERF_SAMPLE_ID) {
      MoveFromBinaryFormat(id_data, p);
    }
    if (sample_type & PERF_SAMPLE_STREAM_ID) {
      MoveFromBinaryFormat(stream_id_data, p);
    }
    if (sample_type & PERF_SAMPLE_CPU) {
      MoveFromBinaryFormat(cpu_data, p);
    }
    // TODO: Add parsing of PERF_SAMPLE_IDENTIFIER.
  }
  CHECK_LE(p, end);
  if (p < end) {
    LOG(DEBUG) << "Record SampleId part has " << end - p << " bytes left\n";
  }
}

void SampleId::WriteToBinaryFormat(char*& p) const {
  if (sample_id_all) {
    if (sample_type & PERF_SAMPLE_TID) {
      MoveToBinaryFormat(tid_data, p);
    }
    if (sample_type & PERF_SAMPLE_TIME) {
      MoveToBinaryFormat(time_data, p);
    }
    if (sample_type & PERF_SAMPLE_ID) {
      MoveToBinaryFormat(id_data, p);
    }
    if (sample_type & PERF_SAMPLE_STREAM_ID) {
      MoveToBinaryFormat(stream_id_data, p);
    }
    if (sample_type & PERF_SAMPLE_CPU) {
      MoveToBinaryFormat(cpu_data, p);
    }
  }
}

void SampleId::Dump(size_t indent) const {
  if (sample_id_all) {
    if (sample_type & PERF_SAMPLE_TID) {
      PrintIndented(indent, "sample_id: pid %u, tid %u\n", tid_data.pid, tid_data.tid);
    }
    if (sample_type & PERF_SAMPLE_TIME) {
      PrintIndented(indent, "sample_id: time %" PRId64 "\n", time_data.time);
    }
    if (sample_type & PERF_SAMPLE_ID) {
      PrintIndented(indent, "sample_id: stream_id %" PRId64 "\n", id_data.id);
    }
    if (sample_type & PERF_SAMPLE_STREAM_ID) {
      PrintIndented(indent, "sample_id: stream_id %" PRId64 "\n", stream_id_data.stream_id);
    }
    if (sample_type & PERF_SAMPLE_CPU) {
      PrintIndented(indent, "sample_id: cpu %u, res %u\n", cpu_data.cpu, cpu_data.res);
    }
  }
}

Record::Record() {
  memset(&header, 0, sizeof(header));
}

Record::Record(const perf_event_header* pheader) {
  header = *pheader;
}

void Record::Dump(size_t indent) const {
  PrintIndented(indent, "record %s: type %u, misc %u, size %u\n",
                RecordTypeToString(header.type).c_str(), header.type, header.misc, header.size);
  DumpData(indent + 1);
  sample_id.Dump(indent + 1);
}

MmapRecord::MmapRecord(const perf_event_attr& attr, const perf_event_header* pheader)
    : Record(pheader) {
  const char* p = reinterpret_cast<const char*>(pheader + 1);
  const char* end = reinterpret_cast<const char*>(pheader) + pheader->size;
  MoveFromBinaryFormat(data, p);
  filename = p;
  p += ALIGN(filename.size() + 1, 8);
  CHECK_LE(p, end);
  sample_id.ReadFromBinaryFormat(attr, p, end);
}

void MmapRecord::DumpData(size_t indent) const {
  PrintIndented(indent, "pid %u, tid %u, addr 0x%" PRIx64 ", len 0x%" PRIx64 "\n", data.pid,
                data.tid, data.addr, data.len);
  PrintIndented(indent, "pgoff 0x%" PRIx64 ", filename %s\n", data.pgoff, filename.c_str());
}

std::vector<char> MmapRecord::BinaryFormat() const {
  std::vector<char> buf(header.size);
  char* p = buf.data();
  MoveToBinaryFormat(header, p);
  MoveToBinaryFormat(data, p);
  strcpy(p, filename.c_str());
  p += ALIGN(filename.size() + 1, 8);
  sample_id.WriteToBinaryFormat(p);
  return buf;
}

Mmap2Record::Mmap2Record(const perf_event_attr& attr, const perf_event_header* pheader)
    : Record(pheader) {
  const char* p = reinterpret_cast<const char*>(pheader + 1);
  const char* end = reinterpret_cast<const char*>(pheader) + pheader->size;
  MoveFromBinaryFormat(data, p);
  filename = p;
  p += ALIGN(filename.size() + 1, 8);
  CHECK_LE(p, end);
  sample_id.ReadFromBinaryFormat(attr, p, end);
}

void Mmap2Record::DumpData(size_t indent) const {
  PrintIndented(indent, "pid %u, tid %u, addr 0x%" PRIx64 ", len 0x%" PRIx64 "\n", data.pid,
                data.tid, data.addr, data.len);
  PrintIndented(indent,
                "pgoff 0x" PRIx64 ", maj %u, min %u, ino %" PRId64 ", ino_generation %" PRIu64 "\n",
                data.pgoff, data.maj, data.min, data.ino, data.ino_generation);
  PrintIndented(indent, "prot %u, flags %u, filenames %s\n", data.prot, data.flags,
                filename.c_str());
}

CommRecord::CommRecord(const perf_event_attr& attr, const perf_event_header* pheader)
    : Record(pheader) {
  const char* p = reinterpret_cast<const char*>(pheader + 1);
  const char* end = reinterpret_cast<const char*>(pheader) + pheader->size;
  MoveFromBinaryFormat(data, p);
  comm = p;
  p += ALIGN(strlen(p) + 1, 8);
  CHECK_LE(p, end);
  sample_id.ReadFromBinaryFormat(attr, p, end);
}

void CommRecord::DumpData(size_t indent) const {
  PrintIndented(indent, "pid %u, tid %u, comm %s\n", data.pid, data.tid, comm.c_str());
}

std::vector<char> CommRecord::BinaryFormat() const {
  std::vector<char> buf(header.size);
  char* p = buf.data();
  MoveToBinaryFormat(header, p);
  MoveToBinaryFormat(data, p);
  strcpy(p, comm.c_str());
  p += ALIGN(comm.size() + 1, 8);
  sample_id.WriteToBinaryFormat(p);
  return buf;
}

ExitOrForkRecord::ExitOrForkRecord(const perf_event_attr& attr, const perf_event_header* pheader)
    : Record(pheader) {
  const char* p = reinterpret_cast<const char*>(pheader + 1);
  const char* end = reinterpret_cast<const char*>(pheader) + pheader->size;
  MoveFromBinaryFormat(data, p);
  CHECK_LE(p, end);
  sample_id.ReadFromBinaryFormat(attr, p, end);
}

void ExitOrForkRecord::DumpData(size_t indent) const {
  PrintIndented(indent, "pid %u, ppid %u, tid %u, ptid %u\n", data.pid, data.ppid, data.tid,
                data.ptid);
}

std::vector<char> ForkRecord::BinaryFormat() const {
  std::vector<char> buf(header.size);
  char* p = buf.data();
  MoveToBinaryFormat(header, p);
  MoveToBinaryFormat(data, p);
  sample_id.WriteToBinaryFormat(p);
  return buf;
}

SampleRecord::SampleRecord(const perf_event_attr& attr, const perf_event_header* pheader)
    : Record(pheader) {
  const char* p = reinterpret_cast<const char*>(pheader + 1);
  const char* end = reinterpret_cast<const char*>(pheader) + pheader->size;
  sample_type = attr.sample_type;

  if (sample_type & PERF_SAMPLE_IP) {
    MoveFromBinaryFormat(ip_data, p);
  }
  if (sample_type & PERF_SAMPLE_TID) {
    MoveFromBinaryFormat(tid_data, p);
  }
  if (sample_type & PERF_SAMPLE_TIME) {
    MoveFromBinaryFormat(time_data, p);
  }
  if (sample_type & PERF_SAMPLE_ADDR) {
    MoveFromBinaryFormat(addr_data, p);
  }
  if (sample_type & PERF_SAMPLE_ID) {
    MoveFromBinaryFormat(id_data, p);
  }
  if (sample_type & PERF_SAMPLE_STREAM_ID) {
    MoveFromBinaryFormat(stream_id_data, p);
  }
  if (sample_type & PERF_SAMPLE_CPU) {
    MoveFromBinaryFormat(cpu_data, p);
  }
  if (sample_type & PERF_SAMPLE_PERIOD) {
    MoveFromBinaryFormat(period_data, p);
  }
  if (sample_type & PERF_SAMPLE_CALLCHAIN) {
    uint64_t nr;
    MoveFromBinaryFormat(nr, p);
    callchain_data.ips.resize(nr);
    MoveFromBinaryFormat(callchain_data.ips.data(), nr, p);
  }
  if (sample_type & PERF_SAMPLE_BRANCH_STACK) {
    uint64_t nr;
    MoveFromBinaryFormat(nr, p);
    branch_stack_data.stack.resize(nr);
    MoveFromBinaryFormat(branch_stack_data.stack.data(), nr, p);
  }
  if (sample_type & PERF_SAMPLE_REGS_USER) {
    MoveFromBinaryFormat(regs_user_data.abi, p);
    if (regs_user_data.abi == 0) {
      regs_user_data.reg_mask = 0;
    } else {
      regs_user_data.reg_mask = attr.sample_regs_user;
      size_t bit_nr = 0;
      for (size_t i = 0; i < 64; ++i) {
        if ((regs_user_data.reg_mask >> i) & 1) {
          bit_nr++;
        }
      }
      regs_user_data.regs.resize(bit_nr);
      MoveFromBinaryFormat(regs_user_data.regs.data(), bit_nr, p);
    }
  }
  if (sample_type & PERF_SAMPLE_STACK_USER) {
    uint64_t size;
    MoveFromBinaryFormat(size, p);
    if (size == 0) {
      stack_user_data.dyn_size = 0;
    } else {
      stack_user_data.data.resize(size);
      MoveFromBinaryFormat(stack_user_data.data.data(), size, p);
      MoveFromBinaryFormat(stack_user_data.dyn_size, p);
    }
  }
  // TODO: Add parsing of other PERF_SAMPLE_*.
  CHECK_LE(p, end);
  if (p < end) {
    LOG(DEBUG) << "Record has " << end - p << " bytes left\n";
  }
}

void SampleRecord::DumpData(size_t indent) const {
  PrintIndented(indent, "sample_type: 0x%" PRIx64 "\n", sample_type);
  if (sample_type & PERF_SAMPLE_IP) {
    PrintIndented(indent, "ip %p\n", reinterpret_cast<void*>(ip_data.ip));
  }
  if (sample_type & PERF_SAMPLE_TID) {
    PrintIndented(indent, "pid %u, tid %u\n", tid_data.pid, tid_data.tid);
  }
  if (sample_type & PERF_SAMPLE_TIME) {
    PrintIndented(indent, "time %" PRId64 "\n", time_data.time);
  }
  if (sample_type & PERF_SAMPLE_ADDR) {
    PrintIndented(indent, "addr %p\n", reinterpret_cast<void*>(addr_data.addr));
  }
  if (sample_type & PERF_SAMPLE_ID) {
    PrintIndented(indent, "id %" PRId64 "\n", id_data.id);
  }
  if (sample_type & PERF_SAMPLE_STREAM_ID) {
    PrintIndented(indent, "stream_id %" PRId64 "\n", stream_id_data.stream_id);
  }
  if (sample_type & PERF_SAMPLE_CPU) {
    PrintIndented(indent, "cpu %u, res %u\n", cpu_data.cpu, cpu_data.res);
  }
  if (sample_type & PERF_SAMPLE_PERIOD) {
    PrintIndented(indent, "period %" PRId64 "\n", period_data.period);
  }
  if (sample_type & PERF_SAMPLE_CALLCHAIN) {
    PrintIndented(indent, "callchain nr=%" PRIu64 "\n", callchain_data.ips.size());
    for (auto& ip : callchain_data.ips) {
      PrintIndented(indent + 1, "0x%" PRIx64 "\n", ip);
    }
  }
  if (sample_type & PERF_SAMPLE_BRANCH_STACK) {
    PrintIndented(indent, "branch_stack nr=%" PRIu64 "\n", branch_stack_data.stack.size());
    for (auto& item : branch_stack_data.stack) {
      PrintIndented(indent + 1, "from 0x%" PRIx64 ", to 0x%" PRIx64 ", flags 0x%" PRIx64 "\n",
                    item.from, item.to, item.flags);
    }
  }
  if (sample_type & PERF_SAMPLE_REGS_USER) {
    PrintIndented(indent, "user regs: abi=%" PRId64 "\n", regs_user_data.abi);
    for (size_t i = 0, pos = 0; i < 64; ++i) {
      if ((regs_user_data.reg_mask >> i) & 1) {
        PrintIndented(indent + 1, "reg (%s) 0x%016" PRIx64 "\n", GetRegName(i).c_str(),
                      regs_user_data.regs[pos++]);
      }
    }
  }
  if (sample_type & PERF_SAMPLE_STACK_USER) {
    PrintIndented(indent, "user stack: size %zu dyn_size %" PRIu64 "\n",
                  stack_user_data.data.size(), stack_user_data.dyn_size);
    const uint64_t* p = reinterpret_cast<const uint64_t*>(stack_user_data.data.data());
    const uint64_t* end = p + (stack_user_data.data.size() / sizeof(uint64_t));
    while (p < end) {
      PrintIndented(indent + 1, "");
      for (size_t i = 0; i < 4 && p < end; ++i, ++p) {
        printf(" %016" PRIx64, *p);
      }
      printf("\n");
    }
    printf("\n");
  }
}

BuildIdRecord::BuildIdRecord(const perf_event_header* pheader) : Record(pheader) {
  const char* p = reinterpret_cast<const char*>(pheader + 1);
  const char* end = reinterpret_cast<const char*>(pheader) + pheader->size;
  MoveFromBinaryFormat(pid, p);
  build_id = BuildId(p);
  p += ALIGN(build_id.Size(), 8);
  filename = p;
  p += ALIGN(filename.size() + 1, 64);
  CHECK_EQ(p, end);
}

void BuildIdRecord::DumpData(size_t indent) const {
  PrintIndented(indent, "pid %u\n", pid);
  PrintIndented(indent, "build_id %s\n", build_id.ToString().c_str());
  PrintIndented(indent, "filename %s\n", filename.c_str());
}

std::vector<char> BuildIdRecord::BinaryFormat() const {
  std::vector<char> buf(header.size);
  char* p = buf.data();
  MoveToBinaryFormat(header, p);
  MoveToBinaryFormat(pid, p);
  memcpy(p, build_id.Data(), build_id.Size());
  p += ALIGN(build_id.Size(), 8);
  strcpy(p, filename.c_str());
  p += ALIGN(filename.size() + 1, 64);
  return buf;
}

static std::unique_ptr<Record> ReadRecordFromBuffer(const perf_event_attr& attr,
                                                    const perf_event_header* pheader) {
  switch (pheader->type) {
    case PERF_RECORD_MMAP:
      return std::unique_ptr<Record>(new MmapRecord(attr, pheader));
    case PERF_RECORD_MMAP2:
      return std::unique_ptr<Record>(new Mmap2Record(attr, pheader));
    case PERF_RECORD_COMM:
      return std::unique_ptr<Record>(new CommRecord(attr, pheader));
    case PERF_RECORD_EXIT:
      return std::unique_ptr<Record>(new ExitRecord(attr, pheader));
    case PERF_RECORD_FORK:
      return std::unique_ptr<Record>(new ForkRecord(attr, pheader));
    case PERF_RECORD_SAMPLE:
      return std::unique_ptr<Record>(new SampleRecord(attr, pheader));
    default:
      return std::unique_ptr<Record>(new Record(pheader));
  }
}

static bool IsRecordHappensBefore(const std::unique_ptr<Record>& r1,
                                  const std::unique_ptr<Record>& r2) {
  bool is_r1_sample = (r1->header.type == PERF_RECORD_SAMPLE);
  bool is_r2_sample = (r2->header.type == PERF_RECORD_SAMPLE);
  uint64_t time1 = (is_r1_sample ? static_cast<const SampleRecord*>(r1.get())->time_data.time
                                 : r1->sample_id.time_data.time);
  uint64_t time2 = (is_r2_sample ? static_cast<const SampleRecord*>(r2.get())->time_data.time
                                 : r2->sample_id.time_data.time);
  // The record with smaller time happens first.
  if (time1 != time2) {
    return time1 < time2;
  }
  // If happening at the same time, make non-sample records before sample records,
  // because non-sample records may contain useful information to parse sample records.
  if (is_r1_sample != is_r2_sample) {
    return is_r1_sample ? false : true;
  }
  // Otherwise, don't care of the order.
  return false;
}

std::vector<std::unique_ptr<Record>> ReadRecordsFromBuffer(const perf_event_attr& attr,
                                                           const char* buf, size_t buf_size) {
  std::vector<std::unique_ptr<Record>> result;
  const char* p = buf;
  const char* end = buf + buf_size;
  while (p < end) {
    const perf_event_header* header = reinterpret_cast<const perf_event_header*>(p);
    if (p + header->size <= end) {
      result.push_back(ReadRecordFromBuffer(attr, header));
    }
    p += header->size;
  }
  if ((attr.sample_type & PERF_SAMPLE_TIME) && attr.sample_id_all) {
    std::sort(result.begin(), result.end(), IsRecordHappensBefore);
  }
  return result;
}

MmapRecord CreateMmapRecord(const perf_event_attr& attr, bool in_kernel, uint32_t pid, uint32_t tid,
                            uint64_t addr, uint64_t len, uint64_t pgoff,
                            const std::string& filename) {
  MmapRecord record;
  record.header.type = PERF_RECORD_MMAP;
  record.header.misc = (in_kernel ? PERF_RECORD_MISC_KERNEL : PERF_RECORD_MISC_USER);
  record.data.pid = pid;
  record.data.tid = tid;
  record.data.addr = addr;
  record.data.len = len;
  record.data.pgoff = pgoff;
  record.filename = filename;
  size_t sample_id_size = record.sample_id.CreateContent(attr);
  record.header.size = sizeof(record.header) + sizeof(record.data) +
                       ALIGN(record.filename.size() + 1, 8) + sample_id_size;
  return record;
}

CommRecord CreateCommRecord(const perf_event_attr& attr, uint32_t pid, uint32_t tid,
                            const std::string& comm) {
  CommRecord record;
  record.header.type = PERF_RECORD_COMM;
  record.header.misc = 0;
  record.data.pid = pid;
  record.data.tid = tid;
  record.comm = comm;
  size_t sample_id_size = record.sample_id.CreateContent(attr);
  record.header.size = sizeof(record.header) + sizeof(record.data) +
                       ALIGN(record.comm.size() + 1, 8) + sample_id_size;
  return record;
}

ForkRecord CreateForkRecord(const perf_event_attr& attr, uint32_t pid, uint32_t tid, uint32_t ppid,
                            uint32_t ptid) {
  ForkRecord record;
  record.header.type = PERF_RECORD_FORK;
  record.header.misc = 0;
  record.data.pid = pid;
  record.data.ppid = ppid;
  record.data.tid = tid;
  record.data.ptid = ptid;
  record.data.time = 0;
  size_t sample_id_size = record.sample_id.CreateContent(attr);
  record.header.size = sizeof(record.header) + sizeof(record.data) + sample_id_size;
  return record;
}

BuildIdRecord CreateBuildIdRecord(bool in_kernel, pid_t pid, const BuildId& build_id,
                                  const std::string& filename) {
  BuildIdRecord record;
  record.header.type = PERF_RECORD_BUILD_ID;
  record.header.misc = (in_kernel ? PERF_RECORD_MISC_KERNEL : PERF_RECORD_MISC_USER);
  record.pid = pid;
  record.build_id = build_id;
  record.filename = filename;
  record.header.size = sizeof(record.header) + sizeof(record.pid) +
                       ALIGN(record.build_id.Size(), 8) + ALIGN(filename.size() + 1, 64);
  return record;
}
