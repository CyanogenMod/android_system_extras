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

#include <android-base/logging.h>
#include <android-base/stringprintf.h>

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

template <class T>
void MoveToBinaryFormat(const T* data_p, size_t n, char*& p) {
  size_t size = n * sizeof(T);
  memcpy(p, data_p, size);
  p += size;
}

SampleId::SampleId() {
  memset(this, 0, sizeof(SampleId));
}

// Return sample_id size in binary format.
size_t SampleId::CreateContent(const perf_event_attr& attr) {
  sample_id_all = attr.sample_id_all;
  sample_type = attr.sample_type;
  // Other data are not necessary. TODO: Set missing SampleId data.
  return Size();
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

size_t SampleId::Size() const {
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

uint64_t Record::Timestamp() const {
  return sample_id.time_data.time;
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

void MmapRecord::AdjustSizeBasedOnData() {
  header.size = sizeof(header) + sizeof(data) + ALIGN(filename.size() + 1, 8) + sample_id.Size();
}

void MmapRecord::DumpData(size_t indent) const {
  PrintIndented(indent, "pid %u, tid %u, addr 0x%" PRIx64 ", len 0x%" PRIx64 "\n", data.pid,
                data.tid, data.addr, data.len);
  PrintIndented(indent, "pgoff 0x%" PRIx64 ", filename %s\n", data.pgoff, filename.c_str());
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

std::vector<char> Mmap2Record::BinaryFormat() const {
  std::vector<char> buf(header.size);
  char* p = buf.data();
  MoveToBinaryFormat(header, p);
  MoveToBinaryFormat(data, p);
  strcpy(p, filename.c_str());
  p += ALIGN(filename.size() + 1, 8);
  sample_id.WriteToBinaryFormat(p);
  return buf;
}

void Mmap2Record::AdjustSizeBasedOnData() {
  header.size = sizeof(header) + sizeof(data) + ALIGN(filename.size() + 1, 8) + sample_id.Size();
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

void CommRecord::DumpData(size_t indent) const {
  PrintIndented(indent, "pid %u, tid %u, comm %s\n", data.pid, data.tid, comm.c_str());
}

ExitOrForkRecord::ExitOrForkRecord(const perf_event_attr& attr, const perf_event_header* pheader)
    : Record(pheader) {
  const char* p = reinterpret_cast<const char*>(pheader + 1);
  const char* end = reinterpret_cast<const char*>(pheader) + pheader->size;
  MoveFromBinaryFormat(data, p);
  CHECK_LE(p, end);
  sample_id.ReadFromBinaryFormat(attr, p, end);
}

std::vector<char> ExitOrForkRecord::BinaryFormat() const {
  std::vector<char> buf(header.size);
  char* p = buf.data();
  MoveToBinaryFormat(header, p);
  MoveToBinaryFormat(data, p);
  sample_id.WriteToBinaryFormat(p);
  return buf;
}

void ExitOrForkRecord::DumpData(size_t indent) const {
  PrintIndented(indent, "pid %u, ppid %u, tid %u, ptid %u\n", data.pid, data.ppid, data.tid,
                data.ptid);
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
  if (sample_type & PERF_SAMPLE_RAW) {
    uint32_t size;
    MoveFromBinaryFormat(size, p);
    raw_data.data.resize(size);
    MoveFromBinaryFormat(raw_data.data.data(), size, p);
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

std::vector<char> SampleRecord::BinaryFormat() const {
  std::vector<char> buf(header.size);
  char* p = buf.data();
  MoveToBinaryFormat(header, p);
  if (sample_type & PERF_SAMPLE_IP) {
    MoveToBinaryFormat(ip_data, p);
  }
  if (sample_type & PERF_SAMPLE_TID) {
    MoveToBinaryFormat(tid_data, p);
  }
  if (sample_type & PERF_SAMPLE_TIME) {
    MoveToBinaryFormat(time_data, p);
  }
  if (sample_type & PERF_SAMPLE_ADDR) {
    MoveToBinaryFormat(addr_data, p);
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
  if (sample_type & PERF_SAMPLE_PERIOD) {
    MoveToBinaryFormat(period_data, p);
  }
  if (sample_type & PERF_SAMPLE_CALLCHAIN) {
    uint64_t nr = callchain_data.ips.size();
    MoveToBinaryFormat(nr, p);
    MoveToBinaryFormat(callchain_data.ips.data(), nr, p);
  }
  if (sample_type & PERF_SAMPLE_RAW) {
    uint32_t size = raw_data.data.size();
    MoveToBinaryFormat(size, p);
    MoveToBinaryFormat(raw_data.data.data(), size, p);
  }
  if (sample_type & PERF_SAMPLE_BRANCH_STACK) {
    uint64_t nr = branch_stack_data.stack.size();
    MoveToBinaryFormat(nr, p);
    MoveToBinaryFormat(branch_stack_data.stack.data(), nr, p);
  }
  if (sample_type & PERF_SAMPLE_REGS_USER) {
    MoveToBinaryFormat(regs_user_data.abi, p);
    if (regs_user_data.abi != 0) {
      MoveToBinaryFormat(regs_user_data.regs.data(), regs_user_data.regs.size(), p);
    }
  }
  if (sample_type & PERF_SAMPLE_STACK_USER) {
    uint64_t size = stack_user_data.data.size();
    MoveToBinaryFormat(size, p);
    if (size != 0) {
      MoveToBinaryFormat(stack_user_data.data.data(), size, p);
      MoveToBinaryFormat(stack_user_data.dyn_size, p);
    }
  }

  // If record command does stack unwinding, sample records' size may be decreased.
  // So we can't trust header.size here, and should adjust buffer size based on real need.
  buf.resize(p - buf.data());
  return buf;
}

void SampleRecord::AdjustSizeBasedOnData() {
  size_t size = BinaryFormat().size();
  LOG(DEBUG) << "Record (type " << RecordTypeToString(header.type) << ") size is changed from "
      << header.size << " to " << size;
  header.size = size;
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
  if (sample_type & PERF_SAMPLE_RAW) {
    PrintIndented(indent, "raw size=%zu\n", raw_data.data.size());
    const uint32_t* data = reinterpret_cast<const uint32_t*>(raw_data.data.data());
    size_t size = raw_data.data.size() / sizeof(uint32_t);
    for (size_t i = 0; i < size; ++i) {
      PrintIndented(indent + 1, "0x%08x (%zu)\n", data[i], data[i]);
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
        PrintIndented(indent + 1, "reg (%s) 0x%016" PRIx64 "\n",
                      GetRegName(i, ScopedCurrentArch::GetCurrentArch()).c_str(),
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

uint64_t SampleRecord::Timestamp() const {
  return time_data.time;
}

BuildIdRecord::BuildIdRecord(const perf_event_header* pheader) : Record(pheader) {
  const char* p = reinterpret_cast<const char*>(pheader + 1);
  const char* end = reinterpret_cast<const char*>(pheader) + pheader->size;
  MoveFromBinaryFormat(pid, p);
  build_id = BuildId(p, BUILD_ID_SIZE);
  p += ALIGN(build_id.Size(), 8);
  filename = p;
  p += ALIGN(filename.size() + 1, 64);
  CHECK_EQ(p, end);
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

void BuildIdRecord::DumpData(size_t indent) const {
  PrintIndented(indent, "pid %u\n", pid);
  PrintIndented(indent, "build_id %s\n", build_id.ToString().c_str());
  PrintIndented(indent, "filename %s\n", filename.c_str());
}

UnknownRecord::UnknownRecord(const perf_event_header* pheader) : Record(pheader) {
  const char* p = reinterpret_cast<const char*>(pheader + 1);
  const char* end = reinterpret_cast<const char*>(pheader) + pheader->size;
  data.insert(data.end(), p, end);
}

std::vector<char> UnknownRecord::BinaryFormat() const {
  std::vector<char> buf(header.size);
  char* p = buf.data();
  MoveToBinaryFormat(header, p);
  MoveToBinaryFormat(data.data(), data.size(), p);
  return buf;
}

void UnknownRecord::DumpData(size_t) const {
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
      return std::unique_ptr<Record>(new UnknownRecord(pheader));
  }
}

std::vector<std::unique_ptr<Record>> ReadRecordsFromBuffer(const perf_event_attr& attr,
                                                           const char* buf, size_t buf_size) {
  std::vector<std::unique_ptr<Record>> result;
  const char* p = buf;
  const char* end = buf + buf_size;
  while (p < end) {
    const perf_event_header* header = reinterpret_cast<const perf_event_header*>(p);
    CHECK_LE(p + header->size, end);
    CHECK_NE(0u, header->size);
    result.push_back(ReadRecordFromBuffer(attr, header));
    p += header->size;
  }
  return result;
}

std::unique_ptr<Record> ReadRecordFromFile(const perf_event_attr& attr, FILE* fp) {
  std::vector<char> buf(sizeof(perf_event_header));
  perf_event_header* header = reinterpret_cast<perf_event_header*>(&buf[0]);
  if (fread(header, sizeof(perf_event_header), 1, fp) != 1) {
    PLOG(ERROR) << "Failed to read record file";
    return nullptr;
  }
  buf.resize(header->size);
  header = reinterpret_cast<perf_event_header*>(&buf[0]);
  if (fread(&buf[sizeof(perf_event_header)], buf.size() - sizeof(perf_event_header), 1, fp) != 1) {
    PLOG(ERROR) << "Failed to read record file";
    return nullptr;
  }
  return ReadRecordFromBuffer(attr, header);
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

bool RecordCache::RecordWithSeq::IsHappensBefore(const RecordWithSeq& other) const {
  bool is_sample = (record->header.type == PERF_RECORD_SAMPLE);
  bool is_other_sample = (other.record->header.type == PERF_RECORD_SAMPLE);
  uint64_t time = record->Timestamp();
  uint64_t other_time = other.record->Timestamp();
  // The record with smaller time happens first.
  if (time != other_time) {
    return time < other_time;
  }
  // If happening at the same time, make non-sample records before sample records,
  // because non-sample records may contain useful information to parse sample records.
  if (is_sample != is_other_sample) {
    return is_sample ? false : true;
  }
  // Otherwise, use the same order as they enter the cache.
  return seq < other.seq;
}

bool RecordCache::RecordComparator::operator()(const RecordWithSeq& r1,
                                               const RecordWithSeq& r2) {
  return r2.IsHappensBefore(r1);
}

RecordCache::RecordCache(const perf_event_attr& attr, size_t min_cache_size,
                         uint64_t min_time_diff_in_ns)
    : attr_(attr),
      has_timestamp_(attr.sample_id_all && (attr.sample_type & PERF_SAMPLE_TIME)),
      min_cache_size_(min_cache_size),
      min_time_diff_in_ns_(min_time_diff_in_ns),
      last_time_(0),
      cur_seq_(0),
      queue_(RecordComparator()) {
}

RecordCache::~RecordCache() {
  PopAll();
}

void RecordCache::Push(const char* data, size_t size) {
  std::vector<std::unique_ptr<Record>> records = ReadRecordsFromBuffer(attr_, data, size);
  if (has_timestamp_) {
    for (const auto& r : records) {
      last_time_ = std::max(last_time_, r->Timestamp());
    }
  }
  for (auto& r : records) {
    queue_.push(CreateRecordWithSeq(r.release()));
  }
}

void RecordCache::Push(std::unique_ptr<Record> record) {
  queue_.push(CreateRecordWithSeq(record.release()));
}

std::unique_ptr<Record> RecordCache::Pop() {
  if (queue_.size() < min_cache_size_) {
    return nullptr;
  }
  Record* r = queue_.top().record;
  if (has_timestamp_) {
    if (r->Timestamp() + min_time_diff_in_ns_ > last_time_) {
      return nullptr;
    }
  }
  queue_.pop();
  return std::unique_ptr<Record>(r);
}

std::vector<std::unique_ptr<Record>> RecordCache::PopAll() {
  std::vector<std::unique_ptr<Record>> result;
  while (!queue_.empty()) {
    result.emplace_back(queue_.top().record);
    queue_.pop();
  }
  return result;
}

RecordCache::RecordWithSeq RecordCache::CreateRecordWithSeq(Record *r) {
  RecordWithSeq result;
  result.seq = cur_seq_++;
  result.record = r;
  return result;
}
