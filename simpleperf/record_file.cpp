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

#include "record_file.h"

#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <set>

#include <base/logging.h>

#include "event_fd.h"
#include "perf_event.h"
#include "record.h"
#include "utils.h"

using namespace PerfFileFormat;

std::unique_ptr<RecordFileWriter> RecordFileWriter::CreateInstance(
    const std::string& filename, const perf_event_attr& event_attr,
    const std::vector<std::unique_ptr<EventFd>>& event_fds) {
  FILE* fp = fopen(filename.c_str(), "web+");
  if (fp == nullptr) {
    PLOG(ERROR) << "failed to open record file '" << filename << "'";
    return nullptr;
  }

  auto writer = std::unique_ptr<RecordFileWriter>(new RecordFileWriter(filename, fp));
  if (!writer->WriteAttrSection(event_attr, event_fds)) {
    return nullptr;
  }
  return writer;
}

RecordFileWriter::RecordFileWriter(const std::string& filename, FILE* fp)
    : filename_(filename), record_fp_(fp), data_section_offset_(0), data_section_size_(0) {
}

RecordFileWriter::~RecordFileWriter() {
  if (record_fp_ != nullptr) {
    Close();
  }
}

bool RecordFileWriter::WriteAttrSection(const perf_event_attr& event_attr,
                                        const std::vector<std::unique_ptr<EventFd>>& event_fds) {
  // Skip file header part.
  if (fseek(record_fp_, sizeof(FileHeader), SEEK_SET) == -1) {
    return false;
  }

  // Write id section.
  std::vector<uint64_t> ids;
  for (auto& event_fd : event_fds) {
    ids.push_back(event_fd->Id());
  }
  long id_section_offset = ftell(record_fp_);
  if (id_section_offset == -1) {
    return false;
  }
  if (!Write(ids.data(), ids.size() * sizeof(uint64_t))) {
    return false;
  }

  // Write attr section.
  FileAttr attr;
  attr.attr = event_attr;
  attr.ids.offset = id_section_offset;
  attr.ids.size = ids.size() * sizeof(uint64_t);

  long attr_section_offset = ftell(record_fp_);
  if (attr_section_offset == -1) {
    return false;
  }
  if (!Write(&attr, sizeof(attr))) {
    return false;
  }

  long data_section_offset = ftell(record_fp_);
  if (data_section_offset == -1) {
    return false;
  }

  attr_section_offset_ = attr_section_offset;
  attr_section_size_ = sizeof(attr);
  data_section_offset_ = data_section_offset;

  // Save event_attr for use when reading records.
  event_attr_ = event_attr;
  return true;
}

bool RecordFileWriter::WriteData(const void* buf, size_t len) {
  if (!Write(buf, len)) {
    return false;
  }
  data_section_size_ += len;
  return true;
}

bool RecordFileWriter::Write(const void* buf, size_t len) {
  if (fwrite(buf, len, 1, record_fp_) != 1) {
    PLOG(ERROR) << "failed to write to record file '" << filename_ << "'";
    return false;
  }
  return true;
}

bool RecordFileWriter::WriteFileHeader() {
  FileHeader header;
  memset(&header, 0, sizeof(header));
  memcpy(header.magic, PERF_MAGIC, sizeof(header.magic));
  header.header_size = sizeof(header);
  header.attr_size = sizeof(FileAttr);
  header.attrs.offset = attr_section_offset_;
  header.attrs.size = attr_section_size_;
  header.data.offset = data_section_offset_;
  header.data.size = data_section_size_;
  for (auto& feature : features_) {
    int i = feature / 8;
    int j = feature % 8;
    header.features[i] |= (1 << j);
  }

  if (fseek(record_fp_, 0, SEEK_SET) == -1) {
    return false;
  }
  if (!Write(&header, sizeof(header))) {
    return false;
  }
  return true;
}

bool RecordFileWriter::Close() {
  CHECK(record_fp_ != nullptr);
  bool result = true;

  // Write file header. We gather enough information to write file header only after
  // writing data section and feature section.
  if (!WriteFileHeader()) {
    result = false;
  }

  if (fclose(record_fp_) != 0) {
    PLOG(ERROR) << "failed to close record file '" << filename_ << "'";
    result = false;
  }
  record_fp_ = nullptr;
  return result;
}

std::unique_ptr<RecordFileReader> RecordFileReader::CreateInstance(const std::string& filename) {
  int fd = open(filename.c_str(), O_RDONLY | O_CLOEXEC);
  if (fd == -1) {
    PLOG(ERROR) << "failed to open record file '" << filename << "'";
    return nullptr;
  }
  auto reader = std::unique_ptr<RecordFileReader>(new RecordFileReader(filename, fd));
  if (!reader->MmapFile()) {
    return nullptr;
  }
  return reader;
}

RecordFileReader::RecordFileReader(const std::string& filename, int fd)
    : filename_(filename), record_fd_(fd), mmap_addr_(nullptr), mmap_len_(0) {
}

RecordFileReader::~RecordFileReader() {
  if (record_fd_ != -1) {
    Close();
  }
}

bool RecordFileReader::Close() {
  bool result = true;
  if (munmap(const_cast<char*>(mmap_addr_), mmap_len_) == -1) {
    PLOG(ERROR) << "failed to munmap() record file '" << filename_ << "'";
    result = false;
  }
  if (close(record_fd_) == -1) {
    PLOG(ERROR) << "failed to close record file '" << filename_ << "'";
    result = false;
  }
  record_fd_ = -1;
  return result;
}

bool RecordFileReader::MmapFile() {
  off64_t file_size = lseek64(record_fd_, 0, SEEK_END);
  if (file_size == -1) {
    return false;
  }
  size_t mmap_len = file_size;
  void* mmap_addr = mmap(nullptr, mmap_len, PROT_READ, MAP_SHARED, record_fd_, 0);
  if (mmap_addr == MAP_FAILED) {
    PLOG(ERROR) << "failed to mmap() record file '" << filename_ << "'";
    return false;
  }

  mmap_addr_ = reinterpret_cast<const char*>(mmap_addr);
  mmap_len_ = mmap_len;
  return true;
}

const FileHeader* RecordFileReader::FileHeader() {
  return reinterpret_cast<const struct FileHeader*>(mmap_addr_);
}

std::vector<const FileAttr*> RecordFileReader::AttrSection() {
  std::vector<const FileAttr*> result;
  const struct FileHeader* header = FileHeader();
  size_t attr_count = header->attrs.size / header->attr_size;
  const FileAttr* attr = reinterpret_cast<const FileAttr*>(mmap_addr_ + header->attrs.offset);
  for (size_t i = 0; i < attr_count; ++i) {
    result.push_back(attr++);
  }
  return result;
}

std::vector<uint64_t> RecordFileReader::IdsForAttr(const FileAttr* attr) {
  std::vector<uint64_t> result;
  size_t id_count = attr->ids.size / sizeof(uint64_t);
  const uint64_t* id = reinterpret_cast<const uint64_t*>(mmap_addr_ + attr->ids.offset);
  for (size_t i = 0; i < id_count; ++i) {
    result.push_back(*id++);
  }
  return result;
}

std::vector<std::unique_ptr<const Record>> RecordFileReader::DataSection() {
  std::vector<std::unique_ptr<const Record>> result;
  const struct FileHeader* header = FileHeader();
  auto file_attrs = AttrSection();
  CHECK(file_attrs.size() > 0);
  perf_event_attr attr = file_attrs[0]->attr;

  const char* end = mmap_addr_ + header->data.offset + header->data.size;
  const char* p = mmap_addr_ + header->data.offset;
  while (p < end) {
    const perf_event_header* header = reinterpret_cast<const perf_event_header*>(p);
    if (p + header->size <= end) {
      result.push_back(std::move(ReadRecordFromBuffer(attr, header)));
    }
    p += header->size;
  }
  return result;
}
