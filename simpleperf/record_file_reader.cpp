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
#include <set>
#include <vector>

#include <android-base/logging.h>

#include "perf_event.h"
#include "record.h"
#include "utils.h"

using namespace PerfFileFormat;

std::unique_ptr<RecordFileReader> RecordFileReader::CreateInstance(const std::string& filename) {
  std::string mode = std::string("rb") + CLOSE_ON_EXEC_MODE;
  FILE* fp = fopen(filename.c_str(), mode.c_str());
  if (fp == nullptr) {
    PLOG(ERROR) << "failed to open record file '" << filename << "'";
    return nullptr;
  }
  auto reader = std::unique_ptr<RecordFileReader>(new RecordFileReader(filename, fp));
  if (!reader->ReadHeader() || !reader->ReadAttrSection() ||
      !reader->ReadFeatureSectionDescriptors()) {
    return nullptr;
  }
  return reader;
}

RecordFileReader::RecordFileReader(const std::string& filename, FILE* fp)
    : filename_(filename), record_fp_(fp) {
}

RecordFileReader::~RecordFileReader() {
  if (record_fp_ != nullptr) {
    Close();
  }
}

bool RecordFileReader::Close() {
  bool result = true;
  if (fclose(record_fp_) != 0) {
    PLOG(ERROR) << "failed to close record file '" << filename_ << "'";
    result = false;
  }
  record_fp_ = nullptr;
  return result;
}

bool RecordFileReader::ReadHeader() {
  if (fread(&header_, sizeof(header_), 1, record_fp_) != 1) {
    PLOG(ERROR) << "failed to read file " << filename_;
    return false;
  }
  return true;
}

bool RecordFileReader::ReadAttrSection() {
  size_t attr_count = header_.attrs.size / header_.attr_size;
  if (header_.attr_size != sizeof(FileAttr)) {
    LOG(DEBUG) << "attr size (" << header_.attr_size << ") in " << filename_
                 << " doesn't match expected size (" << sizeof(FileAttr) << ")";
  }
  if (attr_count == 0) {
    LOG(ERROR) << "no attr in file " << filename_;
    return false;
  }
  if (fseek(record_fp_, header_.attrs.offset, SEEK_SET) != 0) {
    PLOG(ERROR) << "failed to fseek()";
    return false;
  }
  for (size_t i = 0; i < attr_count; ++i) {
    std::vector<char> buf(header_.attr_size);
    if (fread(&buf[0], buf.size(), 1, record_fp_) != 1) {
      PLOG(ERROR) << "failed to read " << filename_;
      return false;
    }
    // The size of perf_event_attr is changing between different linux kernel versions.
    // Make sure we copy correct data to memory.
    FileAttr attr;
    memset(&attr, 0, sizeof(attr));
    size_t section_desc_size = sizeof(attr.ids);
    size_t perf_event_attr_size = header_.attr_size - section_desc_size;
    memcpy(&attr.attr, &buf[0], std::min(sizeof(attr.attr), perf_event_attr_size));
    memcpy(&attr.ids, &buf[perf_event_attr_size], section_desc_size);
    file_attrs_.push_back(attr);
  }
  return true;
}

bool RecordFileReader::ReadFeatureSectionDescriptors() {
  std::vector<int> features;
  for (size_t i = 0; i < sizeof(header_.features); ++i) {
    for (size_t j = 0; j < 8; ++j) {
      if (header_.features[i] & (1 << j)) {
        features.push_back(i * 8 + j);
      }
    }
  }
  uint64_t feature_section_offset = header_.data.offset + header_.data.size;
  if (fseek(record_fp_, feature_section_offset, SEEK_SET) != 0) {
    PLOG(ERROR) << "failed to fseek()";
    return false;
  }
  for (const auto& id : features) {
    SectionDesc desc;
    if (fread(&desc, sizeof(desc), 1, record_fp_) != 1) {
      PLOG(ERROR) << "failed to read " << filename_;
      return false;
    }
    feature_section_descriptors_.emplace(id, desc);
  }
  return true;
}

bool RecordFileReader::ReadIdsForAttr(const FileAttr& attr, std::vector<uint64_t>* ids) {
  size_t id_count = attr.ids.size / sizeof(uint64_t);
  if (fseek(record_fp_, attr.ids.offset, SEEK_SET) != 0) {
    PLOG(ERROR) << "failed to fseek()";
    return false;
  }
  ids->resize(id_count);
  if (fread(ids->data(), attr.ids.size, 1, record_fp_) != 1) {
    PLOG(ERROR) << "failed to read file " << filename_;
    return false;
  }
  return true;
}

bool RecordFileReader::ReadDataSection(std::function<bool(std::unique_ptr<Record>)> callback,
                                       bool sorted) {
  if (fseek(record_fp_, header_.data.offset, SEEK_SET) != 0) {
    PLOG(ERROR) << "failed to fseek()";
    return false;
  }
  RecordCache cache(file_attrs_[0].attr);
  for (size_t nbytes_read = 0; nbytes_read < header_.data.size;) {
    std::unique_ptr<Record> record = ReadRecordFromFile(file_attrs_[0].attr, record_fp_);
    if (record == nullptr) {
      return false;
    }
    nbytes_read += record->size();
    if (sorted) {
      cache.Push(std::move(record));
      record = cache.Pop();
      if (record != nullptr) {
        if (!callback(std::move(record))) {
          return false;
        }
      }
    } else {
      if (!callback(std::move(record))) {
        return false;
      }
    }
  }
  std::vector<std::unique_ptr<Record>> records = cache.PopAll();
  for (auto& record : records) {
    if (!callback(std::move(record))) {
      return false;
    }
  }
  return true;
}

bool RecordFileReader::ReadFeatureSection(int feature, std::vector<char>* data) {
  const std::map<int, SectionDesc>& section_map = FeatureSectionDescriptors();
  auto it = section_map.find(feature);
  if (it == section_map.end()) {
    return false;
  }
  SectionDesc section = it->second;
  data->resize(section.size);
  if (fseek(record_fp_, section.offset, SEEK_SET) != 0) {
    PLOG(ERROR) << "failed to fseek()";
    return false;
  }
  if (fread(data->data(), data->size(), 1, record_fp_) != 1) {
    PLOG(ERROR) << "failed to read " << filename_;
    return false;
  }
  return true;
}

std::vector<std::string> RecordFileReader::ReadCmdlineFeature() {
  std::vector<char> buf;
  if (!ReadFeatureSection(FEAT_CMDLINE, &buf)) {
    return std::vector<std::string>();
  }
  const char* p = buf.data();
  const char* end = buf.data() + buf.size();
  std::vector<std::string> cmdline;
  uint32_t arg_count;
  MoveFromBinaryFormat(arg_count, p);
  CHECK_LE(p, end);
  for (size_t i = 0; i < arg_count; ++i) {
    uint32_t len;
    MoveFromBinaryFormat(len, p);
    CHECK_LE(p + len, end);
    cmdline.push_back(p);
    p += len;
  }
  return cmdline;
}

std::vector<BuildIdRecord> RecordFileReader::ReadBuildIdFeature() {
  std::vector<char> buf;
  if (!ReadFeatureSection(FEAT_BUILD_ID, &buf)) {
    return std::vector<BuildIdRecord>();
  }
  const char* p = buf.data();
  const char* end = buf.data() + buf.size();
  std::vector<BuildIdRecord> result;
  while (p < end) {
    const perf_event_header* header = reinterpret_cast<const perf_event_header*>(p);
    CHECK_LE(p + header->size, end);
    BuildIdRecord record(header);
    // Set type explicitly as the perf.data produced by perf doesn't set it.
    record.header.type = PERF_RECORD_BUILD_ID;
    result.push_back(record);
    p += header->size;
  }
  return result;
}

std::string RecordFileReader::ReadFeatureString(int feature) {
  std::vector<char> buf;
  if (!ReadFeatureSection(feature, &buf)) {
    return std::string();
  }
  const char* p = buf.data();
  const char* end = buf.data() + buf.size();
  uint32_t len;
  MoveFromBinaryFormat(len, p);
  CHECK_LE(p + len, end);
  return p;
}

std::vector<std::unique_ptr<Record>> RecordFileReader::DataSection() {
  std::vector<std::unique_ptr<Record>> records;
  ReadDataSection([&](std::unique_ptr<Record> record) {
    records.push_back(std::move(record));
    return true;
  });
  return records;
}
