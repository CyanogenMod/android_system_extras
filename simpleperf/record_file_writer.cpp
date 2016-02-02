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
#include <string>
#include <vector>

#include <android-base/file.h>
#include <android-base/logging.h>

#include "perf_event.h"
#include "record.h"
#include "utils.h"

using namespace PerfFileFormat;

std::unique_ptr<RecordFileWriter> RecordFileWriter::CreateInstance(const std::string& filename) {
  // Remove old perf.data to avoid file ownership problems.
  std::string err;
  if (!android::base::RemoveFileIfExists(filename, &err)) {
    LOG(ERROR) << "failed to remove file " << filename << ": " << err;
    return nullptr;
  }
  FILE* fp = fopen(filename.c_str(), "web+");
  if (fp == nullptr) {
    PLOG(ERROR) << "failed to open record file '" << filename << "'";
    return nullptr;
  }

  return std::unique_ptr<RecordFileWriter>(new RecordFileWriter(filename, fp));
}

RecordFileWriter::RecordFileWriter(const std::string& filename, FILE* fp)
    : filename_(filename),
      record_fp_(fp),
      attr_section_offset_(0),
      attr_section_size_(0),
      data_section_offset_(0),
      data_section_size_(0),
      feature_count_(0),
      current_feature_index_(0) {
}

RecordFileWriter::~RecordFileWriter() {
  if (record_fp_ != nullptr) {
    Close();
  }
}

bool RecordFileWriter::WriteAttrSection(const std::vector<AttrWithId>& attr_ids) {
  if (attr_ids.empty()) {
    return false;
  }

  // Skip file header part.
  if (fseek(record_fp_, sizeof(FileHeader), SEEK_SET) == -1) {
    return false;
  }

  // Write id section.
  long id_section_offset = ftell(record_fp_);
  if (id_section_offset == -1) {
    return false;
  }
  for (auto& attr_id : attr_ids) {
    if (!Write(attr_id.ids.data(), attr_id.ids.size() * sizeof(uint64_t))) {
      return false;
    }
  }

  // Write attr section.
  long attr_section_offset = ftell(record_fp_);
  if (attr_section_offset == -1) {
    return false;
  }
  for (auto& attr_id : attr_ids) {
    FileAttr file_attr;
    file_attr.attr = *attr_id.attr;
    file_attr.ids.offset = id_section_offset;
    file_attr.ids.size = attr_id.ids.size() * sizeof(uint64_t);
    id_section_offset += file_attr.ids.size;
    if (!Write(&file_attr, sizeof(file_attr))) {
      return false;
    }
  }

  long data_section_offset = ftell(record_fp_);
  if (data_section_offset == -1) {
    return false;
  }

  attr_section_offset_ = attr_section_offset;
  attr_section_size_ = data_section_offset - attr_section_offset;
  data_section_offset_ = data_section_offset;

  // Save event_attr for use when reading records.
  event_attr_ = *attr_ids[0].attr;
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

bool RecordFileWriter::SeekFileEnd(uint64_t* file_end) {
  if (fseek(record_fp_, 0, SEEK_END) == -1) {
    PLOG(ERROR) << "fseek() failed";
    return false;
  }
  long offset = ftell(record_fp_);
  if (offset == -1) {
    PLOG(ERROR) << "ftell() failed";
    return false;
  }
  *file_end = static_cast<uint64_t>(offset);
  return true;
}

bool RecordFileWriter::WriteFeatureHeader(size_t feature_count) {
  feature_count_ = feature_count;
  current_feature_index_ = 0;
  uint64_t feature_header_size = feature_count * sizeof(SectionDesc);

  // Reserve enough space in the record file for the feature header.
  std::vector<unsigned char> zero_data(feature_header_size);
  if (fseek(record_fp_, data_section_offset_ + data_section_size_, SEEK_SET) == -1) {
    PLOG(ERROR) << "fseek() failed";
    return false;
  }
  return Write(zero_data.data(), zero_data.size());
}

bool RecordFileWriter::WriteBuildIdFeature(const std::vector<BuildIdRecord>& build_id_records) {
  uint64_t start_offset;
  if (!WriteFeatureBegin(&start_offset)) {
    return false;
  }
  for (auto& record : build_id_records) {
    std::vector<char> data = record.BinaryFormat();
    if (!Write(data.data(), data.size())) {
      return false;
    }
  }
  return WriteFeatureEnd(FEAT_BUILD_ID, start_offset);
}

bool RecordFileWriter::WriteFeatureString(int feature, const std::string& s) {
  uint64_t start_offset;
  if (!WriteFeatureBegin(&start_offset)) {
    return false;
  }
  uint32_t len = static_cast<uint32_t>(ALIGN(s.size() + 1, 64));
  if (!Write(&len, sizeof(len))) {
    return false;
  }
  std::vector<char> v(len, '\0');
  std::copy(s.begin(), s.end(), v.begin());
  if (!Write(v.data(), v.size())) {
    return false;
  }
  return WriteFeatureEnd(feature, start_offset);
}

bool RecordFileWriter::WriteCmdlineFeature(const std::vector<std::string>& cmdline) {
  uint64_t start_offset;
  if (!WriteFeatureBegin(&start_offset)) {
    return false;
  }
  uint32_t arg_count = cmdline.size();
  if (!Write(&arg_count, sizeof(arg_count))) {
    return false;
  }
  for (auto& arg : cmdline) {
    uint32_t len = static_cast<uint32_t>(ALIGN(arg.size() + 1, 64));
    if (!Write(&len, sizeof(len))) {
      return false;
    }
    std::vector<char> array(len, '\0');
    std::copy(arg.begin(), arg.end(), array.begin());
    if (!Write(array.data(), array.size())) {
      return false;
    }
  }
  return WriteFeatureEnd(FEAT_CMDLINE, start_offset);
}

bool RecordFileWriter::WriteBranchStackFeature() {
  uint64_t start_offset;
  if (!WriteFeatureBegin(&start_offset)) {
    return false;
  }
  return WriteFeatureEnd(FEAT_BRANCH_STACK, start_offset);
}

bool RecordFileWriter::WriteFeatureBegin(uint64_t* start_offset) {
  CHECK_LT(current_feature_index_, feature_count_);
  if (!SeekFileEnd(start_offset)) {
    return false;
  }
  return true;
}

bool RecordFileWriter::WriteFeatureEnd(int feature, uint64_t start_offset) {
  uint64_t end_offset;
  if (!SeekFileEnd(&end_offset)) {
    return false;
  }
  SectionDesc desc;
  desc.offset = start_offset;
  desc.size = end_offset - start_offset;
  uint64_t feature_offset = data_section_offset_ + data_section_size_;
  if (fseek(record_fp_, feature_offset + current_feature_index_ * sizeof(SectionDesc), SEEK_SET) ==
      -1) {
    PLOG(ERROR) << "fseek() failed";
    return false;
  }
  if (!Write(&desc, sizeof(SectionDesc))) {
    return false;
  }
  ++current_feature_index_;
  features_.push_back(feature);
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
