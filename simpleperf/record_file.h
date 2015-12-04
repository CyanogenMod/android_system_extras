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

#ifndef SIMPLE_PERF_RECORD_FILE_H_
#define SIMPLE_PERF_RECORD_FILE_H_

#include <stdio.h>

#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include <android-base/macros.h>

#include "perf_event.h"
#include "record.h"
#include "record_file_format.h"

struct AttrWithId {
  const perf_event_attr* attr;
  std::vector<uint64_t> ids;
};

// RecordFileWriter writes to a perf record file, like perf.data.
class RecordFileWriter {
 public:
  static std::unique_ptr<RecordFileWriter> CreateInstance(const std::string& filename);

  ~RecordFileWriter();

  bool WriteAttrSection(const std::vector<AttrWithId>& attr_ids);
  bool WriteData(const void* buf, size_t len);

  bool WriteData(const std::vector<char>& data) {
    return WriteData(data.data(), data.size());
  }

  bool WriteFeatureHeader(size_t feature_count);
  bool WriteBuildIdFeature(const std::vector<BuildIdRecord>& build_id_records);
  bool WriteFeatureString(int feature, const std::string& s);
  bool WriteCmdlineFeature(const std::vector<std::string>& cmdline);
  bool WriteBranchStackFeature();

  // Normally, Close() should be called after writing. But if something
  // wrong happens and we need to finish in advance, the destructor
  // will take care of calling Close().
  bool Close();

 private:
  RecordFileWriter(const std::string& filename, FILE* fp);
  void GetHitModulesInBuffer(const char* p, const char* end,
                             std::vector<std::string>* hit_kernel_modules,
                             std::vector<std::string>* hit_user_files);
  bool WriteFileHeader();
  bool Write(const void* buf, size_t len);
  bool SeekFileEnd(uint64_t* file_end);
  bool WriteFeatureBegin(uint64_t* start_offset);
  bool WriteFeatureEnd(int feature, uint64_t start_offset);

  const std::string filename_;
  FILE* record_fp_;

  perf_event_attr event_attr_;
  uint64_t attr_section_offset_;
  uint64_t attr_section_size_;
  uint64_t data_section_offset_;
  uint64_t data_section_size_;

  std::vector<int> features_;
  int feature_count_;
  int current_feature_index_;

  DISALLOW_COPY_AND_ASSIGN(RecordFileWriter);
};

// RecordFileReader read contents from a perf record file, like perf.data.
class RecordFileReader {
 public:
  static std::unique_ptr<RecordFileReader> CreateInstance(const std::string& filename);

  ~RecordFileReader();

  const PerfFileFormat::FileHeader& FileHeader() const {
    return header_;
  }

  const std::vector<PerfFileFormat::FileAttr>& AttrSection() const {
    return file_attrs_;
  }

  const std::map<int, PerfFileFormat::SectionDesc>& FeatureSectionDescriptors() const {
    return feature_section_descriptors_;
  }

  bool ReadIdsForAttr(const PerfFileFormat::FileAttr& attr, std::vector<uint64_t>* ids);
  // If sorted is true, sort records before passing them to callback function.
  bool ReadDataSection(std::function<bool(std::unique_ptr<Record>)> callback, bool sorted = true);
  std::vector<std::string> ReadCmdlineFeature();
  std::vector<BuildIdRecord> ReadBuildIdFeature();
  std::string ReadFeatureString(int feature);
  bool Close();

  // For testing only.
  std::vector<std::unique_ptr<Record>> DataSection();

 private:
  RecordFileReader(const std::string& filename, FILE* fp);
  bool ReadHeader();
  bool ReadAttrSection();
  bool ReadFeatureSectionDescriptors();
  bool ReadFeatureSection(int feature, std::vector<char>* data);

  const std::string filename_;
  FILE* record_fp_;

  PerfFileFormat::FileHeader header_;
  std::vector<PerfFileFormat::FileAttr> file_attrs_;
  std::map<int, PerfFileFormat::SectionDesc> feature_section_descriptors_;

  DISALLOW_COPY_AND_ASSIGN(RecordFileReader);
};

#endif  // SIMPLE_PERF_RECORD_FILE_H_
