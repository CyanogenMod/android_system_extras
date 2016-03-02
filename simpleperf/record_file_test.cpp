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

#include <gtest/gtest.h>

#include <string.h>

#include <memory>

#include <android-base/test_utils.h>

#include "environment.h"
#include "event_attr.h"
#include "event_type.h"
#include "record.h"
#include "record_file.h"

#include "record_equal_test.h"

using namespace PerfFileFormat;

class RecordFileTest : public ::testing::Test {
 protected:
  void AddEventType(const std::string& event_type_str) {
    std::unique_ptr<EventTypeAndModifier> event_type_modifier = ParseEventType(event_type_str);
    ASSERT_TRUE(event_type_modifier != nullptr);
    perf_event_attr attr = CreateDefaultPerfEventAttr(event_type_modifier->event_type);
    attrs_.push_back(std::unique_ptr<perf_event_attr>(new perf_event_attr(attr)));
    AttrWithId attr_id;
    attr_id.attr = attrs_.back().get();
    attr_id.ids.push_back(attrs_.size());  // Fake id.
    attr_ids_.push_back(attr_id);
  }

  TemporaryFile tmpfile_;
  std::vector<std::unique_ptr<perf_event_attr>> attrs_;
  std::vector<AttrWithId> attr_ids_;
};

TEST_F(RecordFileTest, smoke) {
  // Write to a record file.
  std::unique_ptr<RecordFileWriter> writer = RecordFileWriter::CreateInstance(tmpfile_.path);
  ASSERT_TRUE(writer != nullptr);

  // Write attr section.
  AddEventType("cpu-cycles");
  ASSERT_TRUE(writer->WriteAttrSection(attr_ids_));

  // Write data section.
  MmapRecord mmap_record = CreateMmapRecord(*(attr_ids_[0].attr), true, 1, 1, 0x1000, 0x2000,
                                            0x3000, "mmap_record_example");
  ASSERT_TRUE(writer->WriteData(mmap_record.BinaryFormat()));

  // Write feature section.
  ASSERT_TRUE(writer->WriteFeatureHeader(1));
  char p[BuildId::Size()];
  for (size_t i = 0; i < BuildId::Size(); ++i) {
    p[i] = i;
  }
  BuildId build_id(p);
  BuildIdRecord build_id_record = CreateBuildIdRecord(false, getpid(), build_id, "init");
  ASSERT_TRUE(writer->WriteBuildIdFeature({build_id_record}));
  ASSERT_TRUE(writer->Close());

  // Read from a record file.
  std::unique_ptr<RecordFileReader> reader = RecordFileReader::CreateInstance(tmpfile_.path);
  ASSERT_TRUE(reader != nullptr);
  const std::vector<FileAttr>& file_attrs = reader->AttrSection();
  ASSERT_EQ(1u, file_attrs.size());
  ASSERT_EQ(0, memcmp(&file_attrs[0].attr, attr_ids_[0].attr, sizeof(perf_event_attr)));
  std::vector<uint64_t> ids;
  ASSERT_TRUE(reader->ReadIdsForAttr(file_attrs[0], &ids));
  ASSERT_EQ(ids, attr_ids_[0].ids);

  // Read and check data section.
  std::vector<std::unique_ptr<Record>> records = reader->DataSection();
  ASSERT_EQ(1u, records.size());
  CheckRecordEqual(mmap_record, *records[0]);

  // Read and check feature section.
  std::vector<BuildIdRecord> build_id_records = reader->ReadBuildIdFeature();
  ASSERT_EQ(1u, build_id_records.size());
  CheckRecordEqual(build_id_record, build_id_records[0]);

  ASSERT_TRUE(reader->Close());
}

TEST_F(RecordFileTest, records_sorted_by_time) {
  // Write to a record file.
  std::unique_ptr<RecordFileWriter> writer = RecordFileWriter::CreateInstance(tmpfile_.path);
  ASSERT_TRUE(writer != nullptr);

  // Write attr section.
  AddEventType("cpu-cycles");
  attrs_[0]->sample_id_all = 1;
  attrs_[0]->sample_type |= PERF_SAMPLE_TIME;
  ASSERT_TRUE(writer->WriteAttrSection(attr_ids_));

  // Write data section.
  MmapRecord r1 =
      CreateMmapRecord(*(attr_ids_[0].attr), true, 1, 1, 0x100, 0x2000, 0x3000, "mmap_record1");
  MmapRecord r2 = r1;
  MmapRecord r3 = r1;
  r1.sample_id.time_data.time = 2;
  r2.sample_id.time_data.time = 1;
  r3.sample_id.time_data.time = 3;
  ASSERT_TRUE(writer->WriteData(r1.BinaryFormat()));
  ASSERT_TRUE(writer->WriteData(r2.BinaryFormat()));
  ASSERT_TRUE(writer->WriteData(r3.BinaryFormat()));
  ASSERT_TRUE(writer->Close());

  // Read from a record file.
  std::unique_ptr<RecordFileReader> reader = RecordFileReader::CreateInstance(tmpfile_.path);
  ASSERT_TRUE(reader != nullptr);
  std::vector<std::unique_ptr<Record>> records = reader->DataSection();
  ASSERT_EQ(3u, records.size());
  CheckRecordEqual(r2, *records[0]);
  CheckRecordEqual(r1, *records[1]);
  CheckRecordEqual(r3, *records[2]);

  ASSERT_TRUE(reader->Close());
}

TEST_F(RecordFileTest, record_more_than_one_attr) {
  // Write to a record file.
  std::unique_ptr<RecordFileWriter> writer = RecordFileWriter::CreateInstance(tmpfile_.path);
  ASSERT_TRUE(writer != nullptr);

  // Write attr section.
  AddEventType("cpu-cycles");
  AddEventType("cpu-clock");
  AddEventType("task-clock");
  ASSERT_TRUE(writer->WriteAttrSection(attr_ids_));

  ASSERT_TRUE(writer->Close());

  // Read from a record file.
  std::unique_ptr<RecordFileReader> reader = RecordFileReader::CreateInstance(tmpfile_.path);
  ASSERT_TRUE(reader != nullptr);
  const std::vector<FileAttr>& file_attrs = reader->AttrSection();
  ASSERT_EQ(3u, file_attrs.size());
  for (size_t i = 0; i < file_attrs.size(); ++i) {
    ASSERT_EQ(0, memcmp(&file_attrs[i].attr, attr_ids_[i].attr, sizeof(perf_event_attr)));
    std::vector<uint64_t> ids;
    ASSERT_TRUE(reader->ReadIdsForAttr(file_attrs[i], &ids));
    ASSERT_EQ(ids, attr_ids_[i].ids);
  }
}
