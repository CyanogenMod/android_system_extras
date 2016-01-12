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

#include "event_attr.h"
#include "event_type.h"
#include "record.h"
#include "record_equal_test.h"

class RecordTest : public ::testing::Test {
 protected:
  virtual void SetUp() {
    const EventType* type = FindEventTypeByName("cpu-cycles");
    ASSERT_TRUE(type != nullptr);
    event_attr = CreateDefaultPerfEventAttr(*type);
  }

  template <class RecordType>
  void CheckRecordMatchBinary(const RecordType& record);

  perf_event_attr event_attr;
};

template <class RecordType>
void RecordTest::CheckRecordMatchBinary(const RecordType& record) {
  std::vector<char> binary = record.BinaryFormat();
  std::vector<std::unique_ptr<Record>> records =
      ReadRecordsFromBuffer(event_attr, binary.data(), binary.size());
  ASSERT_EQ(1u, records.size());
  CheckRecordEqual(record, *records[0]);
}

TEST_F(RecordTest, MmapRecordMatchBinary) {
  MmapRecord record =
      CreateMmapRecord(event_attr, true, 1, 2, 0x1000, 0x2000, 0x3000, "MmapRecord");
  CheckRecordMatchBinary(record);
}

TEST_F(RecordTest, CommRecordMatchBinary) {
  CommRecord record = CreateCommRecord(event_attr, 1, 2, "CommRecord");
  CheckRecordMatchBinary(record);
}

TEST_F(RecordTest, RecordCache_smoke) {
  event_attr.sample_id_all = 1;
  event_attr.sample_type |= PERF_SAMPLE_TIME;
  RecordCache cache(event_attr, 2, 2);
  MmapRecord r1 = CreateMmapRecord(event_attr, true, 1, 1, 0x100, 0x200, 0x300, "mmap_record1");
  MmapRecord r2 = r1;
  MmapRecord r3 = r1;
  MmapRecord r4 = r1;
  r1.sample_id.time_data.time = 3;
  r2.sample_id.time_data.time = 1;
  r3.sample_id.time_data.time = 4;
  r4.sample_id.time_data.time = 6;
  std::vector<char> buf1 = r1.BinaryFormat();
  std::vector<char> buf2 = r2.BinaryFormat();
  std::vector<char> buf3 = r3.BinaryFormat();
  std::vector<char> buf4 = r4.BinaryFormat();
  // Push r1.
  cache.Push(buf1.data(), buf1.size());
  ASSERT_EQ(nullptr, cache.Pop());
  // Push r2.
  cache.Push(buf2.data(), buf2.size());
  // Pop r2.
  std::unique_ptr<Record> popped_r = cache.Pop();
  ASSERT_TRUE(popped_r != nullptr);
  CheckRecordEqual(r2, *popped_r);
  ASSERT_EQ(nullptr, cache.Pop());
  // Push r3.
  cache.Push(buf3.data(), buf3.size());
  ASSERT_EQ(nullptr, cache.Pop());
  // Push r4.
  cache.Push(buf4.data(), buf4.size());
  // Pop r1.
  popped_r = cache.Pop();
  ASSERT_TRUE(popped_r != nullptr);
  CheckRecordEqual(r1, *popped_r);
  // Pop r3.
  popped_r = cache.Pop();
  ASSERT_TRUE(popped_r != nullptr);
  CheckRecordEqual(r3, *popped_r);
  ASSERT_EQ(nullptr, cache.Pop());
  // Pop r4.
  std::vector<std::unique_ptr<Record>> last_records = cache.PopAll();
  ASSERT_EQ(1u, last_records.size());
  CheckRecordEqual(r4, *last_records[0]);
}

TEST_F(RecordTest, RecordCache_FIFO) {
  event_attr.sample_id_all = 1;
  event_attr.sample_type |= PERF_SAMPLE_TIME;
  RecordCache cache(event_attr, 2, 2);
  std::vector<MmapRecord> records;
  for (size_t i = 0; i < 10; ++i) {
    MmapRecord r = CreateMmapRecord(event_attr, true, 1, i, 0x100, 0x200, 0x300, "mmap_record1");
    records.push_back(r);
    std::vector<char> buf = r.BinaryFormat();
    cache.Push(buf.data(), buf.size());
  }
  std::vector<std::unique_ptr<Record>> out_records = cache.PopAll();
  ASSERT_EQ(records.size(), out_records.size());
  for (size_t i = 0; i < records.size(); ++i) {
    CheckRecordEqual(records[i], *out_records[i]);
  }
}
