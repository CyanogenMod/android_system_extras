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
