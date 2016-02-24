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

#include "command.h"
#include "test_util.h"

class DumpRecordCommandTest : public ::testing::Test {
 protected:
  virtual void SetUp() {
    record_cmd = CreateCommandInstance("record");
    ASSERT_TRUE(record_cmd != nullptr);
    dumprecord_cmd = CreateCommandInstance("dump");
    ASSERT_TRUE(dumprecord_cmd != nullptr);
  }

  std::unique_ptr<Command> record_cmd;
  std::unique_ptr<Command> dumprecord_cmd;
};

TEST_F(DumpRecordCommandTest, no_options) {
  ASSERT_TRUE(record_cmd->Run({"-a", "sleep", SLEEP_SEC}));
  ASSERT_TRUE(dumprecord_cmd->Run({}));
}

TEST_F(DumpRecordCommandTest, record_file_option) {
  ASSERT_TRUE(record_cmd->Run({"-a", "-o", "perf2.data", "sleep", SLEEP_SEC}));
  ASSERT_TRUE(dumprecord_cmd->Run({"perf2.data"}));
}
