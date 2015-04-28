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

#include <command.h>

class RecordCommandTest : public ::testing::Test {
 protected:
  virtual void SetUp() {
    record_cmd = Command::FindCommandByName("record");
    ASSERT_TRUE(record_cmd != nullptr);
  }

  Command* record_cmd;
};

TEST_F(RecordCommandTest, no_options) {
  ASSERT_TRUE(record_cmd->Run({"record", "sleep", "1"}));
}

TEST_F(RecordCommandTest, system_wide_option) {
  ASSERT_TRUE(record_cmd->Run({"record", "-a", "sleep", "1"}));
}

TEST_F(RecordCommandTest, sample_period_option) {
  ASSERT_TRUE(record_cmd->Run({"record", "-c", "100000", "sleep", "1"}));
}

TEST_F(RecordCommandTest, event_option) {
  ASSERT_TRUE(record_cmd->Run({"record", "-e", "cpu-clock", "sleep", "1"}));
}

TEST_F(RecordCommandTest, freq_option) {
  ASSERT_TRUE(record_cmd->Run({"record", "-f", "99", "sleep", "1"}));
  ASSERT_TRUE(record_cmd->Run({"record", "-F", "99", "sleep", "1"}));
}

TEST_F(RecordCommandTest, output_file_option) {
  ASSERT_TRUE(record_cmd->Run({"record", "-o", "perf2.data", "sleep", "1"}));
}
