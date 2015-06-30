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

static std::unique_ptr<Command> RecordCmd() {
  return CreateCommandInstance("record");
}

static std::unique_ptr<Command> ReportCmd() {
  return CreateCommandInstance("report");
}

class ReportCommandTest : public ::testing::Test {
 protected:
  static void SetUpTestCase() {
    ASSERT_TRUE(RecordCmd()->Run({"-a", "sleep", "1"}));
    ASSERT_TRUE(RecordCmd()->Run({"-a", "-o", "perf2.data", "sleep", "1"}));
  }
};

TEST_F(ReportCommandTest, no_options) {
  ASSERT_TRUE(ReportCmd()->Run({}));
}

TEST_F(ReportCommandTest, input_file_option) {
  ASSERT_TRUE(ReportCmd()->Run({"-i", "perf2.data"}));
}

TEST_F(ReportCommandTest, sort_option_pid) {
  ASSERT_TRUE(ReportCmd()->Run({"--sort", "pid"}));
}

TEST_F(ReportCommandTest, sort_option_all) {
  ASSERT_TRUE(ReportCmd()->Run({"--sort", "comm,pid,dso,symbol"}));
}

extern bool IsBranchSamplingSupported();

TEST(report_cmd, use_branch_address) {
  if (IsBranchSamplingSupported()) {
    ASSERT_TRUE(RecordCmd()->Run({"-b", "sleep", "1"}));
    ASSERT_TRUE(
        ReportCmd()->Run({"-b", "--sort", "comm,pid,dso_from,symbol_from,dso_to,symbol_to"}));
  } else {
    GTEST_LOG_(INFO)
        << "This test does nothing as branch stack sampling is not supported on this device.";
  }
}

TEST(report_cmd, children_option) {
  ASSERT_TRUE(RecordCmd()->Run({"-g", "sleep", "1"}));
  ASSERT_TRUE(ReportCmd()->Run({"--children"}));
}
