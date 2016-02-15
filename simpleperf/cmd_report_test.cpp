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

#include <android-base/file.h>
#include <android-base/test_utils.h>

#include "command.h"
#include "event_selection_set.h"
#include "get_test_data.h"
#include "read_apk.h"

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
    ASSERT_TRUE(RecordCmd()->Run({"--call-graph", "fp", "-o", "perf_g.data", "sleep", "1"}));
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

TEST_F(ReportCommandTest, children_option) {
  ASSERT_TRUE(ReportCmd()->Run({"--children", "-i", "perf_g.data"}));
}

TEST_F(ReportCommandTest, callgraph_option) {
  ASSERT_TRUE(ReportCmd()->Run({"-g", "-i", "perf_g.data"}));
  ASSERT_TRUE(ReportCmd()->Run({"-g", "callee", "-i", "perf_g.data"}));
  ASSERT_TRUE(ReportCmd()->Run({"-g", "caller", "-i", "perf_g.data"}));
}

TEST_F(ReportCommandTest, pid_filter_option) {
  ASSERT_TRUE(ReportCmd()->Run({"--pids", "0"}));
  ASSERT_TRUE(ReportCmd()->Run({"--pids", "0,1"}));
}

TEST_F(ReportCommandTest, tid_filter_option) {
  ASSERT_TRUE(ReportCmd()->Run({"--tids", "0"}));
  ASSERT_TRUE(ReportCmd()->Run({"--tids", "0,1"}));
}

TEST_F(ReportCommandTest, comm_filter_option) {
  ASSERT_TRUE(ReportCmd()->Run({"--comms", "swapper"}));
  ASSERT_TRUE(ReportCmd()->Run({"--comms", "swapper,simpleperf"}));
}

TEST_F(ReportCommandTest, dso_filter_option) {
  ASSERT_TRUE(ReportCmd()->Run({"--dsos", "[kernel.kallsyms]"}));
  ASSERT_TRUE(ReportCmd()->Run({"--dsos", "[kernel.kallsyms],/init"}));
}

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

TEST(report_cmd, dwarf_callgraph) {
  if (IsDwarfCallChainSamplingSupported()) {
    ASSERT_TRUE(RecordCmd()->Run({"-g", "-o", "perf_dwarf.data", "sleep", "1"}));
    ASSERT_TRUE(ReportCmd()->Run({"-g", "-i", "perf_dwarf.data"}));
  } else {
    GTEST_LOG_(INFO)
        << "This test does nothing as dwarf callchain sampling is not supported on this device.";
  }
}

TEST(report_cmd, report_symbols_of_nativelib_in_apk) {
  TemporaryFile tmp_file;
  ASSERT_TRUE(ReportCmd()->Run({"-i", GetTestData(NATIVELIB_IN_APK_PERF_DATA),
                                "--symfs", GetTestDataDir(), "-o", tmp_file.path}));
  std::string content;
  ASSERT_TRUE(android::base::ReadFileToString(tmp_file.path, &content));
  ASSERT_NE(content.find(GetUrlInApk(APK_FILE, NATIVELIB_IN_APK)), std::string::npos);
  ASSERT_NE(content.find("GlobalFunc"), std::string::npos);
}
