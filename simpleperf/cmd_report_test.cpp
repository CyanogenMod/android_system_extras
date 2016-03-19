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

#include <set>
#include <unordered_map>

#include <android-base/file.h>
#include <android-base/strings.h>
#include <android-base/test_utils.h>

#include "command.h"
#include "event_selection_set.h"
#include "get_test_data.h"
#include "perf_regs.h"
#include "read_apk.h"
#include "test_util.h"

static std::unique_ptr<Command> ReportCmd() {
  return CreateCommandInstance("report");
}

class ReportCommandTest : public ::testing::Test {
 protected:
  void Report(const std::string perf_data,
              const std::vector<std::string>& add_args = std::vector<std::string>()) {
    ReportRaw(GetTestData(perf_data), add_args);
  }

  void ReportRaw(const std::string perf_data,
                 const std::vector<std::string>& add_args = std::vector<std::string>()) {
    success = false;
    std::vector<std::string> args = {"-i", perf_data,
        "--symfs", GetTestDataDir(), "-o", tmp_file.path};
    args.insert(args.end(), add_args.begin(), add_args.end());
    ASSERT_TRUE(ReportCmd()->Run(args));
    ASSERT_TRUE(android::base::ReadFileToString(tmp_file.path, &content));
    ASSERT_TRUE(!content.empty());
    std::vector<std::string> raw_lines = android::base::Split(content, "\n");
    lines.clear();
    for (const auto& line : raw_lines) {
      std::string s = android::base::Trim(line);
      if (!s.empty()) {
        lines.push_back(s);
      }
    }
    ASSERT_GE(lines.size(), 2u);
    success = true;
  }

  TemporaryFile tmp_file;
  std::string content;
  std::vector<std::string> lines;
  bool success;
};

TEST_F(ReportCommandTest, no_option) {
  Report(PERF_DATA);
  ASSERT_TRUE(success);
  ASSERT_NE(content.find("GlobalFunc"), std::string::npos);
}

TEST_F(ReportCommandTest, sort_option_pid) {
  Report(PERF_DATA, {"--sort", "pid"});
  ASSERT_TRUE(success);
  size_t line_index = 0;
  while (line_index < lines.size() && lines[line_index].find("Pid") == std::string::npos) {
    line_index++;
  }
  ASSERT_LT(line_index + 2, lines.size());
}

TEST_F(ReportCommandTest, sort_option_more_than_one) {
  Report(PERF_DATA, {"--sort", "comm,pid,dso,symbol"});
  ASSERT_TRUE(success);
  size_t line_index = 0;
  while (line_index < lines.size() && lines[line_index].find("Overhead") == std::string::npos) {
    line_index++;
  }
  ASSERT_LT(line_index + 1, lines.size());
  ASSERT_NE(lines[line_index].find("Command"), std::string::npos);
  ASSERT_NE(lines[line_index].find("Pid"), std::string::npos);
  ASSERT_NE(lines[line_index].find("Shared Object"), std::string::npos);
  ASSERT_NE(lines[line_index].find("Symbol"), std::string::npos);
  ASSERT_EQ(lines[line_index].find("Tid"), std::string::npos);
}

TEST_F(ReportCommandTest, children_option) {
  Report(CALLGRAPH_FP_PERF_DATA, {"--children", "--sort", "symbol"});
  ASSERT_TRUE(success);
  std::unordered_map<std::string, std::pair<double, double>> map;
  for (size_t i = 0; i < lines.size(); ++i) {
    char name[1024];
    std::pair<double, double> pair;
    if (sscanf(lines[i].c_str(), "%lf%%%lf%%%s", &pair.first, &pair.second, name) == 3) {
      map.insert(std::make_pair(name, pair));
    }
  }
  ASSERT_NE(map.find("GlobalFunc"), map.end());
  ASSERT_NE(map.find("main"), map.end());
  auto func_pair = map["GlobalFunc"];
  auto main_pair = map["main"];
  ASSERT_GE(main_pair.first, func_pair.first);
  ASSERT_GE(func_pair.first, func_pair.second);
  ASSERT_GE(func_pair.second, main_pair.second);
}

static bool CheckCalleeMode(std::vector<std::string>& lines) {
  bool found = false;
  for (size_t i = 0; i + 2 < lines.size(); ++i) {
    if (lines[i].find("GlobalFunc") != std::string::npos &&
        lines[i + 1].find("|") != std::string::npos &&
        lines[i + 2].find("main") != std::string::npos) {
      found = true;
      break;
    }
  }
  return found;
}

static bool CheckCallerMode(std::vector<std::string>& lines) {
  bool found = false;
  for (size_t i = 0; i + 2 < lines.size(); ++i) {
    if (lines[i].find("main") != std::string::npos &&
        lines[i + 1].find("|") != std::string::npos &&
        lines[i + 2].find("GlobalFunc") != std::string::npos) {
      found = true;
      break;
    }
  }
  return found;
}

TEST_F(ReportCommandTest, callgraph_option) {
  Report(CALLGRAPH_FP_PERF_DATA, {"-g"});
  ASSERT_TRUE(success);
  ASSERT_TRUE(CheckCalleeMode(lines));
  Report(CALLGRAPH_FP_PERF_DATA, {"-g", "callee"});
  ASSERT_TRUE(success);
  ASSERT_TRUE(CheckCalleeMode(lines));
  Report(CALLGRAPH_FP_PERF_DATA, {"-g", "caller"});
  ASSERT_TRUE(success);
  ASSERT_TRUE(CheckCallerMode(lines));
}

static bool AllItemsWithString(std::vector<std::string>& lines, const std::vector<std::string>& strs) {
  size_t line_index = 0;
  while (line_index < lines.size() && lines[line_index].find("Overhead") == std::string::npos) {
    line_index++;
  }
  if (line_index == lines.size() || line_index + 1 == lines.size()) {
    return false;
  }
  line_index++;
  for (; line_index < lines.size(); ++line_index) {
    bool exist = false;
    for (auto& s : strs) {
      if (lines[line_index].find(s) != std::string::npos) {
        exist = true;
        break;
      }
    }
    if (!exist) {
      return false;
    }
  }
  return true;
}

TEST_F(ReportCommandTest, pid_filter_option) {
  Report(PERF_DATA);
  ASSERT_TRUE("success");
  ASSERT_FALSE(AllItemsWithString(lines, {"26083"}));
  ASSERT_FALSE(AllItemsWithString(lines, {"26083", "26090"}));
  Report(PERF_DATA, {"--pids", "26083"});
  ASSERT_TRUE(success);
  ASSERT_TRUE(AllItemsWithString(lines, {"26083"}));
  Report(PERF_DATA, {"--pids", "26083,26090"});
  ASSERT_TRUE(success);
  ASSERT_TRUE(AllItemsWithString(lines, {"26083", "26090"}));
}

TEST_F(ReportCommandTest, tid_filter_option) {
  Report(PERF_DATA);
  ASSERT_TRUE("success");
  ASSERT_FALSE(AllItemsWithString(lines, {"26083"}));
  ASSERT_FALSE(AllItemsWithString(lines, {"26083", "26090"}));
  Report(PERF_DATA, {"--tids", "26083"});
  ASSERT_TRUE(success);
  ASSERT_TRUE(AllItemsWithString(lines, {"26083"}));
  Report(PERF_DATA, {"--tids", "26083,26090"});
  ASSERT_TRUE(success);
  ASSERT_TRUE(AllItemsWithString(lines, {"26083", "26090"}));
}

TEST_F(ReportCommandTest, comm_filter_option) {
  Report(PERF_DATA, {"--sort", "comm"});
  ASSERT_TRUE(success);
  ASSERT_FALSE(AllItemsWithString(lines, {"t1"}));
  ASSERT_FALSE(AllItemsWithString(lines, {"t1", "t2"}));
  Report(PERF_DATA, {"--sort", "comm", "--comms", "t1"});
  ASSERT_TRUE(success);
  ASSERT_TRUE(AllItemsWithString(lines, {"t1"}));
  Report(PERF_DATA, {"--sort", "comm", "--comms", "t1,t2"});
  ASSERT_TRUE(success);
  ASSERT_TRUE(AllItemsWithString(lines, {"t1", "t2"}));
}

TEST_F(ReportCommandTest, dso_filter_option) {
  Report(PERF_DATA, {"--sort", "dso"});
  ASSERT_TRUE(success);
  ASSERT_FALSE(AllItemsWithString(lines, {"/t1"}));
  ASSERT_FALSE(AllItemsWithString(lines, {"/t1", "/t2"}));
  Report(PERF_DATA, {"--sort", "dso", "--dsos", "/t1"});
  ASSERT_TRUE(success);
  ASSERT_TRUE(AllItemsWithString(lines, {"/t1"}));
  Report(PERF_DATA, {"--sort", "dso", "--dsos", "/t1,/t2"});
  ASSERT_TRUE(success);
  ASSERT_TRUE(AllItemsWithString(lines, {"/t1", "/t2"}));
}

TEST_F(ReportCommandTest, use_branch_address) {
  Report(BRANCH_PERF_DATA, {"-b", "--sort", "symbol_from,symbol_to"});
  std::set<std::pair<std::string, std::string>> hit_set;
  bool after_overhead = false;
  for (const auto& line : lines) {
    if (!after_overhead && line.find("Overhead") != std::string::npos) {
      after_overhead = true;
    } else if (after_overhead) {
      char from[80];
      char to[80];
      if (sscanf(line.c_str(), "%*f%%%s%s", from, to) == 2) {
        hit_set.insert(std::make_pair<std::string, std::string>(from, to));
      }
    }
  }
  ASSERT_NE(hit_set.find(std::make_pair<std::string, std::string>("GlobalFunc", "CalledFunc")),
            hit_set.end());
  ASSERT_NE(hit_set.find(std::make_pair<std::string, std::string>("CalledFunc", "GlobalFunc")),
            hit_set.end());
}

TEST_F(ReportCommandTest, report_symbols_of_nativelib_in_apk) {
  Report(NATIVELIB_IN_APK_PERF_DATA);
  ASSERT_TRUE(success);
  ASSERT_NE(content.find(GetUrlInApk(APK_FILE, NATIVELIB_IN_APK)), std::string::npos);
  ASSERT_NE(content.find("Func2"), std::string::npos);
}

#if defined(__linux__)

static std::unique_ptr<Command> RecordCmd() {
  return CreateCommandInstance("record");
}

TEST_F(ReportCommandTest, dwarf_callgraph) {
  if (IsDwarfCallChainSamplingSupported()) {
    TemporaryFile tmp_file;
    ASSERT_TRUE(RecordCmd()->Run({"-g", "-o", tmp_file.path, "sleep", SLEEP_SEC}));
    ReportRaw(tmp_file.path, {"-g"});
    ASSERT_TRUE(success);
  } else {
    GTEST_LOG_(INFO)
        << "This test does nothing as dwarf callchain sampling is not supported on this device.";
  }
}

TEST_F(ReportCommandTest, report_dwarf_callgraph_of_nativelib_in_apk) {
  // NATIVELIB_IN_APK_PERF_DATA is recorded on arm64, so can only report callgraph on arm64.
  if (GetBuildArch() == ARCH_ARM64) {
    Report(NATIVELIB_IN_APK_PERF_DATA, {"-g"});
    ASSERT_NE(content.find(GetUrlInApk(APK_FILE, NATIVELIB_IN_APK)), std::string::npos);
    ASSERT_NE(content.find("Func2"), std::string::npos);
    ASSERT_NE(content.find("Func1"), std::string::npos);
    ASSERT_NE(content.find("GlobalFunc"), std::string::npos);
  } else {
    GTEST_LOG_(INFO) << "This test does nothing as it is only run on arm64 devices";
  }
}

#endif

