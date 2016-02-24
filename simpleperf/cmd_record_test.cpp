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

#include <android-base/stringprintf.h>

#include "command.h"
#include "environment.h"
#include "event_selection_set.h"
#include "record.h"
#include "record_file.h"
#include "test_util.h"

using namespace PerfFileFormat;

static std::unique_ptr<Command> RecordCmd() {
  return CreateCommandInstance("record");
}

TEST(record_cmd, no_options) {
  ASSERT_TRUE(RecordCmd()->Run({"sleep", SLEEP_SEC}));
}

TEST(record_cmd, system_wide_option) {
  ASSERT_TRUE(RecordCmd()->Run({"-a", "sleep", SLEEP_SEC}));
}

TEST(record_cmd, sample_period_option) {
  ASSERT_TRUE(RecordCmd()->Run({"-c", "100000", "sleep", SLEEP_SEC}));
}

TEST(record_cmd, event_option) {
  ASSERT_TRUE(RecordCmd()->Run({"-e", "cpu-clock", "sleep", SLEEP_SEC}));
}

TEST(record_cmd, freq_option) {
  ASSERT_TRUE(RecordCmd()->Run({"-f", "99", "sleep", SLEEP_SEC}));
  ASSERT_TRUE(RecordCmd()->Run({"-F", "99", "sleep", SLEEP_SEC}));
}

TEST(record_cmd, output_file_option) {
  ASSERT_TRUE(RecordCmd()->Run({"-o", "perf2.data", "sleep", SLEEP_SEC}));
}

TEST(record_cmd, dump_kernel_mmap) {
  ASSERT_TRUE(RecordCmd()->Run({"sleep", SLEEP_SEC}));
  std::unique_ptr<RecordFileReader> reader = RecordFileReader::CreateInstance("perf.data");
  ASSERT_TRUE(reader != nullptr);
  std::vector<std::unique_ptr<Record>> records = reader->DataSection();
  ASSERT_GT(records.size(), 0U);
  bool have_kernel_mmap = false;
  for (auto& record : records) {
    if (record->header.type == PERF_RECORD_MMAP) {
      const MmapRecord* mmap_record = static_cast<const MmapRecord*>(record.get());
      if (mmap_record->filename == DEFAULT_KERNEL_MMAP_NAME) {
        have_kernel_mmap = true;
        break;
      }
    }
  }
  ASSERT_TRUE(have_kernel_mmap);
}

TEST(record_cmd, dump_build_id_feature) {
  ASSERT_TRUE(RecordCmd()->Run({"sleep", SLEEP_SEC}));
  std::unique_ptr<RecordFileReader> reader = RecordFileReader::CreateInstance("perf.data");
  ASSERT_TRUE(reader != nullptr);
  const FileHeader& file_header = reader->FileHeader();
  ASSERT_TRUE(file_header.features[FEAT_BUILD_ID / 8] & (1 << (FEAT_BUILD_ID % 8)));
  ASSERT_GT(reader->FeatureSectionDescriptors().size(), 0u);
}

TEST(record_cmd, tracepoint_event) {
  ASSERT_TRUE(RecordCmd()->Run({"-a", "-e", "sched:sched_switch", "sleep", SLEEP_SEC}));
}

TEST(record_cmd, branch_sampling) {
  if (IsBranchSamplingSupported()) {
    ASSERT_TRUE(RecordCmd()->Run({"-a", "-b", "sleep", SLEEP_SEC}));
    ASSERT_TRUE(RecordCmd()->Run({"-j", "any,any_call,any_ret,ind_call", "sleep", SLEEP_SEC}));
    ASSERT_TRUE(RecordCmd()->Run({"-j", "any,k", "sleep", SLEEP_SEC}));
    ASSERT_TRUE(RecordCmd()->Run({"-j", "any,u", "sleep", SLEEP_SEC}));
    ASSERT_FALSE(RecordCmd()->Run({"-j", "u", "sleep", SLEEP_SEC}));
  } else {
    GTEST_LOG_(INFO)
        << "This test does nothing as branch stack sampling is not supported on this device.";
  }
}

TEST(record_cmd, event_modifier) {
  ASSERT_TRUE(RecordCmd()->Run({"-e", "cpu-cycles:u", "sleep", SLEEP_SEC}));
}

TEST(record_cmd, fp_callchain_sampling) {
  ASSERT_TRUE(RecordCmd()->Run({"--call-graph", "fp", "sleep", SLEEP_SEC}));
}

TEST(record_cmd, dwarf_callchain_sampling) {
  if (IsDwarfCallChainSamplingSupported()) {
    ASSERT_TRUE(RecordCmd()->Run({"--call-graph", "dwarf", "sleep", SLEEP_SEC}));
    ASSERT_TRUE(RecordCmd()->Run({"--call-graph", "dwarf,16384", "sleep", SLEEP_SEC}));
    ASSERT_TRUE(RecordCmd()->Run({"-g", "sleep", SLEEP_SEC}));
  } else {
    GTEST_LOG_(INFO)
        << "This test does nothing as dwarf callchain sampling is not supported on this device.";
  }
}

TEST(record_cmd, no_unwind_option) {
  if (IsDwarfCallChainSamplingSupported()) {
    ASSERT_TRUE(RecordCmd()->Run({"--call-graph", "dwarf", "--no-unwind", "sleep", SLEEP_SEC}));
  } else {
    GTEST_LOG_(INFO)
        << "This test does nothing as dwarf callchain sampling is not supported on this device.";
  }
  ASSERT_FALSE(RecordCmd()->Run({"--no-unwind", "sleep", SLEEP_SEC}));
}

TEST(record_cmd, post_unwind_option) {
  if (IsDwarfCallChainSamplingSupported()) {
    ASSERT_TRUE(RecordCmd()->Run({"--call-graph", "dwarf", "--post-unwind", "sleep", SLEEP_SEC}));
  } else {
    GTEST_LOG_(INFO)
        << "This test does nothing as dwarf callchain sampling is not supported on this device.";
  }
  ASSERT_FALSE(RecordCmd()->Run({"--post-unwind", "sleep", SLEEP_SEC}));
  ASSERT_FALSE(
      RecordCmd()->Run({"--call-graph", "dwarf", "--no-unwind", "--post-unwind", "sleep", SLEEP_SEC}));
}

TEST(record_cmd, existing_processes) {
  std::vector<std::unique_ptr<Workload>> workloads;
  CreateProcesses(2, &workloads);
  std::string pid_list =
      android::base::StringPrintf("%d,%d", workloads[0]->GetPid(), workloads[1]->GetPid());
  ASSERT_TRUE(RecordCmd()->Run({"-p", pid_list}));
}

TEST(record_cmd, existing_threads) {
  std::vector<std::unique_ptr<Workload>> workloads;
  CreateProcesses(2, &workloads);
  // Process id can also be used as thread id in linux.
  std::string tid_list =
      android::base::StringPrintf("%d,%d", workloads[0]->GetPid(), workloads[1]->GetPid());
  ASSERT_TRUE(RecordCmd()->Run({"-t", tid_list}));
}

TEST(record_cmd, no_monitored_threads) {
  ASSERT_FALSE(RecordCmd()->Run({""}));
}

TEST(record_cmd, more_than_one_event_types) {
  ASSERT_TRUE(RecordCmd()->Run({"-e", "cpu-cycles,cpu-clock", "sleep", SLEEP_SEC}));
  ASSERT_TRUE(RecordCmd()->Run({"-e", "cpu-cycles", "-e", "cpu-clock", "sleep", SLEEP_SEC}));
}

TEST(record_cmd, cpu_option) {
  ASSERT_TRUE(RecordCmd()->Run({"--cpu", "0", "sleep", SLEEP_SEC}));
  ASSERT_TRUE(RecordCmd()->Run({"--cpu", "0", "-a", "sleep", SLEEP_SEC}));
}

TEST(record_cmd, mmap_page_option) {
  ASSERT_TRUE(RecordCmd()->Run({"-m", "1", "sleep", SLEEP_SEC}));
  ASSERT_FALSE(RecordCmd()->Run({"-m", "0", "sleep", SLEEP_SEC}));
  ASSERT_FALSE(RecordCmd()->Run({"-m", "7", "sleep", SLEEP_SEC}));
}
