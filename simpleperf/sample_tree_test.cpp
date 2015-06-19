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

#include "sample_tree.h"

struct ExpectedSampleInMap {
  int pid;
  int tid;
  int map_pid;
  uint64_t map_start_addr;
  size_t sample_count;
};

static void SampleMatchExpectation(const SampleEntry& sample, const ExpectedSampleInMap& expected,
                                   bool* has_error) {
  *has_error = true;
  ASSERT_TRUE(sample.process != nullptr);
  ASSERT_EQ(expected.pid, sample.process->pid);
  ASSERT_EQ(expected.tid, sample.tid);
  ASSERT_TRUE(sample.map != nullptr);
  ASSERT_EQ(expected.map_pid, sample.map->pid);
  ASSERT_EQ(expected.map_start_addr, sample.map->start_addr);
  ASSERT_EQ(expected.sample_count, sample.sample_count);
  *has_error = false;
}

static void CheckSampleCallback(const SampleEntry& sample,
                                std::vector<ExpectedSampleInMap>& expected_samples, size_t* pos) {
  ASSERT_LT(*pos, expected_samples.size());
  bool has_error;
  SampleMatchExpectation(sample, expected_samples[*pos], &has_error);
  ASSERT_FALSE(has_error) << "Error matching sample at pos " << *pos;
  ++*pos;
}

static int CompareSampleFunction(const SampleEntry& sample1, const SampleEntry& sample2) {
  if (sample1.process->pid != sample2.process->pid) {
    return sample1.process->pid - sample2.process->pid;
  }
  if (sample1.tid != sample2.tid) {
    return sample1.tid - sample2.tid;
  }
  if (sample1.map->pid != sample2.map->pid) {
    return sample1.map->pid - sample2.map->pid;
  }
  if (sample1.map->start_addr != sample2.map->start_addr) {
    return sample1.map->start_addr - sample2.map->start_addr;
  }
  return 0;
}

void VisitSampleTree(SampleTree* sample_tree,
                     const std::vector<ExpectedSampleInMap>& expected_samples) {
  size_t pos = 0;
  sample_tree->VisitAllSamples(
      std::bind(&CheckSampleCallback, std::placeholders::_1, expected_samples, &pos));
  ASSERT_EQ(expected_samples.size(), pos);
}

class SampleTreeTest : public testing::Test {
 protected:
  virtual void SetUp() {
    sample_tree = std::unique_ptr<SampleTree>(new SampleTree(CompareSampleFunction));
    sample_tree->AddUserMap(1, 1, 10, 0, 0, "");
    sample_tree->AddUserMap(1, 11, 10, 0, 0, "");
    sample_tree->AddUserMap(2, 1, 20, 0, 0, "");
    sample_tree->AddKernelMap(11, 20, 0, 0, "");
  }

  void VisitSampleTree(const std::vector<ExpectedSampleInMap>& expected_samples) {
    ::VisitSampleTree(sample_tree.get(), expected_samples);
  }

  std::unique_ptr<SampleTree> sample_tree;
};

TEST_F(SampleTreeTest, ip_in_map) {
  sample_tree->AddSample(1, 1, 1, 0, 0, false);
  sample_tree->AddSample(1, 1, 5, 0, 0, false);
  sample_tree->AddSample(1, 1, 10, 0, 0, false);
  std::vector<ExpectedSampleInMap> expected_samples = {
      {1, 1, 1, 1, 3},
  };
  VisitSampleTree(expected_samples);
}

TEST_F(SampleTreeTest, different_pid) {
  sample_tree->AddSample(1, 1, 1, 0, 0, false);
  sample_tree->AddSample(2, 2, 1, 0, 0, false);
  std::vector<ExpectedSampleInMap> expected_samples = {
      {1, 1, 1, 1, 1}, {2, 2, 2, 1, 1},
  };
  VisitSampleTree(expected_samples);
}

TEST_F(SampleTreeTest, different_tid) {
  sample_tree->AddSample(1, 1, 1, 0, 0, false);
  sample_tree->AddSample(1, 11, 1, 0, 0, false);
  std::vector<ExpectedSampleInMap> expected_samples = {
      {1, 1, 1, 1, 1}, {1, 11, 1, 1, 1},
  };
  VisitSampleTree(expected_samples);
}

TEST_F(SampleTreeTest, different_map) {
  sample_tree->AddSample(1, 1, 1, 0, 0, false);
  sample_tree->AddSample(1, 1, 11, 0, 0, false);
  std::vector<ExpectedSampleInMap> expected_samples = {
      {1, 1, 1, 1, 1}, {1, 1, 1, 11, 1},
  };
  VisitSampleTree(expected_samples);
}

TEST_F(SampleTreeTest, unmapped_sample) {
  sample_tree->AddSample(1, 1, 0, 0, 0, false);
  sample_tree->AddSample(1, 1, 31, 0, 0, false);
  sample_tree->AddSample(1, 1, 70, 0, 0, false);
  // Match the unknown map.
  std::vector<ExpectedSampleInMap> expected_samples = {
      {1, 1, 1, 0, 3},
  };
  VisitSampleTree(expected_samples);
}

TEST_F(SampleTreeTest, map_kernel) {
  sample_tree->AddSample(1, 1, 11, 0, 0, true);
  sample_tree->AddSample(1, 1, 11, 0, 0, false);
  std::vector<ExpectedSampleInMap> expected_samples = {
      {1, 1, -1, 11, 1}, {1, 1, 1, 11, 1},
  };
  VisitSampleTree(expected_samples);
}

TEST(sample_tree, overlapped_map) {
  auto sample_tree = std::unique_ptr<SampleTree>(new SampleTree(CompareSampleFunction));
  sample_tree->AddUserMap(1, 1, 10, 0, 0, "");    // Add map 1.
  sample_tree->AddSample(1, 1, 5, 0, 0, false);   // Hit map 1.
  sample_tree->AddUserMap(1, 5, 20, 0, 0, "");    // Add map 2.
  sample_tree->AddSample(1, 1, 6, 0, 0, false);   // Hit map 2.
  sample_tree->AddSample(1, 1, 4, 0, 0, false);   // Hit unknown map.
  sample_tree->AddUserMap(1, 2, 7, 0, 0, "");     // Add map 3.
  sample_tree->AddSample(1, 1, 7, 0, 0, false);   // Hit map 3.
  sample_tree->AddSample(1, 1, 10, 0, 0, false);  // Hit unknown map.

  std::vector<ExpectedSampleInMap> expected_samples = {
      {1, 1, 1, 0, 2}, {1, 1, 1, 1, 1}, {1, 1, 1, 2, 1}, {1, 1, 1, 5, 1},
  };
  VisitSampleTree(sample_tree.get(), expected_samples);
}
