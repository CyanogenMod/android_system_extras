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
  const char* comm;
  std::string dso_name;
  uint64_t map_start_addr;
  size_t sample_count;
};

static void SampleMatchExpectation(const SampleEntry& sample, const ExpectedSampleInMap& expected,
                                   bool* has_error) {
  *has_error = true;
  ASSERT_TRUE(sample.thread != nullptr);
  ASSERT_EQ(expected.pid, sample.thread->pid);
  ASSERT_EQ(expected.tid, sample.thread->tid);
  ASSERT_STREQ(expected.comm, sample.thread_comm);
  ASSERT_TRUE(sample.map != nullptr);
  ASSERT_EQ(expected.dso_name, sample.map->dso->Path());
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
  if (sample1.thread->pid != sample2.thread->pid) {
    return sample1.thread->pid - sample2.thread->pid;
  }
  if (sample1.thread->tid != sample2.thread->tid) {
    return sample1.thread->tid - sample2.thread->tid;
  }
  if (strcmp(sample1.thread_comm, sample2.thread_comm) != 0) {
    return strcmp(sample1.thread_comm, sample2.thread_comm);
  }
  if (sample1.map->dso->Path() != sample2.map->dso->Path()) {
    return sample1.map->dso->Path() > sample2.map->dso->Path() ? 1 : -1;
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
    thread_tree.AddThread(1, 1, "p1t1");
    thread_tree.AddThread(1, 11, "p1t11");
    thread_tree.AddThread(2, 2, "p2t2");
    thread_tree.AddThreadMap(1, 1, 1, 5, 0, 0, "process1_thread1");
    thread_tree.AddThreadMap(1, 1, 6, 5, 0, 0, "process1_thread1_map2");
    thread_tree.AddThreadMap(1, 11, 1, 10, 0, 0, "process1_thread11");
    thread_tree.AddThreadMap(2, 2, 1, 20, 0, 0, "process2_thread2");
    thread_tree.AddKernelMap(10, 20, 0, 0, "kernel");
    sample_tree = std::unique_ptr<SampleTree>(new SampleTree(&thread_tree, CompareSampleFunction));
  }

  void VisitSampleTree(const std::vector<ExpectedSampleInMap>& expected_samples) {
    ::VisitSampleTree(sample_tree.get(), expected_samples);
  }

  ThreadTree thread_tree;
  std::unique_ptr<SampleTree> sample_tree;
};

TEST_F(SampleTreeTest, ip_in_map) {
  sample_tree->AddSample(1, 1, 1, 0, 0, false);
  sample_tree->AddSample(1, 1, 2, 0, 0, false);
  sample_tree->AddSample(1, 1, 5, 0, 0, false);
  std::vector<ExpectedSampleInMap> expected_samples = {
      {1, 1, "p1t1", "process1_thread1", 1, 3},
  };
  VisitSampleTree(expected_samples);
}

TEST_F(SampleTreeTest, different_pid) {
  sample_tree->AddSample(1, 1, 1, 0, 0, false);
  sample_tree->AddSample(2, 2, 1, 0, 0, false);
  std::vector<ExpectedSampleInMap> expected_samples = {
      {1, 1, "p1t1", "process1_thread1", 1, 1}, {2, 2, "p2t2", "process2_thread2", 1, 1},
  };
  VisitSampleTree(expected_samples);
}

TEST_F(SampleTreeTest, different_tid) {
  sample_tree->AddSample(1, 1, 1, 0, 0, false);
  sample_tree->AddSample(1, 11, 1, 0, 0, false);
  std::vector<ExpectedSampleInMap> expected_samples = {
      {1, 1, "p1t1", "process1_thread1", 1, 1}, {1, 11, "p1t11", "process1_thread11", 1, 1},
  };
  VisitSampleTree(expected_samples);
}

TEST_F(SampleTreeTest, different_comm) {
  sample_tree->AddSample(1, 1, 1, 0, 0, false);
  thread_tree.AddThread(1, 1, "p1t1_comm2");
  sample_tree->AddSample(1, 1, 1, 0, 0, false);
  std::vector<ExpectedSampleInMap> expected_samples = {
      {1, 1, "p1t1", "process1_thread1", 1, 1}, {1, 1, "p1t1_comm2", "process1_thread1", 1, 1},
  };
  VisitSampleTree(expected_samples);
}

TEST_F(SampleTreeTest, different_map) {
  sample_tree->AddSample(1, 1, 1, 0, 0, false);
  sample_tree->AddSample(1, 1, 6, 0, 0, false);
  std::vector<ExpectedSampleInMap> expected_samples = {
      {1, 1, "p1t1", "process1_thread1", 1, 1}, {1, 1, "p1t1", "process1_thread1_map2", 6, 1},
  };
  VisitSampleTree(expected_samples);
}

TEST_F(SampleTreeTest, unmapped_sample) {
  sample_tree->AddSample(1, 1, 0, 0, 0, false);
  sample_tree->AddSample(1, 1, 31, 0, 0, false);
  sample_tree->AddSample(1, 1, 70, 0, 0, false);
  // Match the unknown map.
  std::vector<ExpectedSampleInMap> expected_samples = {
      {1, 1, "p1t1", "unknown", 0, 3},
  };
  VisitSampleTree(expected_samples);
}

TEST_F(SampleTreeTest, map_kernel) {
  sample_tree->AddSample(1, 1, 10, 0, 0, true);
  sample_tree->AddSample(1, 1, 10, 0, 0, false);
  std::vector<ExpectedSampleInMap> expected_samples = {
      {1, 1, "p1t1", "kernel", 10, 1}, {1, 1, "p1t1", "process1_thread1_map2", 6, 1},
  };
  VisitSampleTree(expected_samples);
}

TEST(sample_tree, overlapped_map) {
  ThreadTree thread_tree;
  SampleTree sample_tree(&thread_tree, CompareSampleFunction);
  thread_tree.AddThread(1, 1, "thread1");
  thread_tree.AddThreadMap(1, 1, 1, 10, 0, 0, "map1");  // Add map 1.
  sample_tree.AddSample(1, 1, 5, 0, 0, false);          // Hit map 1.
  thread_tree.AddThreadMap(1, 1, 5, 20, 0, 0, "map2");  // Add map 2.
  sample_tree.AddSample(1, 1, 6, 0, 0, false);          // Hit map 2.
  sample_tree.AddSample(1, 1, 4, 0, 0, false);          // Hit map 1.
  thread_tree.AddThreadMap(1, 1, 2, 7, 0, 0, "map3");   // Add map 3.
  sample_tree.AddSample(1, 1, 7, 0, 0, false);          // Hit map 3.
  sample_tree.AddSample(1, 1, 10, 0, 0, false);         // Hit map 2.

  std::vector<ExpectedSampleInMap> expected_samples = {
      {1, 1, "thread1", "map1", 1, 2},
      {1, 1, "thread1", "map2", 5, 1},
      {1, 1, "thread1", "map2", 9, 1},
      {1, 1, "thread1", "map3", 2, 1},
  };
  VisitSampleTree(&sample_tree, expected_samples);
}
