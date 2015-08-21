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

#ifndef SIMPLE_PERF_SAMPLE_TREE_H_
#define SIMPLE_PERF_SAMPLE_TREE_H_

#include <limits.h>
#include <functional>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "callchain.h"
#include "thread_tree.h"

struct BranchFromEntry {
  uint64_t ip;
  const MapEntry* map;
  const Symbol* symbol;
  uint64_t flags;

  BranchFromEntry() : ip(0), map(nullptr), symbol(nullptr), flags(0) {
  }
};

struct SampleEntry {
  uint64_t ip;
  uint64_t time;
  uint64_t period;
  uint64_t accumulated_period;  // Accumulated when appearing in other samples' callchain.
  uint64_t sample_count;
  const ThreadEntry* thread;
  const char* thread_comm;  // It refers to the thread comm when the sample happens.
  const MapEntry* map;
  const Symbol* symbol;
  BranchFromEntry branch_from;
  CallChainRoot callchain;  // A callchain tree representing all callchains in the sample records.

  SampleEntry(uint64_t ip, uint64_t time, uint64_t period, uint64_t accumulated_period,
              uint64_t sample_count, const ThreadEntry* thread, const MapEntry* map,
              const Symbol* symbol)
      : ip(ip),
        time(time),
        period(period),
        accumulated_period(accumulated_period),
        sample_count(sample_count),
        thread(thread),
        thread_comm(thread->comm),
        map(map),
        symbol(symbol) {
  }

  // The data member 'callchain' can only move, not copy.
  SampleEntry(SampleEntry&&) = default;
  SampleEntry(SampleEntry&) = delete;
};

typedef std::function<int(const SampleEntry&, const SampleEntry&)> compare_sample_func_t;

class SampleTree {
 public:
  SampleTree(ThreadTree* thread_tree, compare_sample_func_t sample_compare_function)
      : thread_tree_(thread_tree),
        sample_comparator_(sample_compare_function),
        sample_tree_(sample_comparator_),
        callchain_sample_tree_(sample_comparator_),
        sorted_sample_comparator_(sample_compare_function),
        sorted_sample_tree_(sorted_sample_comparator_),
        total_samples_(0),
        total_period_(0) {
  }

  void SetFilters(const std::unordered_set<int>& pid_filter,
                  const std::unordered_set<int>& tid_filter,
                  const std::unordered_set<std::string>& comm_filter,
                  const std::unordered_set<std::string>& dso_filter);

  SampleEntry* AddSample(int pid, int tid, uint64_t ip, uint64_t time, uint64_t period,
                         bool in_kernel);
  void AddBranchSample(int pid, int tid, uint64_t from_ip, uint64_t to_ip, uint64_t branch_flags,
                       uint64_t time, uint64_t period);
  SampleEntry* AddCallChainSample(int pid, int tid, uint64_t ip, uint64_t time, uint64_t period,
                                  bool in_kernel, const std::vector<SampleEntry*>& callchain);
  void InsertCallChainForSample(SampleEntry* sample, const std::vector<SampleEntry*>& callchain,
                                uint64_t period);
  void VisitAllSamples(std::function<void(const SampleEntry&)> callback);

  uint64_t TotalSamples() const {
    return total_samples_;
  }

  uint64_t TotalPeriod() const {
    return total_period_;
  }

 private:
  bool IsFilteredOut(const SampleEntry& value);
  SampleEntry* InsertSample(SampleEntry& value);
  SampleEntry* AllocateSample(SampleEntry& value);

  struct SampleComparator {
    bool operator()(SampleEntry* sample1, SampleEntry* sample2) const {
      return compare_function(*sample1, *sample2) < 0;
    }
    SampleComparator(compare_sample_func_t compare_function) : compare_function(compare_function) {
    }

    compare_sample_func_t compare_function;
  };

  struct SortedSampleComparator {
    bool operator()(SampleEntry* sample1, SampleEntry* sample2) const {
      uint64_t period1 = sample1->period + sample1->accumulated_period;
      uint64_t period2 = sample2->period + sample2->accumulated_period;
      if (period1 != period2) {
        return period1 > period2;
      }
      return compare_function(*sample1, *sample2) < 0;
    }
    SortedSampleComparator(compare_sample_func_t compare_function)
        : compare_function(compare_function) {
    }

    compare_sample_func_t compare_function;
  };

  ThreadTree* thread_tree_;
  SampleComparator sample_comparator_;
  std::set<SampleEntry*, SampleComparator> sample_tree_;
  // If a CallChainSample is filtered out, it is stored in callchain_sample_tree_ and only used
  // in other SampleEntry's callchain.
  std::set<SampleEntry*, SampleComparator> callchain_sample_tree_;

  SortedSampleComparator sorted_sample_comparator_;
  std::set<SampleEntry*, SortedSampleComparator> sorted_sample_tree_;
  std::vector<std::unique_ptr<SampleEntry>> sample_storage_;

  std::unordered_set<int> pid_filter_;
  std::unordered_set<int> tid_filter_;
  std::unordered_set<std::string> comm_filter_;
  std::unordered_set<std::string> dso_filter_;

  uint64_t total_samples_;
  uint64_t total_period_;
};

#endif  // SIMPLE_PERF_SAMPLE_TREE_H_
