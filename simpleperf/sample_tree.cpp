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

#include "sample_tree.h"

#include <android-base/logging.h>

#include "environment.h"

void SampleTree::SetFilters(const std::unordered_set<int>& pid_filter,
                            const std::unordered_set<int>& tid_filter,
                            const std::unordered_set<std::string>& comm_filter,
                            const std::unordered_set<std::string>& dso_filter) {
  pid_filter_ = pid_filter;
  tid_filter_ = tid_filter;
  comm_filter_ = comm_filter;
  dso_filter_ = dso_filter;
}

SampleEntry* SampleTree::AddSample(int pid, int tid, uint64_t ip, uint64_t time, uint64_t period,
                                   bool in_kernel) {
  const ThreadEntry* thread = thread_tree_->FindThreadOrNew(pid, tid);
  const MapEntry* map = thread_tree_->FindMap(thread, ip, in_kernel);
  const Symbol* symbol = thread_tree_->FindSymbol(map, ip);

  SampleEntry value(ip, time, period, 0, 1, thread, map, symbol);

  if (IsFilteredOut(value)) {
    return nullptr;
  }
  return InsertSample(value);
}

void SampleTree::AddBranchSample(int pid, int tid, uint64_t from_ip, uint64_t to_ip,
                                 uint64_t branch_flags, uint64_t time, uint64_t period) {
  const ThreadEntry* thread = thread_tree_->FindThreadOrNew(pid, tid);
  const MapEntry* from_map = thread_tree_->FindMap(thread, from_ip, false);
  if (from_map == thread_tree_->UnknownMap()) {
    from_map = thread_tree_->FindMap(thread, from_ip, true);
  }
  const Symbol* from_symbol = thread_tree_->FindSymbol(from_map, from_ip);
  const MapEntry* to_map = thread_tree_->FindMap(thread, to_ip, false);
  if (to_map == thread_tree_->UnknownMap()) {
    to_map = thread_tree_->FindMap(thread, to_ip, true);
  }
  const Symbol* to_symbol = thread_tree_->FindSymbol(to_map, to_ip);

  SampleEntry value(to_ip, time, period, 0, 1, thread, to_map, to_symbol);
  value.branch_from.ip = from_ip;
  value.branch_from.map = from_map;
  value.branch_from.symbol = from_symbol;
  value.branch_from.flags = branch_flags;

  if (IsFilteredOut(value)) {
    return;
  }
  InsertSample(value);
}

SampleEntry* SampleTree::AddCallChainSample(int pid, int tid, uint64_t ip, uint64_t time,
                                            uint64_t period, bool in_kernel,
                                            const std::vector<SampleEntry*>& callchain) {
  const ThreadEntry* thread = thread_tree_->FindThreadOrNew(pid, tid);
  const MapEntry* map = thread_tree_->FindMap(thread, ip, in_kernel);
  const Symbol* symbol = thread_tree_->FindSymbol(map, ip);

  SampleEntry value(ip, time, 0, period, 0, thread, map, symbol);

  if (IsFilteredOut(value)) {
    // Store in callchain_sample_tree_ for use in other SampleEntry's callchain.
    auto it = callchain_sample_tree_.find(&value);
    if (it != callchain_sample_tree_.end()) {
      return *it;
    }
    SampleEntry* sample = AllocateSample(value);
    callchain_sample_tree_.insert(sample);
    return sample;
  }

  auto it = sample_tree_.find(&value);
  if (it != sample_tree_.end()) {
    SampleEntry* sample = *it;
    // Process only once for recursive function call.
    if (std::find(callchain.begin(), callchain.end(), sample) != callchain.end()) {
      return sample;
    }
  }
  return InsertSample(value);
}

bool SampleTree::IsFilteredOut(const SampleEntry& value) {
  if (!pid_filter_.empty() && pid_filter_.find(value.thread->pid) == pid_filter_.end()) {
    return true;
  }
  if (!tid_filter_.empty() && tid_filter_.find(value.thread->tid) == tid_filter_.end()) {
    return true;
  }
  if (!comm_filter_.empty() && comm_filter_.find(value.thread_comm) == comm_filter_.end()) {
    return true;
  }
  if (!dso_filter_.empty() && dso_filter_.find(value.map->dso->Path()) == dso_filter_.end()) {
    return true;
  }
  return false;
}

SampleEntry* SampleTree::InsertSample(SampleEntry& value) {
  SampleEntry* result;
  auto it = sample_tree_.find(&value);
  if (it == sample_tree_.end()) {
    result = AllocateSample(value);
    auto pair = sample_tree_.insert(result);
    CHECK(pair.second);
  } else {
    result = *it;
    result->period += value.period;
    result->accumulated_period += value.accumulated_period;
    result->sample_count += value.sample_count;
  }
  total_samples_ += value.sample_count;
  total_period_ += value.period;
  return result;
}

SampleEntry* SampleTree::AllocateSample(SampleEntry& value) {
  SampleEntry* sample = new SampleEntry(std::move(value));
  sample_storage_.push_back(std::unique_ptr<SampleEntry>(sample));
  return sample;
}

void SampleTree::InsertCallChainForSample(SampleEntry* sample,
                                          const std::vector<SampleEntry*>& callchain,
                                          uint64_t period) {
  sample->callchain.AddCallChain(callchain, period);
}

void SampleTree::VisitAllSamples(std::function<void(const SampleEntry&)> callback) {
  if (sorted_sample_tree_.size() != sample_tree_.size()) {
    sorted_sample_tree_.clear();
    for (auto& sample : sample_tree_) {
      sample->callchain.SortByPeriod();
      sorted_sample_tree_.insert(sample);
    }
  }
  for (auto& sample : sorted_sample_tree_) {
    callback(*sample);
  }
}
