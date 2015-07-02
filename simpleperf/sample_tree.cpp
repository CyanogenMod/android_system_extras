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

#include <base/logging.h>

#include "environment.h"

bool MapComparator::operator()(const MapEntry* map1, const MapEntry* map2) const {
  if (map1->start_addr != map2->start_addr) {
    return map1->start_addr < map2->start_addr;
  }
  if (map1->len != map2->len) {
    return map1->len < map2->len;
  }
  if (map1->time != map2->time) {
    return map1->time < map2->time;
  }
  return false;
}

void SampleTree::AddThread(int pid, int tid, const std::string& comm) {
  auto it = thread_tree_.find(tid);
  if (it == thread_tree_.end()) {
    ThreadEntry* thread = new ThreadEntry{
        pid, tid,
        "unknown",                             // comm
        std::set<MapEntry*, MapComparator>(),  // maps
    };
    auto pair = thread_tree_.insert(std::make_pair(tid, std::unique_ptr<ThreadEntry>(thread)));
    CHECK(pair.second);
    it = pair.first;
  }
  thread_comm_storage_.push_back(std::unique_ptr<std::string>(new std::string(comm)));
  it->second->comm = thread_comm_storage_.back()->c_str();
}

void SampleTree::ForkThread(int pid, int tid, int ppid, int ptid) {
  ThreadEntry* parent = FindThreadOrNew(ppid, ptid);
  ThreadEntry* child = FindThreadOrNew(pid, tid);
  child->comm = parent->comm;
  child->maps = parent->maps;
}

static void RemoveOverlappedMap(std::set<MapEntry*, MapComparator>* map_set, const MapEntry* map) {
  for (auto it = map_set->begin(); it != map_set->end();) {
    if ((*it)->start_addr >= map->start_addr + map->len) {
      break;
    }
    if ((*it)->start_addr + (*it)->len <= map->start_addr) {
      ++it;
    } else {
      it = map_set->erase(it);
    }
  }
}

void SampleTree::AddKernelMap(uint64_t start_addr, uint64_t len, uint64_t pgoff, uint64_t time,
                              const std::string& filename) {
  // kernel map len can be 0 when record command is not run in supervisor mode.
  if (len == 0) {
    return;
  }
  DsoEntry* dso = FindKernelDsoOrNew(filename);
  MapEntry* map = new MapEntry{
      start_addr, len, pgoff, time, dso,
  };
  map_storage_.push_back(std::unique_ptr<MapEntry>(map));
  RemoveOverlappedMap(&kernel_map_tree_, map);
  auto pair = kernel_map_tree_.insert(map);
  CHECK(pair.second);
}

DsoEntry* SampleTree::FindKernelDsoOrNew(const std::string& filename) {
  if (filename == DEFAULT_KERNEL_MMAP_NAME) {
    if (kernel_dso_ == nullptr) {
      kernel_dso_ = DsoFactory::LoadKernel();
    }
    return kernel_dso_.get();
  }
  auto it = module_dso_tree_.find(filename);
  if (it == module_dso_tree_.end()) {
    module_dso_tree_[filename] = DsoFactory::LoadKernelModule(filename);
    it = module_dso_tree_.find(filename);
  }
  return it->second.get();
}

void SampleTree::AddThreadMap(int pid, int tid, uint64_t start_addr, uint64_t len, uint64_t pgoff,
                              uint64_t time, const std::string& filename) {
  ThreadEntry* thread = FindThreadOrNew(pid, tid);
  DsoEntry* dso = FindUserDsoOrNew(filename);
  MapEntry* map = new MapEntry{
      start_addr, len, pgoff, time, dso,
  };
  map_storage_.push_back(std::unique_ptr<MapEntry>(map));
  RemoveOverlappedMap(&thread->maps, map);
  auto pair = thread->maps.insert(map);
  CHECK(pair.second);
}

ThreadEntry* SampleTree::FindThreadOrNew(int pid, int tid) {
  auto it = thread_tree_.find(tid);
  if (it == thread_tree_.end()) {
    AddThread(pid, tid, "unknown");
    it = thread_tree_.find(tid);
  } else {
    CHECK_EQ(pid, it->second.get()->pid) << "tid = " << tid;
  }
  return it->second.get();
}

DsoEntry* SampleTree::FindUserDsoOrNew(const std::string& filename) {
  auto it = user_dso_tree_.find(filename);
  if (it == user_dso_tree_.end()) {
    user_dso_tree_[filename] = DsoFactory::LoadDso(filename);
    it = user_dso_tree_.find(filename);
  }
  return it->second.get();
}

static bool IsIpInMap(uint64_t ip, const MapEntry* map) {
  return (map->start_addr <= ip && map->start_addr + map->len > ip);
}

const MapEntry* SampleTree::FindMap(const ThreadEntry* thread, uint64_t ip, bool in_kernel) {
  // Construct a map_entry which is strictly after the searched map_entry, based on MapComparator.
  MapEntry find_map = {
      ip,          // start_addr
      ULLONG_MAX,  // len
      0,           // pgoff
      ULLONG_MAX,  // time
      nullptr,     // dso
  };
  if (!in_kernel) {
    auto it = thread->maps.upper_bound(&find_map);
    if (it != thread->maps.begin() && IsIpInMap(ip, *--it)) {
      return *it;
    }
  } else {
    auto it = kernel_map_tree_.upper_bound(&find_map);
    if (it != kernel_map_tree_.begin() && IsIpInMap(ip, *--it)) {
      return *it;
    }
  }
  return &unknown_map_;
}

SampleEntry* SampleTree::AddSample(int pid, int tid, uint64_t ip, uint64_t time, uint64_t period,
                                   bool in_kernel) {
  const ThreadEntry* thread = FindThreadOrNew(pid, tid);
  const MapEntry* map = FindMap(thread, ip, in_kernel);
  const SymbolEntry* symbol = FindSymbol(map, ip);

  SampleEntry value(ip, time, period, 0, 1, thread, map, symbol);

  return InsertSample(value);
}

void SampleTree::AddBranchSample(int pid, int tid, uint64_t from_ip, uint64_t to_ip,
                                 uint64_t branch_flags, uint64_t time, uint64_t period) {
  const ThreadEntry* thread = FindThreadOrNew(pid, tid);
  const MapEntry* from_map = FindMap(thread, from_ip, false);
  if (from_map == &unknown_map_) {
    from_map = FindMap(thread, from_ip, true);
  }
  const SymbolEntry* from_symbol = FindSymbol(from_map, from_ip);
  const MapEntry* to_map = FindMap(thread, to_ip, false);
  if (to_map == &unknown_map_) {
    to_map = FindMap(thread, to_ip, true);
  }
  const SymbolEntry* to_symbol = FindSymbol(to_map, to_ip);

  SampleEntry value(to_ip, time, period, 0, 1, thread, to_map, to_symbol);
  value.branch_from.ip = from_ip;
  value.branch_from.map = from_map;
  value.branch_from.symbol = from_symbol;
  value.branch_from.flags = branch_flags;

  InsertSample(value);
}

SampleEntry* SampleTree::AddCallChainSample(int pid, int tid, uint64_t ip, uint64_t time,
                                            uint64_t period, bool in_kernel,
                                            const std::vector<SampleEntry*>& callchain) {
  const ThreadEntry* thread = FindThreadOrNew(pid, tid);
  const MapEntry* map = FindMap(thread, ip, in_kernel);
  const SymbolEntry* symbol = FindSymbol(map, ip);

  SampleEntry value(ip, time, 0, period, 0, thread, map, symbol);

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

const SymbolEntry* SampleTree::FindSymbol(const MapEntry* map, uint64_t ip) {
  uint64_t offset_in_file;
  if (map->dso == kernel_dso_.get()) {
    offset_in_file = ip;
  } else {
    offset_in_file = ip - map->start_addr + map->pgoff;
  }
  const SymbolEntry* symbol = map->dso->FindSymbol(offset_in_file);
  if (symbol == nullptr) {
    symbol = &unknown_symbol_;
  }
  return symbol;
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
