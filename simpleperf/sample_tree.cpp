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

bool SampleTree::MapComparator::operator()(const MapEntry* map1, const MapEntry* map2) {
  if (map1->pid != map2->pid) {
    return map1->pid < map2->pid;
  }
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

void SampleTree::AddProcess(int pid, const std::string& comm) {
  ProcessEntry* process = new ProcessEntry{
      .pid = pid, .comm = comm,
  };
  // TODO: Check the return value of below insertion operation when per thread comm is used.
  process_tree_.insert(std::make_pair(pid, std::unique_ptr<ProcessEntry>(process)));
}

void SampleTree::AddKernelMap(uint64_t start_addr, uint64_t len, uint64_t pgoff, uint64_t time,
                              const std::string& filename) {
  DsoEntry* dso = FindKernelDsoOrNew(filename);
  MapEntry* map = new MapEntry{
      .pid = -1, .start_addr = start_addr, .len = len, .pgoff = pgoff, .time = time, .dso = dso,
  };
  map_storage_.push_back(std::unique_ptr<MapEntry>(map));
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

void SampleTree::AddUserMap(int pid, uint64_t start_addr, uint64_t len, uint64_t pgoff,
                            uint64_t time, const std::string& filename) {
  DsoEntry* dso = FindUserDsoOrNew(filename);
  MapEntry* map = new MapEntry{
      .pid = pid, .start_addr = start_addr, .len = len, .pgoff = pgoff, .time = time, .dso = dso,
  };
  map_storage_.push_back(std::unique_ptr<MapEntry>(map));
  RemoveOverlappedUserMap(map);
  auto pair = user_map_tree_.insert(map);
  CHECK(pair.second);
}

DsoEntry* SampleTree::FindUserDsoOrNew(const std::string& filename) {
  auto it = user_dso_tree_.find(filename);
  if (it == user_dso_tree_.end()) {
    user_dso_tree_[filename] = DsoFactory::LoadDso(filename);
    it = user_dso_tree_.find(filename);
  }
  return it->second.get();
}

void SampleTree::RemoveOverlappedUserMap(const MapEntry* map) {
  MapEntry find_map = {
      .pid = map->pid, .start_addr = 0, .len = 0, .time = 0,
  };
  auto it = user_map_tree_.lower_bound(&find_map);
  while (it != user_map_tree_.end() && (*it)->pid == map->pid) {
    if ((*it)->start_addr >= map->start_addr + map->len) {
      break;
    }
    if ((*it)->start_addr + (*it)->len <= map->start_addr) {
      ++it;
    } else {
      it = user_map_tree_.erase(it);
    }
  }
}

const ProcessEntry* SampleTree::FindProcessEntryOrNew(int pid) {
  auto it = process_tree_.find(pid);
  if (it == process_tree_.end()) {
    ProcessEntry* process = new ProcessEntry{
        .pid = pid, .comm = "unknown",
    };
    auto pair = process_tree_.insert(std::make_pair(pid, std::unique_ptr<ProcessEntry>(process)));
    it = pair.first;
    CHECK(pair.second);
  }
  return it->second.get();
}

static bool IsIpInMap(int pid, uint64_t ip, const MapEntry* map) {
  return (pid == map->pid && map->start_addr <= ip && map->start_addr + map->len > ip);
}

const MapEntry* SampleTree::FindMapEntryOrNew(int pid, uint64_t ip, bool in_kernel) {
  // Construct a map_entry which is strictly after the searched map_entry, based on MapComparator.
  MapEntry find_map = {
      .pid = (in_kernel) ? -1 : pid,
      .start_addr = ip,
      .len = static_cast<uint64_t>(-1),
      .time = static_cast<uint64_t>(-1),
  };
  if (!in_kernel) {
    auto it = user_map_tree_.upper_bound(&find_map);
    if (it != user_map_tree_.begin() && IsIpInMap(pid, ip, *--it)) {
      return *it;
    }
  } else {
    auto it = kernel_map_tree_.upper_bound(&find_map);
    if (it != kernel_map_tree_.begin() && IsIpInMap(-1, ip, *--it)) {
      return *it;
    }
  }
  return FindUnknownMapEntryOrNew(pid);
}

const MapEntry* SampleTree::FindUnknownMapEntryOrNew(int pid) {
  auto it = unknown_maps_.find(pid);
  if (it == unknown_maps_.end()) {
    MapEntry* map = new MapEntry{
        .pid = pid,
        .start_addr = 0,
        .len = static_cast<uint64_t>(-1),
        .pgoff = 0,
        .time = 0,
        .dso = &unknown_dso_,
    };
    map_storage_.push_back(std::unique_ptr<MapEntry>(map));
    auto pair = unknown_maps_.insert(std::make_pair(pid, map));
    it = pair.first;
    CHECK(pair.second);
  }
  return it->second;
}

void SampleTree::AddSample(int pid, int tid, uint64_t ip, uint64_t time, uint64_t period,
                           bool in_kernel) {
  const ProcessEntry* process_entry = FindProcessEntryOrNew(pid);
  const MapEntry* map_entry = FindMapEntryOrNew(pid, ip, in_kernel);
  const SymbolEntry* symbol_entry = FindSymbolEntry(ip, map_entry);

  SampleEntry find_sample = {
      .tid = tid,
      .ip = ip,
      .time = time,
      .period = period,
      .sample_count = 1,
      .process = process_entry,
      .map = map_entry,
      .symbol = symbol_entry,
  };
  auto it = sample_tree_.find(find_sample);
  if (it == sample_tree_.end()) {
    auto pair = sample_tree_.insert(find_sample);
    CHECK(pair.second);
  } else {
    SampleEntry* sample_entry = const_cast<SampleEntry*>(&*it);
    sample_entry->period += period;
    sample_entry->sample_count++;
  }
  total_samples_++;
  total_period_ += period;
}

const SymbolEntry* SampleTree::FindSymbolEntry(uint64_t ip, const MapEntry* map_entry) {
  uint64_t offset_in_file;
  if (map_entry->dso == kernel_dso_.get()) {
    offset_in_file = ip;
  } else {
    offset_in_file = ip - map_entry->start_addr + map_entry->pgoff;
  }
  const SymbolEntry* symbol = map_entry->dso->FindSymbol(offset_in_file);
  if (symbol == nullptr) {
    symbol = &unknown_symbol_;
  }
  return symbol;
}

void SampleTree::VisitAllSamples(std::function<void(const SampleEntry&)> callback) {
  if (sorted_sample_tree_.size() != sample_tree_.size()) {
    sorted_sample_tree_.clear();
    for (auto& sample : sample_tree_) {
      sorted_sample_tree_.insert(sample);
    }
  }
  for (auto& sample : sorted_sample_tree_) {
    callback(sample);
  }
}
