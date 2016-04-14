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

#ifndef SIMPLE_PERF_THREAD_TREE_H_
#define SIMPLE_PERF_THREAD_TREE_H_

#include <stdint.h>

#include <limits>
#include <memory>
#include <set>

#include "dso.h"

namespace simpleperf {

struct MapEntry {
  uint64_t start_addr;
  uint64_t len;
  uint64_t pgoff;
  uint64_t time;  // Map creation time.
  Dso* dso;

  MapEntry(uint64_t start_addr, uint64_t len, uint64_t pgoff, uint64_t time, Dso* dso)
      : start_addr(start_addr), len(len), pgoff(pgoff), time(time), dso(dso) {
  }
  MapEntry() {
  }

  uint64_t get_end_addr() const {
    return start_addr + len;
  }
};

struct MapComparator {
  bool operator()(const MapEntry* map1, const MapEntry* map2) const;
};

struct ThreadEntry {
  int pid;
  int tid;
  const char* comm;  // It always refers to the latest comm.
  std::set<MapEntry*, MapComparator> maps;
};

class ThreadTree {
 public:
  ThreadTree() : unknown_symbol_("unknown", 0, std::numeric_limits<unsigned long long>::max()) {
    unknown_dso_ = Dso::CreateDso(DSO_ELF_FILE, "unknown");
    unknown_map_ =
        MapEntry(0, std::numeric_limits<unsigned long long>::max(), 0, 0, unknown_dso_.get());
  }

  void AddThread(int pid, int tid, const std::string& comm);
  void ForkThread(int pid, int tid, int ppid, int ptid);
  ThreadEntry* FindThreadOrNew(int pid, int tid);
  void AddKernelMap(uint64_t start_addr, uint64_t len, uint64_t pgoff, uint64_t time,
                    const std::string& filename);
  void AddThreadMap(int pid, int tid, uint64_t start_addr, uint64_t len, uint64_t pgoff,
                    uint64_t time, const std::string& filename);
  const MapEntry* FindMap(const ThreadEntry* thread, uint64_t ip, bool in_kernel);
  const Symbol* FindSymbol(const MapEntry* map, uint64_t ip);
  const MapEntry* UnknownMap() const {
    return &unknown_map_;
  }

  void Clear();

 private:
  Dso* FindKernelDsoOrNew(const std::string& filename);
  Dso* FindUserDsoOrNew(const std::string& filename);
  MapEntry* AllocateMap(const MapEntry& value);
  void FixOverlappedMap(std::set<MapEntry*, MapComparator>* map_set, const MapEntry* map);

  std::unordered_map<int, std::unique_ptr<ThreadEntry>> thread_tree_;
  std::vector<std::unique_ptr<std::string>> thread_comm_storage_;

  std::set<MapEntry*, MapComparator> kernel_map_tree_;
  std::vector<std::unique_ptr<MapEntry>> map_storage_;
  MapEntry unknown_map_;

  std::unique_ptr<Dso> kernel_dso_;
  std::unordered_map<std::string, std::unique_ptr<Dso>> module_dso_tree_;
  std::unordered_map<std::string, std::unique_ptr<Dso>> user_dso_tree_;
  std::unique_ptr<Dso> unknown_dso_;
  Symbol unknown_symbol_;
};

}  // namespace simpleperf

using MapEntry = simpleperf::MapEntry;
using ThreadEntry = simpleperf::ThreadEntry;
using ThreadTree = simpleperf::ThreadTree;

struct Record;

void BuildThreadTree(const Record& record, ThreadTree* thread_tree);

#endif  // SIMPLE_PERF_THREAD_TREE_H_
