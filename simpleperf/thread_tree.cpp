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

#include "thread_tree.h"

#include <base/logging.h>
#include "environment.h"
#include "perf_event.h"
#include "record.h"

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

void ThreadTree::AddThread(int pid, int tid, const std::string& comm) {
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

void ThreadTree::ForkThread(int pid, int tid, int ppid, int ptid) {
  ThreadEntry* parent = FindThreadOrNew(ppid, ptid);
  ThreadEntry* child = FindThreadOrNew(pid, tid);
  child->comm = parent->comm;
  child->maps = parent->maps;
}

ThreadEntry* ThreadTree::FindThreadOrNew(int pid, int tid) {
  auto it = thread_tree_.find(tid);
  if (it == thread_tree_.end()) {
    AddThread(pid, tid, "unknown");
    it = thread_tree_.find(tid);
  } else {
    CHECK_EQ(pid, it->second.get()->pid) << "tid = " << tid;
  }
  return it->second.get();
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

void ThreadTree::AddKernelMap(uint64_t start_addr, uint64_t len, uint64_t pgoff, uint64_t time,
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

DsoEntry* ThreadTree::FindKernelDsoOrNew(const std::string& filename) {
  if (filename == DEFAULT_KERNEL_MMAP_NAME) {
    if (kernel_dso_ == nullptr) {
      kernel_dso_ = DsoFactory::GetInstance()->CreateDso(DSO_KERNEL);
    }
    return kernel_dso_.get();
  }
  auto it = module_dso_tree_.find(filename);
  if (it == module_dso_tree_.end()) {
    module_dso_tree_[filename] = DsoFactory::GetInstance()->CreateDso(DSO_KERNEL_MODULE, filename);
    it = module_dso_tree_.find(filename);
  }
  return it->second.get();
}

void ThreadTree::AddThreadMap(int pid, int tid, uint64_t start_addr, uint64_t len, uint64_t pgoff,
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

DsoEntry* ThreadTree::FindUserDsoOrNew(const std::string& filename) {
  auto it = user_dso_tree_.find(filename);
  if (it == user_dso_tree_.end()) {
    user_dso_tree_[filename] = DsoFactory::GetInstance()->CreateDso(DSO_ELF_FILE, filename);
    it = user_dso_tree_.find(filename);
  }
  return it->second.get();
}

static bool IsAddrInMap(uint64_t addr, const MapEntry* map) {
  return (addr >= map->start_addr && addr < map->start_addr + map->len);
}

static MapEntry* FindMapByAddr(const std::set<MapEntry*, MapComparator>& maps, uint64_t addr) {
  // Construct a map_entry which is strictly after the searched map_entry, based on MapComparator.
  MapEntry find_map = {
      addr,        // start_addr
      ULLONG_MAX,  // len
      0,           // pgoff
      ULLONG_MAX,  // time
      nullptr,     // dso
  };
  auto it = maps.upper_bound(&find_map);
  if (it != maps.begin() && IsAddrInMap(addr, *--it)) {
    return *it;
  }
  return nullptr;
}

const MapEntry* ThreadTree::FindMap(const ThreadEntry* thread, uint64_t ip, bool in_kernel) {
  MapEntry* result = nullptr;
  if (!in_kernel) {
    result = FindMapByAddr(thread->maps, ip);
  } else {
    result = FindMapByAddr(kernel_map_tree_, ip);
  }
  return result != nullptr ? result : &unknown_map_;
}

const SymbolEntry* ThreadTree::FindSymbol(const MapEntry* map, uint64_t ip) {
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

void BuildThreadTree(const std::vector<std::unique_ptr<Record>>& records, ThreadTree* thread_tree) {
  for (auto& record : records) {
    if (record->header.type == PERF_RECORD_MMAP) {
      const MmapRecord& r = *static_cast<const MmapRecord*>(record.get());
      if ((r.header.misc & PERF_RECORD_MISC_CPUMODE_MASK) == PERF_RECORD_MISC_KERNEL) {
        thread_tree->AddKernelMap(r.data.addr, r.data.len, r.data.pgoff, r.sample_id.time_data.time,
                                  r.filename);
      } else {
        thread_tree->AddThreadMap(r.data.pid, r.data.tid, r.data.addr, r.data.len, r.data.pgoff,
                                  r.sample_id.time_data.time, r.filename);
      }
    } else if (record->header.type == PERF_RECORD_MMAP2) {
      const Mmap2Record& r = *static_cast<const Mmap2Record*>(record.get());
      if ((r.header.misc & PERF_RECORD_MISC_CPUMODE_MASK) == PERF_RECORD_MISC_KERNEL) {
        thread_tree->AddKernelMap(r.data.addr, r.data.len, r.data.pgoff, r.sample_id.time_data.time,
                                  r.filename);
      } else {
        std::string filename =
            (r.filename == DEFAULT_EXECNAME_FOR_THREAD_MMAP) ? "[unknown]" : r.filename;
        thread_tree->AddThreadMap(r.data.pid, r.data.tid, r.data.addr, r.data.len, r.data.pgoff,
                                  r.sample_id.time_data.time, filename);
      }
    } else if (record->header.type == PERF_RECORD_COMM) {
      const CommRecord& r = *static_cast<const CommRecord*>(record.get());
      thread_tree->AddThread(r.data.pid, r.data.tid, r.comm);
    } else if (record->header.type == PERF_RECORD_FORK) {
      const ForkRecord& r = *static_cast<const ForkRecord*>(record.get());
      thread_tree->ForkThread(r.data.pid, r.data.tid, r.data.ppid, r.data.ptid);
    }
  }
}
