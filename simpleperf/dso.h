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

#ifndef SIMPLE_PERF_DSO_H_
#define SIMPLE_PERF_DSO_H_

#include <memory>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

#include "build_id.h"

struct SymbolEntry {
  std::string name;
  uint64_t addr;
  uint64_t len;
};

struct SymbolComparator {
  bool operator()(const std::unique_ptr<SymbolEntry>& symbol1,
                  const std::unique_ptr<SymbolEntry>& symbol2);
};

struct DsoEntry {
  std::string path;
  std::set<std::unique_ptr<SymbolEntry>, SymbolComparator> symbols;

  const SymbolEntry* FindSymbol(uint64_t offset_in_dso);
};

class DsoFactory {
 public:
  static DsoFactory* GetInstance();
  void SetDemangle(bool demangle);
  bool SetSymFsDir(const std::string& symfs_dir);
  void SetVmlinux(const std::string& vmlinux);
  void SetBuildIds(const std::vector<std::pair<std::string, BuildId>>& build_ids);
  std::unique_ptr<DsoEntry> LoadKernel();
  std::unique_ptr<DsoEntry> LoadKernelModule(const std::string& dso_path);
  std::unique_ptr<DsoEntry> LoadDso(const std::string& dso_path);

 private:
  DsoFactory();
  BuildId GetExpectedBuildId(const std::string& filename);

  bool demangle_;
  std::string symfs_dir_;
  std::string vmlinux_;
  std::unordered_map<std::string, BuildId> build_id_map_;
};

#endif  // SIMPLE_PERF_DSO_H_
