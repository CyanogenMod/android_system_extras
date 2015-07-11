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

#include "dso.h"

#include <stdlib.h>
#include <base/logging.h>
#include "environment.h"
#include "read_elf.h"
#include "utils.h"

bool SymbolComparator::operator()(const std::unique_ptr<SymbolEntry>& symbol1,
                                  const std::unique_ptr<SymbolEntry>& symbol2) {
  return symbol1->addr < symbol2->addr;
}

const SymbolEntry* DsoEntry::FindSymbol(uint64_t offset_in_dso) {
  std::unique_ptr<SymbolEntry> symbol(new SymbolEntry{
      "",             // name
      offset_in_dso,  // addr
      0,              // len
  });

  auto it = symbols.upper_bound(symbol);
  if (it != symbols.begin()) {
    --it;
    if ((*it)->addr <= offset_in_dso && (*it)->addr + (*it)->len > offset_in_dso) {
      return (*it).get();
    }
  }
  return nullptr;
}

bool DsoFactory::demangle = true;

void DsoFactory::SetDemangle(bool demangle) {
  DsoFactory::demangle = demangle;
}

std::string DsoFactory::symfs_dir;

bool DsoFactory::SetSymFsDir(const std::string& symfs_dir) {
  std::string dirname = symfs_dir;
  if (!dirname.empty()) {
    if (dirname.back() != '/') {
      dirname.push_back('/');
    }
    std::vector<std::string> files;
    std::vector<std::string> subdirs;
    GetEntriesInDir(symfs_dir, &files, &subdirs);
    if (files.empty() && subdirs.empty()) {
      LOG(ERROR) << "Invalid symfs_dir '" << symfs_dir << "'";
      return false;
    }
  }
  DsoFactory::symfs_dir = dirname;
  return true;
}

std::unordered_map<std::string, BuildId> DsoFactory::build_id_map;

void DsoFactory::SetBuildIds(const std::vector<std::pair<std::string, BuildId>>& build_ids) {
  std::unordered_map<std::string, BuildId> map;
  for (auto& pair : build_ids) {
    LOG(DEBUG) << "build_id_map: " << pair.first << ", " << pair.second.ToString();
    map.insert(pair);
  }
  build_id_map = std::move(map);
}

static bool IsKernelFunctionSymbol(const KernelSymbol& symbol) {
  return (symbol.type == 'T' || symbol.type == 't' || symbol.type == 'W' || symbol.type == 'w');
}

static bool KernelSymbolCallback(const KernelSymbol& kernel_symbol, DsoEntry* dso) {
  if (IsKernelFunctionSymbol(kernel_symbol)) {
    SymbolEntry* symbol = new SymbolEntry{
        kernel_symbol.name,  // name
        kernel_symbol.addr,  // addr
        0,                   // len
    };
    dso->symbols.insert(std::unique_ptr<SymbolEntry>(symbol));
  }
  return false;
}

static void FixupSymbolLength(DsoEntry* dso) {
  SymbolEntry* prev_symbol = nullptr;
  for (auto& symbol : dso->symbols) {
    if (prev_symbol != nullptr && prev_symbol->len == 0) {
      prev_symbol->len = symbol->addr - prev_symbol->addr;
    }
    prev_symbol = symbol.get();
  }
  if (prev_symbol != nullptr && prev_symbol->len == 0) {
    prev_symbol->len = ULLONG_MAX - prev_symbol->addr;
  }
}

// TODO: Fix the way to get kernel symbols. See b/22179177.
std::unique_ptr<DsoEntry> DsoFactory::LoadKernel() {
  std::unique_ptr<DsoEntry> dso(new DsoEntry);
  dso->path = "[kernel.kallsyms]";
  BuildId build_id = GetExpectedBuildId(DEFAULT_KERNEL_FILENAME_FOR_BUILD_ID);
  BuildId real_build_id;
  GetKernelBuildId(&real_build_id);
  bool match = (build_id == real_build_id);
  LOG(DEBUG) << "check kernel build id (" << (match ? "match" : "mismatch") << "): expected "
             << build_id.ToString() << ", real " << real_build_id.ToString();
  if (match) {
    ProcessKernelSymbols("/proc/kallsyms",
                         std::bind(&KernelSymbolCallback, std::placeholders::_1, dso.get()));
  }
  FixupSymbolLength(dso.get());
  return dso;
}

static void ParseSymbolCallback(const ElfFileSymbol& elf_symbol, DsoEntry* dso,
                                bool (*filter)(const ElfFileSymbol&)) {
  if (filter(elf_symbol)) {
    SymbolEntry* symbol = new SymbolEntry{
        elf_symbol.name,           // name
        elf_symbol.start_in_file,  // addr
        elf_symbol.len,            // len
    };
    dso->symbols.insert(std::unique_ptr<SymbolEntry>(symbol));
  }
}

static bool SymbolFilterForKernelModule(const ElfFileSymbol& elf_symbol) {
  // TODO: Parse symbol outside of .text section.
  return (elf_symbol.is_func && elf_symbol.is_in_text_section);
}

std::unique_ptr<DsoEntry> DsoFactory::LoadKernelModule(const std::string& dso_path) {
  std::unique_ptr<DsoEntry> dso(new DsoEntry);
  dso->path = dso_path;
  BuildId build_id = GetExpectedBuildId(dso_path);
  ParseSymbolsFromElfFile(symfs_dir + dso_path, build_id,
                          std::bind(ParseSymbolCallback, std::placeholders::_1, dso.get(),
                                    SymbolFilterForKernelModule));
  FixupSymbolLength(dso.get());
  return dso;
}

static bool SymbolFilterForDso(const ElfFileSymbol& elf_symbol) {
  return elf_symbol.is_func || (elf_symbol.is_label && elf_symbol.is_in_text_section);
}

extern "C" char* __cxa_demangle(const char* mangled_name, char* buf, size_t* n, int* status);

static void DemangleInPlace(std::string* name) {
  int status;
  bool is_linker_symbol = (name->find(linker_prefix) == 0);
  const char* mangled_str = name->c_str();
  if (is_linker_symbol) {
    mangled_str += linker_prefix.size();
  }
  char* demangled_name = __cxa_demangle(mangled_str, nullptr, nullptr, &status);
  if (status == 0) {
    if (is_linker_symbol) {
      *name = std::string("[linker]") + demangled_name;
    } else {
      *name = demangled_name;
    }
    free(demangled_name);
  } else if (is_linker_symbol) {
    std::string temp = std::string("[linker]") + mangled_str;
    *name = std::move(temp);
  }
}

std::unique_ptr<DsoEntry> DsoFactory::LoadDso(const std::string& dso_path) {
  std::unique_ptr<DsoEntry> dso(new DsoEntry);
  dso->path = dso_path;
  BuildId build_id = GetExpectedBuildId(dso_path);
  ParseSymbolsFromElfFile(
      symfs_dir + dso_path, build_id,
      std::bind(ParseSymbolCallback, std::placeholders::_1, dso.get(), SymbolFilterForDso));
  if (demangle) {
    for (auto& symbol : dso->symbols) {
      DemangleInPlace(&symbol->name);
    }
  }
  FixupSymbolLength(dso.get());
  return dso;
}

BuildId DsoFactory::GetExpectedBuildId(const std::string& filename) {
  auto it = build_id_map.find(filename);
  if (it != build_id_map.end()) {
    return it->second;
  }
  return BuildId();
}
