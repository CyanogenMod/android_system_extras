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

DsoEntry::DsoEntry(DsoType type, const std::string& path)
    : type(type), path(path), is_loaded(false) {
}

const SymbolEntry* DsoEntry::FindSymbol(uint64_t offset_in_dso) {
  if (!is_loaded) {
    DsoFactory::GetInstance()->LoadDso(this);
    is_loaded = true;
  }
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

DsoFactory* DsoFactory::GetInstance() {
  static DsoFactory dso_factory;
  return &dso_factory;
}

DsoFactory::DsoFactory() : demangle_(true) {
}

void DsoFactory::SetDemangle(bool demangle) {
  demangle_ = demangle;
}

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
  symfs_dir_ = dirname;
  return true;
}

void DsoFactory::SetVmlinux(const std::string& vmlinux) {
  vmlinux_ = vmlinux;
}

void DsoFactory::SetBuildIds(const std::vector<std::pair<std::string, BuildId>>& build_ids) {
  std::unordered_map<std::string, BuildId> map;
  for (auto& pair : build_ids) {
    LOG(DEBUG) << "build_id_map: " << pair.first << ", " << pair.second.ToString();
    map.insert(pair);
  }
  build_id_map_ = std::move(map);
}

std::unique_ptr<DsoEntry> DsoFactory::CreateDso(DsoType dso_type, const std::string& dso_path) {
  std::string path = dso_path;
  if (dso_type == DSO_KERNEL) {
    path = "[kernel.kallsyms]";
  }
  return std::unique_ptr<DsoEntry>(new DsoEntry(dso_type, path));
}

bool DsoFactory::LoadDso(DsoEntry* dso) {
  switch (dso->type) {
    case DSO_KERNEL:
      return LoadKernel(dso);
    case DSO_KERNEL_MODULE:
      return LoadKernelModule(dso);
    case DSO_ELF_FILE:
      return LoadElfFile(dso);
    default:
      return false;
  }
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

static void VmlinuxSymbolCallback(const ElfFileSymbol& elf_symbol, DsoEntry* dso) {
  if (elf_symbol.is_func) {
    SymbolEntry* symbol = new SymbolEntry{
        elf_symbol.name,   // name
        elf_symbol.vaddr,  // addr
        elf_symbol.len,    // len
    };
    dso->symbols.insert(std::unique_ptr<SymbolEntry>(symbol));
  }
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

bool DsoFactory::LoadKernel(DsoEntry* dso) {
  BuildId build_id = GetExpectedBuildId(DEFAULT_KERNEL_FILENAME_FOR_BUILD_ID);
  if (!vmlinux_.empty()) {
    ParseSymbolsFromElfFile(vmlinux_, build_id,
                            std::bind(VmlinuxSymbolCallback, std::placeholders::_1, dso));
  } else {
    if (!build_id.IsEmpty()) {
      BuildId real_build_id;
      GetKernelBuildId(&real_build_id);
      bool match = (build_id == real_build_id);
      LOG(DEBUG) << "check kernel build id (" << (match ? "match" : "mismatch") << "): expected "
                 << build_id.ToString() << ", real " << real_build_id.ToString();
      if (!match) {
        return false;
      }
    }
    ProcessKernelSymbols("/proc/kallsyms",
                         std::bind(&KernelSymbolCallback, std::placeholders::_1, dso));
  }
  FixupSymbolLength(dso);
  return true;
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

bool DsoFactory::LoadKernelModule(DsoEntry* dso) {
  BuildId build_id = GetExpectedBuildId(dso->path);
  ParseSymbolsFromElfFile(
      symfs_dir_ + dso->path, build_id,
      std::bind(ParseSymbolCallback, std::placeholders::_1, dso, SymbolFilterForKernelModule));
  FixupSymbolLength(dso);
  return true;
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

bool DsoFactory::LoadElfFile(DsoEntry* dso) {
  BuildId build_id = GetExpectedBuildId(dso->path);
  ParseSymbolsFromElfFile(
      symfs_dir_ + dso->path, build_id,
      std::bind(ParseSymbolCallback, std::placeholders::_1, dso, SymbolFilterForDso));
  if (demangle_) {
    for (auto& symbol : dso->symbols) {
      DemangleInPlace(&symbol->name);
    }
  }
  FixupSymbolLength(dso);
  return true;
}

BuildId DsoFactory::GetExpectedBuildId(const std::string& filename) {
  auto it = build_id_map_.find(filename);
  if (it != build_id_map_.end()) {
    return it->second;
  }
  return BuildId();
}
