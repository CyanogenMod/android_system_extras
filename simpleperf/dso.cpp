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
#include <string.h>

#include <algorithm>
#include <limits>
#include <vector>

#include <android-base/logging.h>

#include "environment.h"
#include "read_apk.h"
#include "read_elf.h"
#include "utils.h"

static OneTimeFreeAllocator symbol_name_allocator;

Symbol::Symbol(const std::string& name, uint64_t addr, uint64_t len)
    : addr(addr),
      len(len),
      name_(symbol_name_allocator.AllocateString(name)),
      demangled_name_(nullptr) {
}

const char* Symbol::DemangledName() const {
  if (demangled_name_ == nullptr) {
    const std::string s = Dso::Demangle(name_);
    if (s == name_) {
      demangled_name_ = name_;
    } else {
      demangled_name_ = symbol_name_allocator.AllocateString(s);
    }
  }
  return demangled_name_;
}

bool Dso::demangle_ = true;
std::string Dso::symfs_dir_;
std::string Dso::vmlinux_;
std::unordered_map<std::string, BuildId> Dso::build_id_map_;
size_t Dso::dso_count_;

void Dso::SetDemangle(bool demangle) {
  demangle_ = demangle;
}

extern "C" char* __cxa_demangle(const char* mangled_name, char* buf, size_t* n, int* status);

std::string Dso::Demangle(const std::string& name) {
  if (!demangle_) {
    return name;
  }
  int status;
  bool is_linker_symbol = (name.find(linker_prefix) == 0);
  const char* mangled_str = name.c_str();
  if (is_linker_symbol) {
    mangled_str += linker_prefix.size();
  }
  std::string result = name;
  char* demangled_name = __cxa_demangle(mangled_str, nullptr, nullptr, &status);
  if (status == 0) {
    if (is_linker_symbol) {
      result = std::string("[linker]") + demangled_name;
    } else {
      result = demangled_name;
    }
    free(demangled_name);
  } else if (is_linker_symbol) {
    result = std::string("[linker]") + mangled_str;
  }
  return result;
}

bool Dso::SetSymFsDir(const std::string& symfs_dir) {
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

void Dso::SetVmlinux(const std::string& vmlinux) {
  vmlinux_ = vmlinux;
}

void Dso::SetBuildIds(const std::vector<std::pair<std::string, BuildId>>& build_ids) {
  std::unordered_map<std::string, BuildId> map;
  for (auto& pair : build_ids) {
    LOG(DEBUG) << "build_id_map: " << pair.first << ", " << pair.second.ToString();
    map.insert(pair);
  }
  build_id_map_ = std::move(map);
}

BuildId Dso::GetExpectedBuildId(const std::string& filename) {
  auto it = build_id_map_.find(filename);
  if (it != build_id_map_.end()) {
    return it->second;
  }
  return BuildId();
}

std::unique_ptr<Dso> Dso::CreateDso(DsoType dso_type, const std::string& dso_path) {
  std::string path = dso_path;
  if (dso_type == DSO_KERNEL) {
    path = "[kernel.kallsyms]";
  }
  return std::unique_ptr<Dso>(new Dso(dso_type, path));
}

Dso::Dso(DsoType type, const std::string& path)
    : type_(type), path_(path), min_vaddr_(std::numeric_limits<uint64_t>::max()), is_loaded_(false) {
  dso_count_++;
}

Dso::~Dso() {
  if (--dso_count_ == 0) {
    symbol_name_allocator.Clear();
  }
}

struct SymbolComparator {
  bool operator()(const Symbol& symbol1, const Symbol& symbol2) {
    return symbol1.addr < symbol2.addr;
  }
};

std::string Dso::GetAccessiblePath() const {
  return symfs_dir_ + path_;
}

const Symbol* Dso::FindSymbol(uint64_t vaddr_in_dso) {
  if (!is_loaded_) {
    is_loaded_ = true;
    if (!Load()) {
      LOG(DEBUG) << "failed to load dso: " << path_;
      return nullptr;
    }
  }

  auto it = std::upper_bound(symbols_.begin(), symbols_.end(), Symbol("", vaddr_in_dso, 0),
                             SymbolComparator());
  if (it != symbols_.begin()) {
    --it;
    if (it->addr <= vaddr_in_dso && it->addr + it->len > vaddr_in_dso) {
      return &*it;
    }
  }
  return nullptr;
}

uint64_t Dso::MinVirtualAddress() {
  if (min_vaddr_ == std::numeric_limits<uint64_t>::max()) {
    min_vaddr_ = 0;
    if (type_ == DSO_ELF_FILE) {
      BuildId build_id = GetExpectedBuildId(GetAccessiblePath());

      uint64_t addr;
      if (ReadMinExecutableVirtualAddressFromElfFile(GetAccessiblePath(), build_id, &addr)) {
        min_vaddr_ = addr;
      }
    }
  }
  return min_vaddr_;
}

bool Dso::Load() {
  bool result = false;
  switch (type_) {
    case DSO_KERNEL:
      result = LoadKernel();
      break;
    case DSO_KERNEL_MODULE:
      result = LoadKernelModule();
      break;
    case DSO_ELF_FILE: {
      if (std::get<0>(SplitUrlInApk(path_))) {
        result = LoadEmbeddedElfFile();
      } else {
        result = LoadElfFile();
      }
      break;
    }
  }
  if (result) {
    std::sort(symbols_.begin(), symbols_.end(), SymbolComparator());
    FixupSymbolLength();
  }
  return result;
}

static bool IsKernelFunctionSymbol(const KernelSymbol& symbol) {
  return (symbol.type == 'T' || symbol.type == 't' || symbol.type == 'W' || symbol.type == 'w');
}

bool Dso::KernelSymbolCallback(const KernelSymbol& kernel_symbol, Dso* dso) {
  if (IsKernelFunctionSymbol(kernel_symbol)) {
    dso->InsertSymbol(Symbol(kernel_symbol.name, kernel_symbol.addr, 0));
  }
  return false;
}

void Dso::VmlinuxSymbolCallback(const ElfFileSymbol& elf_symbol, Dso* dso) {
  if (elf_symbol.is_func) {
    dso->InsertSymbol(Symbol(elf_symbol.name, elf_symbol.vaddr, elf_symbol.len));
  }
}

bool Dso::LoadKernel() {
  BuildId build_id = GetExpectedBuildId(DEFAULT_KERNEL_FILENAME_FOR_BUILD_ID);
  if (!vmlinux_.empty()) {
    ParseSymbolsFromElfFile(vmlinux_, build_id,
                            std::bind(VmlinuxSymbolCallback, std::placeholders::_1, this));
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
                         std::bind(&KernelSymbolCallback, std::placeholders::_1, this));
    bool allZero = true;
    for (auto& symbol : symbols_) {
      if (symbol.addr != 0) {
        allZero = false;
        break;
      }
    }
    if (allZero) {
      LOG(WARNING) << "Symbol addresses in /proc/kallsyms are all zero. Check "
                      "/proc/sys/kernel/kptr_restrict if possible.";
      symbols_.clear();
      return false;
    }
  }
  return true;
}

void Dso::ElfFileSymbolCallback(const ElfFileSymbol& elf_symbol, Dso* dso,
                                bool (*filter)(const ElfFileSymbol&)) {
  if (filter(elf_symbol)) {
    dso->InsertSymbol(Symbol(elf_symbol.name, elf_symbol.vaddr, elf_symbol.len));
  }
}

static bool SymbolFilterForKernelModule(const ElfFileSymbol& elf_symbol) {
  // TODO: Parse symbol outside of .text section.
  return (elf_symbol.is_func && elf_symbol.is_in_text_section);
}

bool Dso::LoadKernelModule() {
  BuildId build_id = GetExpectedBuildId(path_);
  ParseSymbolsFromElfFile(
      symfs_dir_ + path_, build_id,
      std::bind(ElfFileSymbolCallback, std::placeholders::_1, this, SymbolFilterForKernelModule));
  return true;
}

static bool SymbolFilterForDso(const ElfFileSymbol& elf_symbol) {
  return elf_symbol.is_func || (elf_symbol.is_label && elf_symbol.is_in_text_section);
}

bool Dso::LoadElfFile() {
  bool loaded = false;
  BuildId build_id = GetExpectedBuildId(GetAccessiblePath());

  if (symfs_dir_.empty()) {
    // Linux host can store debug shared libraries in /usr/lib/debug.
    loaded = ParseSymbolsFromElfFile(
        "/usr/lib/debug" + path_, build_id,
        std::bind(ElfFileSymbolCallback, std::placeholders::_1, this, SymbolFilterForDso));
  }
  if (!loaded) {
    loaded = ParseSymbolsFromElfFile(
        GetAccessiblePath(), build_id,
        std::bind(ElfFileSymbolCallback, std::placeholders::_1, this, SymbolFilterForDso));
  }
  return loaded;
}

bool Dso::LoadEmbeddedElfFile() {
  std::string path = GetAccessiblePath();
  BuildId build_id = GetExpectedBuildId(path);
  auto tuple = SplitUrlInApk(path);
  CHECK(std::get<0>(tuple));
  return ParseSymbolsFromApkFile(std::get<1>(tuple), std::get<2>(tuple), build_id,
                                 std::bind(ElfFileSymbolCallback, std::placeholders::_1,
                                           this, SymbolFilterForDso));
}

void Dso::InsertSymbol(const Symbol& symbol) {
  symbols_.push_back(symbol);
}

void Dso::FixupSymbolLength() {
  Symbol* prev_symbol = nullptr;
  for (auto& symbol : symbols_) {
    if (prev_symbol != nullptr && prev_symbol->len == 0) {
      prev_symbol->len = symbol.addr - prev_symbol->addr;
    }
    prev_symbol = &symbol;
  }
  if (prev_symbol != nullptr && prev_symbol->len == 0) {
    prev_symbol->len = std::numeric_limits<unsigned long long>::max() - prev_symbol->addr;
  }
}
