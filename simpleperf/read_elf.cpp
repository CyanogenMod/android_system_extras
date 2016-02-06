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

#include "read_elf.h"
#include "read_apk.h"

#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <algorithm>
#include <limits>

#include <android-base/file.h>
#include <android-base/logging.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-parameter"

#include <llvm/ADT/StringRef.h>
#include <llvm/Object/Binary.h>
#include <llvm/Object/ELFObjectFile.h>
#include <llvm/Object/ObjectFile.h>

#pragma clang diagnostic pop

#include "utils.h"

#define ELF_NOTE_GNU "GNU"
#define NT_GNU_BUILD_ID 3

FileHelper::FileHelper(const char *filename) : fd_(-1)
{
  fd_ = TEMP_FAILURE_RETRY(open(filename, O_RDONLY | O_BINARY));
}

FileHelper::~FileHelper()
{
  if (fd_ != -1) { close(fd_); }
}

bool IsValidElfFile(int fd) {
  static const char elf_magic[] = {0x7f, 'E', 'L', 'F'};
  char buf[4];
  return android::base::ReadFully(fd, buf, 4) && memcmp(buf, elf_magic, 4) == 0;
}

bool IsValidElfPath(const std::string& filename) {
  if (!IsRegularFile(filename)) {
    return false;
  }
  std::string mode = std::string("rb") + CLOSE_ON_EXEC_MODE;
  FILE* fp = fopen(filename.c_str(), mode.c_str());
  if (fp == nullptr) {
    return false;
  }
  bool result = IsValidElfFile(fileno(fp));
  fclose(fp);
  return result;
}

static bool GetBuildIdFromNoteSection(const char* section, size_t section_size, BuildId* build_id) {
  const char* p = section;
  const char* end = p + section_size;
  while (p < end) {
    CHECK_LE(p + 12, end);
    size_t namesz = *reinterpret_cast<const uint32_t*>(p);
    p += 4;
    size_t descsz = *reinterpret_cast<const uint32_t*>(p);
    p += 4;
    uint32_t type = *reinterpret_cast<const uint32_t*>(p);
    p += 4;
    namesz = ALIGN(namesz, 4);
    descsz = ALIGN(descsz, 4);
    CHECK_LE(p + namesz + descsz, end);
    if ((type == NT_GNU_BUILD_ID) && (strcmp(p, ELF_NOTE_GNU) == 0)) {
      *build_id = BuildId(p + namesz, descsz);
      return true;
    }
    p += namesz + descsz;
  }
  return false;
}

bool GetBuildIdFromNoteFile(const std::string& filename, BuildId* build_id) {
  std::string content;
  if (!android::base::ReadFileToString(filename, &content)) {
    LOG(DEBUG) << "can't read note file " << filename;
    return false;
  }
  if (GetBuildIdFromNoteSection(content.c_str(), content.size(), build_id) == false) {
    LOG(DEBUG) << "can't read build_id from note file " << filename;
    return false;
  }
  return true;
}

template <class ELFT>
bool GetBuildIdFromELFFile(const llvm::object::ELFFile<ELFT>* elf, BuildId* build_id) {
  for (auto section_iterator = elf->begin_sections(); section_iterator != elf->end_sections();
       ++section_iterator) {
    if (section_iterator->sh_type == llvm::ELF::SHT_NOTE) {
      auto contents = elf->getSectionContents(&*section_iterator);
      if (contents.getError()) {
        LOG(DEBUG) << "read note section error";
        continue;
      }
      if (GetBuildIdFromNoteSection(reinterpret_cast<const char*>(contents->data()),
                                    contents->size(), build_id)) {
        return true;
      }
    }
  }
  return false;
}

static bool GetBuildIdFromObjectFile(llvm::object::ObjectFile* obj, BuildId* build_id) {
  bool result = false;
  if (auto elf = llvm::dyn_cast<llvm::object::ELF32LEObjectFile>(obj)) {
    result = GetBuildIdFromELFFile(elf->getELFFile(), build_id);
  } else if (auto elf = llvm::dyn_cast<llvm::object::ELF64LEObjectFile>(obj)) {
    result = GetBuildIdFromELFFile(elf->getELFFile(), build_id);
  } else {
    LOG(ERROR) << "unknown elf format in file " << obj->getFileName().data();
    return false;
  }
  if (!result) {
    LOG(DEBUG) << "no build id present in file " << obj->getFileName().data();
  }
  return result;
}

bool GetBuildIdFromEmbeddedElfFile(const std::string& filename,
                                   uint64_t offsetInFile,
                                   uint32_t sizeInFile,
                                   BuildId* build_id) {
  FileHelper opener(filename.c_str());
  if (opener.fd() == -1) {
    LOG(DEBUG) << "unable to open " << filename
               << "to collect embedded ELF build id";
    return false;
  }
  llvm::ErrorOr<std::unique_ptr<llvm::MemoryBuffer>> bufferOrErr =
      llvm::MemoryBuffer::getOpenFileSlice(opener.fd(), filename, sizeInFile,
                                           offsetInFile);
  if (std::error_code EC = bufferOrErr.getError()) {
    LOG(DEBUG) << "MemoryBuffer::getOpenFileSlice failed opening "
               << filename << "while collecting embedded ELF build id: "
               << EC.message();
    return false;
  }
  std::unique_ptr<llvm::MemoryBuffer> buffer = std::move(bufferOrErr.get());
  llvm::LLVMContext *context = nullptr;
  llvm::ErrorOr<std::unique_ptr<llvm::object::Binary>> binaryOrErr =
      llvm::object::createBinary(buffer->getMemBufferRef(), context);
  if (std::error_code EC = binaryOrErr.getError()) {
    LOG(DEBUG) << "llvm::object::createBinary failed opening "
               << filename << "while collecting embedded ELF build id: "
               << EC.message();
    return false;
  }
  std::unique_ptr<llvm::object::Binary> binary = std::move(binaryOrErr.get());
  auto obj = llvm::dyn_cast<llvm::object::ObjectFile>(binary.get());
  if (obj == nullptr) {
    LOG(DEBUG) << "unable to cast to interpret contents of " << filename
               << "at offset " << offsetInFile
               << ": failed to cast to llvm::object::ObjectFile";
    return false;
  }
  return GetBuildIdFromObjectFile(obj, build_id);
}

bool GetBuildIdFromElfFile(const std::string& filename, BuildId* build_id) {
  if (!IsValidElfPath(filename)) {
    return false;
  }
  auto owning_binary = llvm::object::createBinary(llvm::StringRef(filename));
  if (owning_binary.getError()) {
    PLOG(DEBUG) << "can't open file " << filename;
    return false;
  }
  llvm::object::Binary* binary = owning_binary.get().getBinary();
  auto obj = llvm::dyn_cast<llvm::object::ObjectFile>(binary);
  if (obj == nullptr) {
    LOG(DEBUG) << filename << " is not an object file";
    return false;
  }
  return GetBuildIdFromObjectFile(obj, build_id);
}

bool IsArmMappingSymbol(const char* name) {
  // Mapping symbols in arm, which are described in "ELF for ARM Architecture" and
  // "ELF for ARM 64-bit Architecture". The regular expression to match mapping symbol
  // is ^\$(a|d|t|x)(\..*)?$
  return name[0] == '$' && strchr("adtx", name[1]) != nullptr && (name[2] == '\0' || name[2] == '.');
}

template <class ELFT>
void ParseSymbolsFromELFFile(const llvm::object::ELFFile<ELFT>* elf,
                             std::function<void(const ElfFileSymbol&)> callback) {
  bool is_arm = (elf->getHeader()->e_machine == llvm::ELF::EM_ARM ||
                 elf->getHeader()->e_machine == llvm::ELF::EM_AARCH64);
  auto begin = elf->begin_symbols();
  auto end = elf->end_symbols();
  if (begin == end) {
    begin = elf->begin_dynamic_symbols();
    end = elf->end_dynamic_symbols();
  }
  for (; begin != end; ++begin) {
    auto& elf_symbol = *begin;

    ElfFileSymbol symbol;

    auto shdr = elf->getSection(&elf_symbol);
    if (shdr == nullptr) {
      continue;
    }
    auto section_name = elf->getSectionName(shdr);
    if (section_name.getError() || section_name.get().empty()) {
      continue;
    }
    if (section_name.get() == ".text") {
      symbol.is_in_text_section = true;
    }

    auto symbol_name = elf->getSymbolName(begin);
    if (symbol_name.getError()) {
      continue;
    }
    symbol.name = symbol_name.get();
    if (symbol.name.empty()) {
      continue;
    }
    symbol.vaddr = elf_symbol.st_value;
    if ((symbol.vaddr & 1) != 0 && is_arm) {
      // Arm sets bit 0 to mark it as thumb code, remove the flag.
      symbol.vaddr &= ~1;
    }
    symbol.len = elf_symbol.st_size;
    int type = elf_symbol.getType();
    if (type == llvm::ELF::STT_FUNC) {
      symbol.is_func = true;
    } else if (type == llvm::ELF::STT_NOTYPE) {
      if (symbol.is_in_text_section) {
        symbol.is_label = true;
        if (is_arm) {
          // Remove mapping symbols in arm.
          const char* p = (symbol.name.compare(0, linker_prefix.size(), linker_prefix) == 0)
                              ? symbol.name.c_str() + linker_prefix.size()
                              : symbol.name.c_str();
          if (IsArmMappingSymbol(p)) {
            symbol.is_label = false;
          }
        }
      }
    }

    callback(symbol);
  }
}

static llvm::object::ObjectFile* GetObjectFile(
    llvm::ErrorOr<llvm::object::OwningBinary<llvm::object::Binary>>& owning_binary,
    const std::string& filename, const BuildId& expected_build_id) {
  if (owning_binary.getError()) {
    PLOG(DEBUG) << "can't open file '" << filename << "'";
    return nullptr;
  }
  llvm::object::Binary* binary = owning_binary.get().getBinary();
  auto obj = llvm::dyn_cast<llvm::object::ObjectFile>(binary);
  if (obj == nullptr) {
    LOG(DEBUG) << filename << " is not an object file";
    return nullptr;
  }
  if (!expected_build_id.IsEmpty()) {
    BuildId real_build_id;
    GetBuildIdFromObjectFile(obj, &real_build_id);
    bool result = (expected_build_id == real_build_id);
    LOG(DEBUG) << "check build id for \"" << filename << "\" (" << (result ? "match" : "mismatch")
               << "): expected " << expected_build_id.ToString() << ", real "
               << real_build_id.ToString();
    if (!result) {
      return nullptr;
    }
  }
  return obj;
}

bool ParseSymbolsFromElfFile(const std::string& filename, const BuildId& expected_build_id,
                             std::function<void(const ElfFileSymbol&)> callback) {
  if (!IsValidElfPath(filename)) {
    return false;
  }
  auto owning_binary = llvm::object::createBinary(llvm::StringRef(filename));
  llvm::object::ObjectFile* obj = GetObjectFile(owning_binary, filename, expected_build_id);
  if (obj == nullptr) {
    return false;
  }

  if (auto elf = llvm::dyn_cast<llvm::object::ELF32LEObjectFile>(obj)) {
    ParseSymbolsFromELFFile(elf->getELFFile(), callback);
  } else if (auto elf = llvm::dyn_cast<llvm::object::ELF64LEObjectFile>(obj)) {
    ParseSymbolsFromELFFile(elf->getELFFile(), callback);
  } else {
    LOG(ERROR) << "unknown elf format in file" << filename;
    return false;
  }
  return true;
}

template <class ELFT>
bool ReadMinExecutableVirtualAddress(const llvm::object::ELFFile<ELFT>* elf, uint64_t* p_vaddr) {
  bool has_vaddr = false;
  uint64_t min_addr = std::numeric_limits<uint64_t>::max();
  for (auto it = elf->begin_program_headers(); it != elf->end_program_headers(); ++it) {
    if ((it->p_type == llvm::ELF::PT_LOAD) && (it->p_flags & llvm::ELF::PF_X)) {
      if (it->p_vaddr < min_addr) {
        min_addr = it->p_vaddr;
        has_vaddr = true;
      }
    }
  }
  if (has_vaddr) {
    *p_vaddr = min_addr;
  }
  return has_vaddr;
}

bool ReadMinExecutableVirtualAddressFromElfFile(const std::string& filename,
                                                const BuildId& expected_build_id,
                                                uint64_t* min_vaddr) {
  if (!IsValidElfPath(filename)) {
    return false;
  }
  auto owning_binary = llvm::object::createBinary(llvm::StringRef(filename));
  llvm::object::ObjectFile* obj = GetObjectFile(owning_binary, filename, expected_build_id);
  if (obj == nullptr) {
    return false;
  }

  bool result = false;
  if (auto elf = llvm::dyn_cast<llvm::object::ELF32LEObjectFile>(obj)) {
    result = ReadMinExecutableVirtualAddress(elf->getELFFile(), min_vaddr);
  } else if (auto elf = llvm::dyn_cast<llvm::object::ELF64LEObjectFile>(obj)) {
    result = ReadMinExecutableVirtualAddress(elf->getELFFile(), min_vaddr);
  } else {
    LOG(ERROR) << "unknown elf format in file" << filename;
    return false;
  }

  if (!result) {
    LOG(ERROR) << "no program header in file " << filename;
  }
  return result;
}
