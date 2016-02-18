/*
 * Copyright (C) 2016 The Android Open Source Project
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

#ifndef SIMPLE_PERF_READ_APK_H_
#define SIMPLE_PERF_READ_APK_H_

#include <stdint.h>

#include <map>
#include <memory>
#include <string>
#include <tuple>

#include "read_elf.h"

// Container for info an on ELF file embedded into an APK file
class EmbeddedElf {
 public:
  EmbeddedElf()
      : entry_offset_(0)
      , entry_size_(0)
  {
  }

  EmbeddedElf(std::string filepath,
              std::string entry_name,
              size_t entry_offset,
              size_t entry_size)
      : filepath_(filepath)
      , entry_name_(entry_name)
      , entry_offset_(entry_offset)
      , entry_size_(entry_size)
  {
  }

  // Path to APK file
  const std::string &filepath() const { return filepath_; }

  // Entry name within zip archive
  const std::string &entry_name() const { return entry_name_; }

  // Offset of zip entry from start of containing APK file
  uint64_t entry_offset() const { return entry_offset_; }

  // Size of zip entry (length of embedded ELF)
  uint32_t entry_size() const { return entry_size_; }

 private:
  std::string filepath_; // containing APK path
  std::string entry_name_; // name of entry in zip index of embedded elf file
  uint64_t entry_offset_; // offset of ELF from start of containing APK file
  uint32_t entry_size_;  // size of ELF file in zip
};

// APK inspector helper class
class ApkInspector {
 public:
  // Given an APK/ZIP/JAR file and an offset into that file, if the
  // corresponding region of the APK corresponds to an uncompressed
  // ELF file, then return pertinent info on the ELF.
  static EmbeddedElf* FindElfInApkByOffset(const std::string& apk_path, uint64_t file_offset);
  static std::unique_ptr<EmbeddedElf> FindElfInApkByName(const std::string& apk_path,
                                                         const std::string& elf_filename);

 private:
  static std::unique_ptr<EmbeddedElf> FindElfInApkByOffsetWithoutCache(const std::string& apk_path,
                                                                       uint64_t file_offset);

  // First component of pair is APK file path, second is offset into APK.
  typedef std::pair<std::string, uint64_t> ApkOffset;

  static std::map<ApkOffset, std::unique_ptr<EmbeddedElf>> embedded_elf_cache_;
};

// Export for test only.
bool IsValidApkPath(const std::string& apk_path);

std::string GetUrlInApk(const std::string& apk_path, const std::string& elf_filename);
std::tuple<bool, std::string, std::string> SplitUrlInApk(const std::string& path);

bool GetBuildIdFromApkFile(const std::string& apk_path, const std::string& elf_filename,
                           BuildId* build_id);

bool ParseSymbolsFromApkFile(const std::string& apk_path, const std::string& elf_filename,
                             const BuildId& expected_build_id,
                             std::function<void(const ElfFileSymbol&)> callback);


#endif  // SIMPLE_PERF_READ_APK_H_
