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

#include <gtest/gtest.h>

static void ParseSymbol(const ElfFileSymbol& symbol, bool* result) {
  if (symbol.is_func) {
    *result = true;
  }
}

TEST(read_elf, parse_symbols_from_elf_file) {
  char elf_file[PATH_MAX];
  ssize_t elf_file_len = readlink("/proc/self/exe", elf_file, sizeof(elf_file));
  ASSERT_GT(elf_file_len, 0L);
  ASSERT_LT(static_cast<size_t>(elf_file_len), sizeof(elf_file));
  elf_file[elf_file_len] = '\0';

  BuildId build_id;
  GetBuildIdFromElfFile(elf_file, &build_id);
  bool result = false;
  ASSERT_TRUE(ParseSymbolsFromElfFile(elf_file, build_id,
                                      std::bind(ParseSymbol, std::placeholders::_1, &result)));
  ASSERT_TRUE(result);
}

TEST(read_elf, arm_mapping_symbol) {
  ASSERT_TRUE(IsArmMappingSymbol("$a"));
  ASSERT_FALSE(IsArmMappingSymbol("$b"));
  ASSERT_TRUE(IsArmMappingSymbol("$a.anything"));
  ASSERT_FALSE(IsArmMappingSymbol("$a_no_dot"));
}
