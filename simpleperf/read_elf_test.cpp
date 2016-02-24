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

#include <map>
#include "get_test_data.h"

TEST(read_elf, GetBuildIdFromElfFile) {
  BuildId build_id;
  ASSERT_TRUE(GetBuildIdFromElfFile(GetTestData(ELF_FILE), &build_id));
  ASSERT_EQ(build_id, BuildId(elf_file_build_id));
}

TEST(read_elf, GetBuildIdFromEmbeddedElfFile) {
  BuildId build_id;
  ASSERT_TRUE(GetBuildIdFromEmbeddedElfFile(GetTestData(APK_FILE), NATIVELIB_OFFSET_IN_APK,
                                            NATIVELIB_SIZE_IN_APK, &build_id));
  ASSERT_EQ(build_id, native_lib_build_id);
}

void ParseSymbol(const ElfFileSymbol& symbol, std::map<std::string, ElfFileSymbol>* symbols) {
  (*symbols)[symbol.name] = symbol;
}

void CheckElfFileSymbols(const std::map<std::string, ElfFileSymbol>& symbols) {
  auto pos = symbols.find("GlobalVar");
  ASSERT_NE(pos, symbols.end());
  ASSERT_FALSE(pos->second.is_func);
  pos = symbols.find("GlobalFunc");
  ASSERT_NE(pos, symbols.end());
  ASSERT_TRUE(pos->second.is_func);
  ASSERT_TRUE(pos->second.is_in_text_section);
}

TEST(read_elf, parse_symbols_from_elf_file_with_correct_build_id) {
  std::map<std::string, ElfFileSymbol> symbols;
  ASSERT_TRUE(ParseSymbolsFromElfFile(GetTestData(ELF_FILE), elf_file_build_id,
                                      std::bind(ParseSymbol, std::placeholders::_1, &symbols)));
  CheckElfFileSymbols(symbols);
}

TEST(read_elf, parse_symbols_from_elf_file_without_build_id) {
  std::map<std::string, ElfFileSymbol> symbols;
  ASSERT_TRUE(ParseSymbolsFromElfFile(GetTestData(ELF_FILE), BuildId(),
                                      std::bind(ParseSymbol, std::placeholders::_1, &symbols)));
  CheckElfFileSymbols(symbols);
}

TEST(read_elf, parse_symbols_from_elf_file_with_wrong_build_id) {
  BuildId build_id("01010101010101010101");
  std::map<std::string, ElfFileSymbol> symbols;
  ASSERT_FALSE(ParseSymbolsFromElfFile(GetTestData(ELF_FILE), build_id,
                                       std::bind(ParseSymbol, std::placeholders::_1, &symbols)));
}

TEST(read_elf, ParseSymbolsFromEmbeddedElfFile) {
  std::map<std::string, ElfFileSymbol> symbols;
  ASSERT_TRUE(ParseSymbolsFromEmbeddedElfFile(GetTestData(APK_FILE), NATIVELIB_OFFSET_IN_APK,
                                              NATIVELIB_SIZE_IN_APK, native_lib_build_id,
                                              std::bind(ParseSymbol, std::placeholders::_1, &symbols)));
  CheckElfFileSymbols(symbols);
}

TEST(read_elf, arm_mapping_symbol) {
  ASSERT_TRUE(IsArmMappingSymbol("$a"));
  ASSERT_FALSE(IsArmMappingSymbol("$b"));
  ASSERT_TRUE(IsArmMappingSymbol("$a.anything"));
  ASSERT_FALSE(IsArmMappingSymbol("$a_no_dot"));
}

TEST(read_elf, IsValidElfPath) {
  ASSERT_FALSE(IsValidElfPath("/dev/zero"));
  ASSERT_FALSE(IsValidElfPath("/sys/devices/system/cpu/online"));
  ASSERT_TRUE(IsValidElfPath(GetTestData(ELF_FILE)));
}
