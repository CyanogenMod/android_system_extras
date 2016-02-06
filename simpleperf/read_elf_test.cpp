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

static const unsigned char elf_file_build_id[] = {
    0x76, 0x00, 0x32, 0x9e, 0x31, 0x05, 0x8e, 0x12, 0xb1, 0x45,
    0xd1, 0x53, 0xef, 0x27, 0xcd, 0x40, 0xe1, 0xa5, 0xf7, 0xb9
};

TEST(read_elf, GetBuildIdFromElfFile) {
  BuildId build_id;
  ASSERT_TRUE(GetBuildIdFromElfFile(GetTestData("elf_file"), &build_id));
  ASSERT_EQ(build_id, BuildId(elf_file_build_id));
}

static void ParseSymbol(const ElfFileSymbol& symbol, std::map<std::string, ElfFileSymbol>* symbols) {
  (*symbols)[symbol.name] = symbol;
}

static void CheckElfFileSymbols(const std::map<std::string, ElfFileSymbol>& symbols) {
  auto pos = symbols.find("GlobalVar");
  ASSERT_NE(pos, symbols.end());
  ASSERT_FALSE(pos->second.is_func);
  pos = symbols.find("GlobalFunc");
  ASSERT_NE(pos, symbols.end());
  ASSERT_TRUE(pos->second.is_func);
  ASSERT_TRUE(pos->second.is_in_text_section);
}

TEST(read_elf, parse_symbols_from_elf_file_with_correct_build_id) {
  BuildId build_id(elf_file_build_id);
  std::map<std::string, ElfFileSymbol> symbols;
  ASSERT_TRUE(ParseSymbolsFromElfFile(GetTestData("elf_file"), build_id,
                                      std::bind(ParseSymbol, std::placeholders::_1, &symbols)));
  CheckElfFileSymbols(symbols);
}

TEST(read_elf, parse_symbols_from_elf_file_without_build_id) {
  BuildId build_id;
  std::map<std::string, ElfFileSymbol> symbols;
  ASSERT_TRUE(ParseSymbolsFromElfFile(GetTestData("elf_file"), build_id,
                                      std::bind(ParseSymbol, std::placeholders::_1, &symbols)));
  CheckElfFileSymbols(symbols);
}

TEST(read_elf, parse_symbols_from_elf_file_with_wrong_build_id) {
  BuildId build_id("wrong_build_id");
  std::map<std::string, ElfFileSymbol> symbols;
  ASSERT_FALSE(ParseSymbolsFromElfFile(GetTestData("elf_file"), build_id,
                                       std::bind(ParseSymbol, std::placeholders::_1, &symbols)));
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
  ASSERT_TRUE(IsValidElfPath(GetTestData("elf_file")));
}
