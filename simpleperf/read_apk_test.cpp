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

#include "read_apk.h"

#include <gtest/gtest.h>
#include "get_test_data.h"
#include "test_util.h"


TEST(read_apk, IsValidApkPath) {
  ASSERT_FALSE(IsValidApkPath("/dev/zero"));
  ASSERT_FALSE(IsValidApkPath(GetTestData(ELF_FILE)));
  ASSERT_TRUE(IsValidApkPath(GetTestData(APK_FILE)));
}

TEST(read_apk, FindElfInApkByOffset) {
  ApkInspector inspector;
  ASSERT_TRUE(inspector.FindElfInApkByOffset("/dev/null", 0) == nullptr);
  ASSERT_TRUE(inspector.FindElfInApkByOffset(GetTestData(APK_FILE), 0) == nullptr);
  // Test if we can read the EmbeddedElf using an offset inside its [offset, offset+size] range
  // in the apk file.
  EmbeddedElf* ee = inspector.FindElfInApkByOffset(GetTestData(APK_FILE),
                                                   NATIVELIB_OFFSET_IN_APK + NATIVELIB_SIZE_IN_APK / 2);
  ASSERT_TRUE(ee != nullptr);
  ASSERT_EQ(NATIVELIB_IN_APK, ee->entry_name());
  ASSERT_EQ(NATIVELIB_OFFSET_IN_APK, ee->entry_offset());
  ASSERT_EQ(NATIVELIB_SIZE_IN_APK, ee->entry_size());
}

TEST(read_apk, FindElfInApkByName) {
  ASSERT_TRUE(ApkInspector::FindElfInApkByName("/dev/null", "") == nullptr);
  ASSERT_TRUE(ApkInspector::FindElfInApkByName(GetTestData(APK_FILE), "") == nullptr);
  auto ee = ApkInspector::FindElfInApkByName(GetTestData(APK_FILE), NATIVELIB_IN_APK);
  ASSERT_TRUE(ee != nullptr);
  ASSERT_EQ(NATIVELIB_OFFSET_IN_APK, ee->entry_offset());
  ASSERT_EQ(NATIVELIB_SIZE_IN_APK, ee->entry_size());
}

TEST(read_apk, GetBuildIdFromApkFile) {
  BuildId build_id;
  ASSERT_TRUE(GetBuildIdFromApkFile(GetTestData(APK_FILE), NATIVELIB_IN_APK, &build_id));
  ASSERT_EQ(build_id, native_lib_build_id);
}

TEST(read_apk, ParseSymbolsFromApkFile) {
  std::map<std::string, ElfFileSymbol> symbols;
  ASSERT_TRUE(ParseSymbolsFromApkFile(GetTestData(APK_FILE), NATIVELIB_IN_APK, native_lib_build_id,
                                      std::bind(ParseSymbol, std::placeholders::_1, &symbols)));
  CheckElfFileSymbols(symbols);
}
