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

static const std::string fibjar = "fibonacci.jar";
static const std::string jniapk = "has_embedded_native_libs.apk";

TEST(read_apk, IsValidJarOrApkPath) {
  ASSERT_FALSE(IsValidJarOrApkPath("/dev/zero"));
  ASSERT_FALSE(IsValidJarOrApkPath(GetTestData("elf_file")));
  ASSERT_TRUE(IsValidJarOrApkPath(GetTestData(fibjar)));
}

TEST(read_apk, CollectEmbeddedElfInfoFromApk) {
  ApkInspector inspector;
  ASSERT_TRUE(inspector.FindElfInApkByMmapOffset("/dev/null", 0) == nullptr);
  ASSERT_TRUE(inspector.FindElfInApkByMmapOffset(GetTestData(fibjar), 0) == nullptr);
  ASSERT_TRUE(inspector.FindElfInApkByMmapOffset(GetTestData(jniapk), 0) == nullptr);
  EmbeddedElf *ee1 = inspector.FindElfInApkByMmapOffset(GetTestData(jniapk), 0x91000);
  ASSERT_TRUE(ee1 != nullptr);
  ASSERT_EQ(ee1->entry_name(), "lib/armeabi-v7a/libframeworks_coretests_jni.so");
  ASSERT_TRUE(ee1->entry_offset() == 593920);
  ASSERT_TRUE(ee1->entry_size() == 13904);
}
