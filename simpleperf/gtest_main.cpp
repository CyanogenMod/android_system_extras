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

#include <gtest/gtest.h>

#include <android-base/logging.h>

#include "get_test_data.h"
#include "utils.h"

static std::string testdata_dir;

int main(int argc, char** argv) {
  InitLogging(argv, android::base::StderrLogger);
  testing::InitGoogleTest(&argc, argv);
  for (int i = 1; i < argc; ++i) {
    if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
      testdata_dir = argv[i + 1];
      break;
    }
  }
  if (testdata_dir.empty()) {
    printf("Usage: simpleperf_unit_test -t <testdata_dir>\n");
    return 1;
  }
  if (testdata_dir.back() != '/') {
    testdata_dir.push_back('/');
  }
  return RUN_ALL_TESTS();
}

std::string GetTestData(const std::string& filename) {
  return testdata_dir + filename;
}

const std::string& GetTestDataDir() {
  return testdata_dir;
}
