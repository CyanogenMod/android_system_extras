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

#ifndef SIMPLE_PERF_BUILD_ID_H_
#define SIMPLE_PERF_BUILD_ID_H_

#include <string.h>
#include <algorithm>
#include <base/stringprintf.h>

constexpr size_t BUILD_ID_SIZE = 20;

class BuildId {
 public:
  static size_t Size() {
    return BUILD_ID_SIZE;
  }

  BuildId() {
    memset(data_, '\0', BUILD_ID_SIZE);
  }

  BuildId(const void* data, size_t len = BUILD_ID_SIZE) : BuildId() {
    memcpy(data_, data, std::min(len, BUILD_ID_SIZE));
  }

  const unsigned char* Data() const {
    return data_;
  }

  std::string ToString() const {
    std::string s = "0x";
    for (size_t i = 0; i < BUILD_ID_SIZE; ++i) {
      s += android::base::StringPrintf("%02x", data_[i]);
    }
    return s;
  }

  bool operator==(const BuildId& build_id) const {
    return memcmp(data_, build_id.data_, BUILD_ID_SIZE) == 0;
  }

 private:
  unsigned char data_[BUILD_ID_SIZE];
};

#endif  // SIMPLE_PERF_BUILD_ID_H_
