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

#include "environment.h"

#include <stdlib.h>
#include <vector>

#include <base/logging.h>

#include "utils.h"

std::vector<int> GetOnlineCpus() {
  std::vector<int> result;
  FILE* fp = fopen("/sys/devices/system/cpu/online", "re");
  if (fp == nullptr) {
    PLOG(ERROR) << "can't open online cpu information";
    return result;
  }

  LineReader reader(fp);
  char* line;
  if ((line = reader.ReadLine()) != nullptr) {
    result = GetOnlineCpusFromString(line);
  }
  CHECK(!result.empty()) << "can't get online cpu information";
  return result;
}

std::vector<int> GetOnlineCpusFromString(const std::string& s) {
  std::vector<int> result;
  bool have_dash = false;
  const char* p = s.c_str();
  char* endp;
  long cpu;
  // Parse line like: 0,1-3, 5, 7-8
  while ((cpu = strtol(p, &endp, 10)) != 0 || endp != p) {
    if (have_dash && result.size() > 0) {
      for (int t = result.back() + 1; t < cpu; ++t) {
        result.push_back(t);
      }
    }
    have_dash = false;
    result.push_back(cpu);
    p = endp;
    while (!isdigit(*p) && *p != '\0') {
      if (*p == '-') {
        have_dash = true;
      }
      ++p;
    }
  }
  return result;
}
