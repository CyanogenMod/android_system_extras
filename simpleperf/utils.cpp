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

#include "utils.h"

#include <dirent.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <string>

#include <android-base/logging.h>

void OneTimeFreeAllocator::Clear() {
  for (auto& p : v_) {
    delete[] p;
  }
  v_.clear();
  cur_ = nullptr;
  end_ = nullptr;
}

const char* OneTimeFreeAllocator::AllocateString(const std::string& s) {
  size_t size = s.size() + 1;
  if (cur_ + size > end_) {
    size_t alloc_size = std::max(size, unit_size_);
    char* p = new char[alloc_size];
    v_.push_back(p);
    cur_ = p;
    end_ = p + alloc_size;
  }
  strcpy(cur_, s.c_str());
  const char* result = cur_;
  cur_ += size;
  return result;
}

void PrintIndented(size_t indent, const char* fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  printf("%*s", static_cast<int>(indent * 2), "");
  vprintf(fmt, ap);
  va_end(ap);
}

bool IsPowerOfTwo(uint64_t value) {
  return (value != 0 && ((value & (value - 1)) == 0));
}

void GetEntriesInDir(const std::string& dirpath, std::vector<std::string>* files,
                     std::vector<std::string>* subdirs) {
  if (files != nullptr) {
    files->clear();
  }
  if (subdirs != nullptr) {
    subdirs->clear();
  }
  DIR* dir = opendir(dirpath.c_str());
  if (dir == nullptr) {
    PLOG(DEBUG) << "can't open dir " << dirpath;
    return;
  }
  dirent* entry;
  while ((entry = readdir(dir)) != nullptr) {
    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
      continue;
    }
    if (IsDir(dirpath + std::string("/") + entry->d_name)) {
      if (subdirs != nullptr) {
        subdirs->push_back(entry->d_name);
      }
    } else {
      if (files != nullptr) {
        files->push_back(entry->d_name);
      }
    }
  }
  closedir(dir);
}

bool IsDir(const std::string& dirpath) {
  struct stat st;
  if (stat(dirpath.c_str(), &st) == 0) {
    if (S_ISDIR(st.st_mode)) {
      return true;
    }
  }
  return false;
}

bool IsRegularFile(const std::string& filename) {
  struct stat st;
  if (stat(filename.c_str(), &st) == 0) {
    if (S_ISREG(st.st_mode)) {
      return true;
    }
  }
  return false;
}
