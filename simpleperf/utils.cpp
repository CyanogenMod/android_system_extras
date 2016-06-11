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
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <map>
#include <string>

#include <android-base/file.h>
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


FileHelper FileHelper::OpenReadOnly(const std::string& filename) {
    int fd = TEMP_FAILURE_RETRY(open(filename.c_str(), O_RDONLY | O_BINARY));
    return FileHelper(fd);
}

FileHelper FileHelper::OpenWriteOnly(const std::string& filename) {
    int fd = TEMP_FAILURE_RETRY(open(filename.c_str(), O_WRONLY | O_BINARY | O_CREAT, 0644));
    return FileHelper(fd);
}

FileHelper::~FileHelper() {
  if (fd_ != -1) {
    close(fd_);
  }
}

ArchiveHelper::ArchiveHelper(int fd, const std::string& debug_filename) : valid_(false) {
  int rc = OpenArchiveFd(fd, "", &handle_, false);
  if (rc == 0) {
    valid_ = true;
  } else {
    LOG(ERROR) << "Failed to open archive " << debug_filename << ": " << ErrorCodeString(rc);
  }
}

ArchiveHelper::~ArchiveHelper() {
  if (valid_) {
    CloseArchive(handle_);
  }
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

uint64_t GetFileSize(const std::string& filename) {
  struct stat st;
  if (stat(filename.c_str(), &st) == 0) {
    return static_cast<uint64_t>(st.st_size);
  }
  return 0;
}

bool MkdirWithParents(const std::string& path) {
  size_t prev_end = 0;
  while (prev_end < path.size()) {
    size_t next_end = path.find('/', prev_end + 1);
    if (next_end == std::string::npos) {
      break;
    }
    std::string dir_path = path.substr(0, next_end);
    if (!IsDir(dir_path)) {
#if defined(_WIN32)
      int ret = mkdir(dir_path.c_str());
#else
      int ret = mkdir(dir_path.c_str(), 0755);
#endif
      if (ret != 0) {
        PLOG(ERROR) << "failed to create dir " << dir_path;
        return false;
      }
    }
    prev_end = next_end;
  }
  return true;
}

bool GetLogSeverity(const std::string& name, android::base::LogSeverity* severity) {
  static std::map<std::string, android::base::LogSeverity> log_severity_map = {
      {"verbose", android::base::VERBOSE},
      {"debug", android::base::DEBUG},
      {"warning", android::base::WARNING},
      {"error", android::base::ERROR},
      {"fatal", android::base::FATAL},
  };
  auto it = log_severity_map.find(name);
  if (it != log_severity_map.end()) {
    *severity = it->second;
    return true;
  }
  return false;
}

bool IsRoot() {
  static int is_root = -1;
  if (is_root == -1) {
#if defined(__linux__)
    is_root = (getuid() == 0) ? 1 : 0;
#else
    is_root = 0;
#endif
  }
  return is_root == 1;
}
