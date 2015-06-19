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

#ifndef SIMPLE_PERF_UTILS_H_
#define SIMPLE_PERF_UTILS_H_

#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <vector>

#define ALIGN(value, alignment) (((value) + (alignment)-1) & ~((alignment)-1))

class LineReader {
 public:
  LineReader(FILE* fp) : fp_(fp), buf_(nullptr), bufsize_(0) {
  }

  ~LineReader() {
    free(buf_);
    fclose(fp_);
  }

  char* ReadLine() {
    if (getline(&buf_, &bufsize_, fp_) != -1) {
      return buf_;
    }
    return nullptr;
  }

  size_t MaxLineSize() {
    return bufsize_;
  }

 private:
  FILE* fp_;
  char* buf_;
  size_t bufsize_;
};

class SignalHandlerRegister {
 public:
  SignalHandlerRegister(const std::vector<int>& signums, void (*handler)(int)) {
    for (auto& sig : signums) {
      sighandler_t old_handler = signal(sig, handler);
      saved_signal_handlers_.push_back(std::make_pair(sig, old_handler));
    }
  }

  ~SignalHandlerRegister() {
    for (auto& pair : saved_signal_handlers_) {
      signal(pair.first, pair.second);
    }
  }

 private:
  std::vector<std::pair<int, sighandler_t>> saved_signal_handlers_;
};

void PrintIndented(size_t indent, const char* fmt, ...);

bool IsPowerOfTwo(uint64_t value);

void GetEntriesInDir(const std::string& dirpath, std::vector<std::string>* files,
                     std::vector<std::string>* subdirs);
bool IsDir(const std::string& dirpath);
bool RemovePossibleFile(const std::string& filename);

#endif  // SIMPLE_PERF_UTILS_H_
