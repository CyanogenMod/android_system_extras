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

#ifndef SIMPLE_PERF_SCOPED_SIGNAL_HANDLER_H_
#define SIMPLE_PERF_SCOPED_SIGNAL_HANDLER_H_

#include <signal.h>

#include <vector>

class ScopedSignalHandler {
 public:
  ScopedSignalHandler(const std::vector<int>& signums, void (*handler)(int)) {
    for (auto& sig : signums) {
      sig_t old_handler = signal(sig, handler);
      saved_signal_handlers_.push_back(std::make_pair(sig, old_handler));
    }
  }

  ~ScopedSignalHandler() {
    for (auto& pair : saved_signal_handlers_) {
      signal(pair.first, pair.second);
    }
  }

 private:
  std::vector<std::pair<int, sig_t>> saved_signal_handlers_;
};

#endif  // SIMPLE_PERF_SCOPED_SIGNAL_HANDLER_H_
