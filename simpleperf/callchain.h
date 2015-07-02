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

#ifndef SIMPLE_PERF_CALLCHAIN_H_
#define SIMPLE_PERF_CALLCHAIN_H_

#include <memory>
#include <vector>

struct SampleEntry;

struct CallChainNode {
  uint64_t period;
  uint64_t children_period;
  std::vector<SampleEntry*> chain;
  std::vector<std::unique_ptr<CallChainNode>> children;
};

struct CallChainRoot {
  uint64_t children_period;
  std::vector<std::unique_ptr<CallChainNode>> children;

  CallChainRoot() : children_period(0) {
  }

  void AddCallChain(const std::vector<SampleEntry*>& callchain, uint64_t period);
  void SortByPeriod();
};

#endif  // SIMPLE_PERF_CALLCHAIN_H_
