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

#include "callchain.h"

#include <string.h>

#include <queue>

#include <android-base/logging.h>
#include "sample_tree.h"

static bool MatchSampleByName(const SampleEntry* sample1, const SampleEntry* sample2) {
  return strcmp(sample1->symbol->Name(), sample2->symbol->Name()) == 0;
}

static size_t GetMatchingLengthInNode(const CallChainNode* node,
                                      const std::vector<SampleEntry*>& chain, size_t chain_start) {
  size_t i, j;
  for (i = 0, j = chain_start; i < node->chain.size() && j < chain.size(); ++i, ++j) {
    if (!MatchSampleByName(node->chain[i], chain[j])) {
      break;
    }
  }
  return i;
}

static CallChainNode* FindMatchingNode(const std::vector<std::unique_ptr<CallChainNode>>& nodes,
                                       const SampleEntry* sample) {
  for (auto& node : nodes) {
    if (MatchSampleByName(node->chain.front(), sample)) {
      return node.get();
    }
  }
  return nullptr;
}

static std::unique_ptr<CallChainNode> AllocateNode(const std::vector<SampleEntry*>& chain,
                                                   size_t chain_start, uint64_t period,
                                                   uint64_t children_period) {
  std::unique_ptr<CallChainNode> node(new CallChainNode);
  for (size_t i = chain_start; i < chain.size(); ++i) {
    node->chain.push_back(chain[i]);
  }
  node->period = period;
  node->children_period = children_period;
  return node;
}

static void SplitNode(CallChainNode* parent, size_t parent_length) {
  std::unique_ptr<CallChainNode> child =
      AllocateNode(parent->chain, parent_length, parent->period, parent->children_period);
  child->children = std::move(parent->children);
  parent->period = 0;
  parent->children_period = child->period + child->children_period;
  parent->chain.resize(parent_length);
  parent->children.clear();
  parent->children.push_back(std::move(child));
}

void CallChainRoot::AddCallChain(const std::vector<SampleEntry*>& callchain, uint64_t period) {
  children_period += period;
  CallChainNode* p = FindMatchingNode(children, callchain[0]);
  if (p == nullptr) {
    std::unique_ptr<CallChainNode> new_node = AllocateNode(callchain, 0, period, 0);
    children.push_back(std::move(new_node));
    return;
  }
  size_t callchain_pos = 0;
  while (true) {
    size_t match_length = GetMatchingLengthInNode(p, callchain, callchain_pos);
    CHECK_GT(match_length, 0u);
    callchain_pos += match_length;
    bool find_child = true;
    if (match_length < p->chain.size()) {
      SplitNode(p, match_length);
      find_child = false;  // No need to find matching node in p->children.
    }
    if (callchain_pos == callchain.size()) {
      p->period += period;
      return;
    }
    p->children_period += period;
    if (find_child) {
      CallChainNode* np = FindMatchingNode(p->children, callchain[callchain_pos]);
      if (np != nullptr) {
        p = np;
        continue;
      }
    }
    std::unique_ptr<CallChainNode> new_node = AllocateNode(callchain, callchain_pos, period, 0);
    p->children.push_back(std::move(new_node));
    break;
  }
}

static bool CompareNodeByPeriod(const std::unique_ptr<CallChainNode>& n1,
                                const std::unique_ptr<CallChainNode>& n2) {
  uint64_t period1 = n1->period + n1->children_period;
  uint64_t period2 = n2->period + n2->children_period;
  return period1 > period2;
}

void CallChainRoot::SortByPeriod() {
  std::queue<std::vector<std::unique_ptr<CallChainNode>>*> queue;
  queue.push(&children);
  while (!queue.empty()) {
    std::vector<std::unique_ptr<CallChainNode>>* v = queue.front();
    queue.pop();
    std::sort(v->begin(), v->end(), CompareNodeByPeriod);
    for (auto& node : *v) {
      queue.push(&node->children);
    }
  }
}
