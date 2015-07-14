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

#include "event_selection_set.h"

#include <base/logging.h>
#include <base/stringprintf.h>

#include "environment.h"
#include "event_attr.h"
#include "event_type.h"
#include "perf_regs.h"

bool IsBranchSamplingSupported() {
  const EventType* type = FindEventTypeByName("cpu-cycles");
  if (type == nullptr) {
    return false;
  }
  perf_event_attr attr = CreateDefaultPerfEventAttr(*type);
  attr.sample_type |= PERF_SAMPLE_BRANCH_STACK;
  attr.branch_sample_type = PERF_SAMPLE_BRANCH_ANY;
  return IsEventAttrSupportedByKernel(attr);
}

bool IsDwarfCallChainSamplingSupported() {
  const EventType* type = FindEventTypeByName("cpu-cycles");
  if (type == nullptr) {
    return false;
  }
  perf_event_attr attr = CreateDefaultPerfEventAttr(*type);
  attr.sample_type |= PERF_SAMPLE_CALLCHAIN | PERF_SAMPLE_REGS_USER | PERF_SAMPLE_STACK_USER;
  attr.exclude_callchain_user = 1;
  attr.sample_regs_user = GetSupportedRegMask();
  attr.sample_stack_user = 8192;
  return IsEventAttrSupportedByKernel(attr);
}

bool EventSelectionSet::AddEventType(const EventTypeAndModifier& event_type_modifier) {
  EventSelection selection;
  selection.event_type = event_type_modifier.event_type;
  selection.event_attr = CreateDefaultPerfEventAttr(event_type_modifier.event_type);
  selection.event_attr.exclude_user = event_type_modifier.exclude_user;
  selection.event_attr.exclude_kernel = event_type_modifier.exclude_kernel;
  selection.event_attr.exclude_hv = event_type_modifier.exclude_hv;
  selection.event_attr.exclude_host = event_type_modifier.exclude_host;
  selection.event_attr.exclude_guest = event_type_modifier.exclude_guest;
  selection.event_attr.precise_ip = event_type_modifier.precise_ip;
  if (!IsEventAttrSupportedByKernel(selection.event_attr)) {
    LOG(ERROR) << "Event type '" << selection.event_type.name << "' is not supported by the kernel";
    return false;
  }
  selections_.push_back(std::move(selection));
  return true;
}

void EventSelectionSet::SetEnableOnExec(bool enable) {
  for (auto& selection : selections_) {
    selection.event_attr.enable_on_exec = (enable ? 1 : 0);
  }
}

bool EventSelectionSet::GetEnableOnExec() {
  for (auto& selection : selections_) {
    if (selection.event_attr.enable_on_exec == 0) {
      return false;
    }
  }
  return true;
}

void EventSelectionSet::SampleIdAll() {
  for (auto& selection : selections_) {
    selection.event_attr.sample_id_all = 1;
  }
}

void EventSelectionSet::SetSampleFreq(uint64_t sample_freq) {
  for (auto& selection : selections_) {
    perf_event_attr& attr = selection.event_attr;
    attr.freq = 1;
    attr.sample_freq = sample_freq;
  }
}

void EventSelectionSet::SetSamplePeriod(uint64_t sample_period) {
  for (auto& selection : selections_) {
    perf_event_attr& attr = selection.event_attr;
    attr.freq = 0;
    attr.sample_period = sample_period;
  }
}

bool EventSelectionSet::SetBranchSampling(uint64_t branch_sample_type) {
  if (branch_sample_type != 0 &&
      (branch_sample_type & (PERF_SAMPLE_BRANCH_ANY | PERF_SAMPLE_BRANCH_ANY_CALL |
                             PERF_SAMPLE_BRANCH_ANY_RETURN | PERF_SAMPLE_BRANCH_IND_CALL)) == 0) {
    LOG(ERROR) << "Invalid branch_sample_type: 0x" << std::hex << branch_sample_type;
    return false;
  }
  if (branch_sample_type != 0 && !IsBranchSamplingSupported()) {
    LOG(ERROR) << "branch stack sampling is not supported on this device.";
    return false;
  }
  for (auto& selection : selections_) {
    perf_event_attr& attr = selection.event_attr;
    if (branch_sample_type != 0) {
      attr.sample_type |= PERF_SAMPLE_BRANCH_STACK;
    } else {
      attr.sample_type &= ~PERF_SAMPLE_BRANCH_STACK;
    }
    attr.branch_sample_type = branch_sample_type;
  }
  return true;
}

void EventSelectionSet::EnableFpCallChainSampling() {
  for (auto& selection : selections_) {
    selection.event_attr.sample_type |= PERF_SAMPLE_CALLCHAIN;
  }
}

bool EventSelectionSet::EnableDwarfCallChainSampling(uint32_t dump_stack_size) {
  if (!IsDwarfCallChainSamplingSupported()) {
    LOG(ERROR) << "dwarf callchain sampling is not supported on this device.";
    return false;
  }
  for (auto& selection : selections_) {
    selection.event_attr.sample_type |=
        PERF_SAMPLE_CALLCHAIN | PERF_SAMPLE_REGS_USER | PERF_SAMPLE_STACK_USER;
    selection.event_attr.exclude_callchain_user = 1;
    selection.event_attr.sample_regs_user = GetSupportedRegMask();
    selection.event_attr.sample_stack_user = dump_stack_size;
  }
  return true;
}

void EventSelectionSet::SetInherit(bool enable) {
  for (auto& selection : selections_) {
    selection.event_attr.inherit = (enable ? 1 : 0);
  }
}

bool EventSelectionSet::OpenEventFilesForAllCpus() {
  return OpenEventFilesForThreadsOnAllCpus({-1});
}

bool EventSelectionSet::OpenEventFilesForThreads(const std::vector<pid_t>& threads) {
  return OpenEventFiles(threads, {-1});
}

bool EventSelectionSet::OpenEventFilesForThreadsOnAllCpus(const std::vector<pid_t>& threads) {
  std::vector<int> cpus = GetOnlineCpus();
  if (cpus.empty()) {
    return false;
  }
  return OpenEventFiles(threads, cpus);
}

bool EventSelectionSet::OpenEventFiles(const std::vector<pid_t>& threads,
                                       const std::vector<int>& cpus) {
  for (auto& selection : selections_) {
    for (auto& tid : threads) {
      size_t open_per_thread = 0;
      for (auto& cpu : cpus) {
        auto event_fd = EventFd::OpenEventFile(selection.event_attr, tid, cpu);
        if (event_fd != nullptr) {
          selection.event_fds.push_back(std::move(event_fd));
          ++open_per_thread;
        }
      }
      // As the online cpus can be enabled or disabled at runtime, we may not open event file for
      // all cpus successfully. But we should open at least one cpu successfully.
      if (open_per_thread == 0) {
        PLOG(ERROR) << "failed to open perf event file for event_type " << selection.event_type.name
                    << " for "
                    << (tid == -1 ? "all threads" : android::base::StringPrintf(" thread %d", tid));
        return false;
      }
    }
  }
  return true;
}

bool EventSelectionSet::EnableEvents() {
  for (auto& selection : selections_) {
    for (auto& event_fd : selection.event_fds) {
      if (!event_fd->EnableEvent()) {
        return false;
      }
    }
  }
  return true;
}

bool EventSelectionSet::ReadCounters(
    std::map<const EventType*, std::vector<PerfCounter>>* counters_map) {
  for (auto& selection : selections_) {
    std::vector<PerfCounter> counters;
    for (auto& event_fd : selection.event_fds) {
      PerfCounter counter;
      if (!event_fd->ReadCounter(&counter)) {
        return false;
      }
      counters.push_back(counter);
    }
    counters_map->insert(std::make_pair(&selection.event_type, counters));
  }
  return true;
}

void EventSelectionSet::PreparePollForEventFiles(std::vector<pollfd>* pollfds) {
  for (auto& selection : selections_) {
    for (auto& event_fd : selection.event_fds) {
      pollfd poll_fd;
      event_fd->PreparePollForMmapData(&poll_fd);
      pollfds->push_back(poll_fd);
    }
  }
}

bool EventSelectionSet::MmapEventFiles(size_t mmap_pages) {
  for (auto& selection : selections_) {
    for (auto& event_fd : selection.event_fds) {
      if (!event_fd->MmapContent(mmap_pages)) {
        return false;
      }
    }
  }
  return true;
}

static bool ReadMmapEventDataForFd(std::unique_ptr<EventFd>& event_fd,
                                   std::function<bool(const char*, size_t)> callback,
                                   bool* have_data) {
  *have_data = false;
  while (true) {
    char* data;
    size_t size = event_fd->GetAvailableMmapData(&data);
    if (size == 0) {
      break;
    }
    if (!callback(data, size)) {
      return false;
    }
    *have_data = true;
    event_fd->DiscardMmapData(size);
  }
  return true;
}

bool EventSelectionSet::ReadMmapEventData(std::function<bool(const char*, size_t)> callback) {
  for (auto& selection : selections_) {
    for (auto& event_fd : selection.event_fds) {
      while (true) {
        bool have_data;
        if (!ReadMmapEventDataForFd(event_fd, callback, &have_data)) {
          return false;
        }
        if (!have_data) {
          break;
        }
      }
    }
  }
  return true;
}

std::string EventSelectionSet::FindEventFileNameById(uint64_t id) {
  for (auto& selection : selections_) {
    for (auto& event_fd : selection.event_fds) {
      if (event_fd->Id() == id) {
        return event_fd->Name();
      }
    }
  }
  return "";
}

EventSelectionSet::EventSelection* EventSelectionSet::FindSelectionByType(
    const EventType& event_type) {
  for (auto& selection : selections_) {
    if (selection.event_type.name == event_type.name) {
      return &selection;
    }
  }
  return nullptr;
}

const perf_event_attr& EventSelectionSet::FindEventAttrByType(const EventType& event_type) {
  return FindSelectionByType(event_type)->event_attr;
}

const std::vector<std::unique_ptr<EventFd>>& EventSelectionSet::FindEventFdsByType(
    const EventType& event_type) {
  return FindSelectionByType(event_type)->event_fds;
}
