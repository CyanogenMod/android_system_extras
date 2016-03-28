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

#include <poll.h>

#include <android-base/logging.h>
#include <android-base/stringprintf.h>

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
  attr.sample_regs_user = GetSupportedRegMask(GetBuildArch());
  attr.sample_stack_user = 8192;
  return IsEventAttrSupportedByKernel(attr);
}

bool EventSelectionSet::AddEventType(const EventTypeAndModifier& event_type_modifier) {
  EventSelection selection;
  selection.event_type_modifier = event_type_modifier;
  selection.event_attr = CreateDefaultPerfEventAttr(event_type_modifier.event_type);
  selection.event_attr.exclude_user = event_type_modifier.exclude_user;
  selection.event_attr.exclude_kernel = event_type_modifier.exclude_kernel;
  selection.event_attr.exclude_hv = event_type_modifier.exclude_hv;
  selection.event_attr.exclude_host = event_type_modifier.exclude_host;
  selection.event_attr.exclude_guest = event_type_modifier.exclude_guest;
  selection.event_attr.precise_ip = event_type_modifier.precise_ip;
  if (!IsEventAttrSupportedByKernel(selection.event_attr)) {
    LOG(ERROR) << "Event type '" << event_type_modifier.name << "' is not supported by the kernel";
    return false;
  }
  selections_.push_back(std::move(selection));
  UnionSampleType();
  return true;
}

// Union the sample type of different event attrs can make reading sample records in perf.data
// easier.
void EventSelectionSet::UnionSampleType() {
  uint64_t sample_type = 0;
  for (auto& selection : selections_) {
    sample_type |= selection.event_attr.sample_type;
  }
  for (auto& selection : selections_) {
    selection.event_attr.sample_type = sample_type;
  }
}

void EventSelectionSet::SetEnableOnExec(bool enable) {
  for (auto& selection : selections_) {
    // If sampling is enabled on exec, then it is disabled at startup, otherwise
    // it should be enabled at startup. Don't use ioctl(PERF_EVENT_IOC_ENABLE)
    // to enable it after perf_event_open(). Because some android kernels can't
    // handle ioctl() well when cpu-hotplug happens. See http://b/25193162.
    if (enable) {
      selection.event_attr.enable_on_exec = 1;
      selection.event_attr.disabled = 1;
    } else {
      selection.event_attr.enable_on_exec = 0;
      selection.event_attr.disabled = 0;
    }
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
    selection.event_attr.sample_regs_user = GetSupportedRegMask(GetBuildArch());
    selection.event_attr.sample_stack_user = dump_stack_size;
  }
  return true;
}

void EventSelectionSet::SetInherit(bool enable) {
  for (auto& selection : selections_) {
    selection.event_attr.inherit = (enable ? 1 : 0);
  }
}

static bool CheckIfCpusOnline(const std::vector<int>& cpus) {
  std::vector<int> online_cpus = GetOnlineCpus();
  for (const auto& cpu : cpus) {
    if (std::find(online_cpus.begin(), online_cpus.end(), cpu) == online_cpus.end()) {
      LOG(ERROR) << "cpu " << cpu << " is not online.";
      return false;
    }
  }
  return true;
}

bool EventSelectionSet::OpenEventFilesForCpus(const std::vector<int>& cpus) {
  return OpenEventFilesForThreadsOnCpus({-1}, cpus);
}

bool EventSelectionSet::OpenEventFilesForThreadsOnCpus(const std::vector<pid_t>& threads,
                                                       std::vector<int> cpus) {
  if (!cpus.empty()) {
    if (!CheckIfCpusOnline(cpus)) {
      return false;
    }
  } else {
    cpus = GetOnlineCpus();
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
          LOG(VERBOSE) << "OpenEventFile for tid " << tid << ", cpu " << cpu;
          selection.event_fds.push_back(std::move(event_fd));
          ++open_per_thread;
        }
      }
      // As the online cpus can be enabled or disabled at runtime, we may not open event file for
      // all cpus successfully. But we should open at least one cpu successfully.
      if (open_per_thread == 0) {
        PLOG(ERROR) << "failed to open perf event file for event_type "
                    << selection.event_type_modifier.name << " for "
                    << (tid == -1 ? "all threads" : android::base::StringPrintf(" thread %d", tid));
        return false;
      }
    }
  }
  return true;
}

bool EventSelectionSet::ReadCounters(std::vector<CountersInfo>* counters) {
  counters->clear();
  for (auto& selection : selections_) {
    CountersInfo counters_info;
    counters_info.event_type = &selection.event_type_modifier;
    for (auto& event_fd : selection.event_fds) {
      CountersInfo::CounterInfo counter_info;
      if (!event_fd->ReadCounter(&counter_info.counter)) {
        return false;
      }
      counter_info.tid = event_fd->ThreadId();
      counter_info.cpu = event_fd->Cpu();
      counters_info.counters.push_back(counter_info);
    }
    counters->push_back(counters_info);
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

EventSelectionSet::EventSelection* EventSelectionSet::FindSelectionByType(
    const EventTypeAndModifier& event_type_modifier) {
  for (auto& selection : selections_) {
    if (selection.event_type_modifier.name == event_type_modifier.name) {
      return &selection;
    }
  }
  return nullptr;
}

const perf_event_attr* EventSelectionSet::FindEventAttrByType(
    const EventTypeAndModifier& event_type_modifier) {
  EventSelection* selection = FindSelectionByType(event_type_modifier);
  return (selection != nullptr) ? &selection->event_attr : nullptr;
}

const std::vector<std::unique_ptr<EventFd>>* EventSelectionSet::FindEventFdsByType(
    const EventTypeAndModifier& event_type_modifier) {
  EventSelection* selection = FindSelectionByType(event_type_modifier);
  return (selection != nullptr) ? &selection->event_fds : nullptr;
}
