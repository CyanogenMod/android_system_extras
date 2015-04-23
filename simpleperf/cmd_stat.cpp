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

#include <inttypes.h>
#include <stdio.h>
#include <chrono>
#include <string>
#include <vector>

#include <base/logging.h>
#include <base/strings.h>

#include "command.h"
#include "environment.h"
#include "event_attr.h"
#include "event_fd.h"
#include "event_type.h"
#include "perf_event.h"
#include "utils.h"
#include "workload.h"

static std::vector<std::string> default_measured_event_types{
    "cpu-cycles", "stalled-cycles-frontend", "stalled-cycles-backend", "instructions",
    "branch-instructions", "branch-misses", "task-clock", "context-switches", "page-faults",
};

class StatCommandImpl {
 public:
  StatCommandImpl() : verbose_mode_(false), system_wide_collection_(false) {
  }

  bool Run(const std::vector<std::string>& args);

 private:
  bool ParseOptions(const std::vector<std::string>& args, std::vector<std::string>* non_option_args);
  bool AddMeasuredEventType(const std::string& event_type_name,
                            bool report_unsupported_types = true);
  bool AddDefaultMeasuredEventTypes();
  bool OpenEventFilesForCpus(const std::vector<int>& cpus);
  bool OpenEventFilesForProcess(pid_t pid);
  bool StartCounting();
  bool StopCounting();
  bool ReadCounters();
  bool ShowCounters(std::chrono::steady_clock::duration counting_duration);

  struct EventElem {
    const EventType* const event_type;
    std::vector<std::unique_ptr<EventFd>> event_fds;
    std::vector<PerfCounter> event_counters;
    PerfCounter sum_counter;

    EventElem(const EventType* event_type) : event_type(event_type) {
    }
  };

  std::vector<EventElem> measured_events_;
  bool verbose_mode_;
  bool system_wide_collection_;
};

bool StatCommandImpl::Run(const std::vector<std::string>& args) {
  // 1. Parse options.
  std::vector<std::string> workload_args;
  if (!ParseOptions(args, &workload_args)) {
    return false;
  }

  // 2. Add default measured event types.
  if (measured_events_.empty()) {
    if (!AddDefaultMeasuredEventTypes()) {
      return false;
    }
  }

  // 3. Create workload.
  if (workload_args.empty()) {
    workload_args = std::vector<std::string>({"sleep", "1"});
  }
  std::unique_ptr<Workload> workload = Workload::CreateWorkload(workload_args);
  if (workload == nullptr) {
    return false;
  }

  // 4. Open perf_event_files.
  if (system_wide_collection_) {
    std::vector<int> cpus = GetOnlineCpus();
    if (cpus.empty() || !OpenEventFilesForCpus(cpus)) {
      return false;
    }
  } else {
    if (!OpenEventFilesForProcess(workload->GetWorkPid())) {
      return false;
    }
  }

  // 5. Count events while workload running.
  auto start_time = std::chrono::steady_clock::now();
  if (!StartCounting()) {
    return false;
  }
  if (!workload->Start()) {
    return false;
  }
  workload->WaitFinish();
  if (!StopCounting()) {
    return false;
  }
  auto end_time = std::chrono::steady_clock::now();

  // 6. Read and print counters.
  if (!ReadCounters()) {
    return false;
  }
  if (!ShowCounters(end_time - start_time)) {
    return false;
  }

  return true;
}

bool StatCommandImpl::ParseOptions(const std::vector<std::string>& args,
                                   std::vector<std::string>* non_option_args) {
  size_t i;
  for (i = 0; i < args.size() && args[i].size() > 0 && args[i][0] == '-'; ++i) {
    if (args[i] == "-a") {
      system_wide_collection_ = true;
    } else if (args[i] == "-e") {
      if (i + 1 == args.size()) {
        LOG(ERROR) << "No event list following -e option. Try `simpleperf help stat`";
        return false;
      }
      ++i;
      std::vector<std::string> event_types = android::base::Split(args[i], ",");
      for (auto& event_type : event_types) {
        if (!AddMeasuredEventType(event_type)) {
          return false;
        }
      }
    } else if (args[i] == "--verbose") {
      verbose_mode_ = true;
    } else {
      LOG(ERROR) << "Unknown option for stat command: " << args[i];
      LOG(ERROR) << "Try `simpleperf help stat`";
      return false;
    }
  }

  if (non_option_args != nullptr) {
    non_option_args->clear();
    for (; i < args.size(); ++i) {
      non_option_args->push_back(args[i]);
    }
  }
  return true;
}

bool StatCommandImpl::AddMeasuredEventType(const std::string& event_type_name,
                                           bool report_unsupported_types) {
  const EventType* event_type = EventTypeFactory::FindEventTypeByName(event_type_name);
  if (event_type == nullptr) {
    LOG(ERROR) << "Unknown event_type: " << event_type_name;
    LOG(ERROR) << "Try `simpleperf help list` to list all possible event type names";
    return false;
  }
  if (!event_type->IsSupportedByKernel()) {
    (report_unsupported_types ? LOG(ERROR) : LOG(DEBUG)) << "Event type " << event_type->name
                                                         << " is not supported by the kernel";
    return false;
  }
  measured_events_.push_back(EventElem(event_type));
  return true;
}

bool StatCommandImpl::AddDefaultMeasuredEventTypes() {
  for (auto& name : default_measured_event_types) {
    // It is not an error when some event types in the default list are not supported by the kernel.
    AddMeasuredEventType(name, false);
  }
  if (measured_events_.empty()) {
    LOG(ERROR) << "Failed to add any supported default measured types";
    return false;
  }
  return true;
}

bool StatCommandImpl::OpenEventFilesForCpus(const std::vector<int>& cpus) {
  for (auto& elem : measured_events_) {
    EventAttr attr = EventAttr::CreateDefaultAttrToMonitorEvent(*elem.event_type);
    std::vector<std::unique_ptr<EventFd>> event_fds;
    for (auto& cpu : cpus) {
      auto event_fd = EventFd::OpenEventFileForCpu(attr, cpu);
      if (event_fd != nullptr) {
        event_fds.push_back(std::move(event_fd));
      }
    }
    // As the online cpus can be enabled or disabled at runtime, we may not open perf_event_file
    // for all cpus successfully. But we should open at least one cpu successfully for each event
    // type.
    if (event_fds.empty()) {
      LOG(ERROR) << "failed to open perf_event_files for event_type " << elem.event_type->name
                 << " on all cpus";
      return false;
    }
    elem.event_fds = std::move(event_fds);
  }
  return true;
}

bool StatCommandImpl::OpenEventFilesForProcess(pid_t pid) {
  for (auto& elem : measured_events_) {
    EventAttr attr = EventAttr::CreateDefaultAttrToMonitorEvent(*elem.event_type);
    std::vector<std::unique_ptr<EventFd>> event_fds;
    auto event_fd = EventFd::OpenEventFileForProcess(attr, pid);
    if (event_fd == nullptr) {
      PLOG(ERROR) << "failed to open perf_event_file for event_type " << elem.event_type->name
                  << " on pid " << pid;
      return false;
    }
    event_fds.push_back(std::move(event_fd));
    elem.event_fds = std::move(event_fds);
  }
  return true;
}

bool StatCommandImpl::StartCounting() {
  for (auto& elem : measured_events_) {
    for (auto& event_fd : elem.event_fds) {
      if (!event_fd->EnableEvent()) {
        return false;
      }
    }
  }
  return true;
}

bool StatCommandImpl::StopCounting() {
  for (auto& elem : measured_events_) {
    for (auto& event_fd : elem.event_fds) {
      if (!event_fd->DisableEvent()) {
        return false;
      }
    }
  }
  return true;
}

bool StatCommandImpl::ReadCounters() {
  for (auto& elem : measured_events_) {
    std::vector<PerfCounter> event_counters;
    for (auto& event_fd : elem.event_fds) {
      PerfCounter counter;
      if (!event_fd->ReadCounter(&counter)) {
        return false;
      }
      event_counters.push_back(counter);
    }
    PerfCounter sum_counter = event_counters.front();
    for (size_t i = 1; i < event_counters.size(); ++i) {
      sum_counter.value += event_counters[i].value;
      sum_counter.time_enabled += event_counters[i].time_enabled;
      sum_counter.time_running += event_counters[i].time_running;
    }
    elem.event_counters = event_counters;
    elem.sum_counter = sum_counter;
  }
  return true;
}

bool StatCommandImpl::ShowCounters(std::chrono::steady_clock::duration counting_duration) {
  printf("Performance counter statistics:\n\n");
  for (auto& elem : measured_events_) {
    std::string event_type_name = elem.event_type->name;

    if (verbose_mode_) {
      auto& event_fds = elem.event_fds;
      auto& counters = elem.event_counters;
      for (size_t i = 0; i < elem.event_fds.size(); ++i) {
        printf("%s: value %'" PRId64 ", time_enabled %" PRId64 ", time_disabled %" PRId64
               ", id %" PRId64 "\n",
               event_fds[i]->Name().c_str(), counters[i].value, counters[i].time_enabled,
               counters[i].time_running, counters[i].id);
      }
    }

    auto& counter = elem.sum_counter;
    bool scaled = false;
    int64_t scaled_count = counter.value;
    if (counter.time_running < counter.time_enabled) {
      if (counter.time_running == 0) {
        scaled_count = 0;
      } else {
        scaled = true;
        scaled_count = static_cast<int64_t>(static_cast<double>(counter.value) *
                                            counter.time_enabled / counter.time_running);
      }
    }
    printf("%'30" PRId64 "%s  %s\n", scaled_count, scaled ? "(scaled)" : "       ",
           event_type_name.c_str());
  }
  printf("\n");
  printf("Total test time: %lf seconds.\n",
         std::chrono::duration_cast<std::chrono::duration<double>>(counting_duration).count());
  return true;
}

class StatCommand : public Command {
 public:
  StatCommand()
      : Command("stat", "gather performance counter information",
                "Usage: simpleperf stat [options] [command [command-args]]\n"
                "    Gather performance counter information of running [command]. If [command]\n"
                "    is not specified, sleep 1 is used instead.\n\n"
                "    -a           Collect system-wide information.\n"
                "    -e event1,event2,... Select the event list to count. Use `simpleperf list`\n"
                "                         to find all possible event names.\n"
                "    --verbose    Show result in verbose mode.\n"
                "    --help       Print this help information.\n") {
  }

  bool Run(const std::vector<std::string>& args) override {
    for (auto& arg : args) {
      if (arg == "--help") {
        printf("%s\n", LongHelpString().c_str());
        return true;
      }
    }
    StatCommandImpl impl;
    return impl.Run(args);
  }
};

StatCommand stat_command;
