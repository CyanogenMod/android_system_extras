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
#include <signal.h>
#include <stdio.h>
#include <chrono>
#include <set>
#include <string>
#include <vector>

#include <base/logging.h>
#include <base/strings.h>

#include "command.h"
#include "environment.h"
#include "event_attr.h"
#include "event_fd.h"
#include "event_selection_set.h"
#include "event_type.h"
#include "utils.h"
#include "workload.h"

static std::vector<std::string> default_measured_event_types{
    "cpu-cycles",   "stalled-cycles-frontend", "stalled-cycles-backend",
    "instructions", "branch-instructions",     "branch-misses",
    "task-clock",   "context-switches",        "page-faults",
};

static volatile bool signaled;
static void signal_handler(int) {
  signaled = true;
}

class StatCommand : public Command {
 public:
  StatCommand()
      : Command("stat", "gather performance counter information",
                "Usage: simpleperf stat [options] [command [command-args]]\n"
                "    Gather performance counter information of running [command].\n"
                "    -a           Collect system-wide information.\n"
                "    -e event1[:modifier1],event2[:modifier2],...\n"
                "                 Select the event list to count. Use `simpleperf list` to find\n"
                "                 all possible event names. Modifiers can be added to define\n"
                "                 how the event should be monitored. Possible modifiers are:\n"
                "                   u - monitor user space events only\n"
                "                   k - monitor kernel space events only\n"
                "    --no-inherit\n"
                "                 Don't stat created child threads/processes.\n"
                "    -p pid1,pid2,...\n"
                "                 Stat events on existing processes. Mutually exclusive with -a.\n"
                "    -t tid1,tid2,...\n"
                "                 Stat events on existing threads. Mutually exclusive with -a.\n"
                "    --verbose    Show result in verbose mode.\n"),
        verbose_mode_(false),
        system_wide_collection_(false),
        child_inherit_(true) {
    signaled = false;
    signal_handler_register_.reset(
        new SignalHandlerRegister({SIGCHLD, SIGINT, SIGTERM}, signal_handler));
  }

  bool Run(const std::vector<std::string>& args);

 private:
  bool ParseOptions(const std::vector<std::string>& args, std::vector<std::string>* non_option_args);
  bool AddMeasuredEventType(const std::string& event_type_name);
  bool AddDefaultMeasuredEventTypes();
  bool SetEventSelection();
  bool ShowCounters(const std::map<const EventType*, std::vector<PerfCounter>>& counters_map,
                    std::chrono::steady_clock::duration counting_duration);

  bool verbose_mode_;
  bool system_wide_collection_;
  bool child_inherit_;
  std::vector<pid_t> monitored_threads_;
  std::vector<std::pair<std::string, EventTypeAndModifier>> measured_event_types_;
  EventSelectionSet event_selection_set_;

  std::unique_ptr<SignalHandlerRegister> signal_handler_register_;
};

bool StatCommand::Run(const std::vector<std::string>& args) {
  // 1. Parse options, and use default measured event types if not given.
  std::vector<std::string> workload_args;
  if (!ParseOptions(args, &workload_args)) {
    return false;
  }
  if (measured_event_types_.empty()) {
    if (!AddDefaultMeasuredEventTypes()) {
      return false;
    }
  }
  if (!SetEventSelection()) {
    return false;
  }

  // 2. Create workload.
  std::unique_ptr<Workload> workload;
  if (!workload_args.empty()) {
    workload = Workload::CreateWorkload(workload_args);
    if (workload == nullptr) {
      return false;
    }
  }
  if (!system_wide_collection_ && monitored_threads_.empty()) {
    if (workload != nullptr) {
      monitored_threads_.push_back(workload->GetPid());
      event_selection_set_.SetEnableOnExec(true);
    } else {
      LOG(ERROR) << "No threads to monitor. Try `simpleperf help stat` for help\n";
      return false;
    }
  }

  // 3. Open perf_event_files.
  if (system_wide_collection_) {
    if (!event_selection_set_.OpenEventFilesForAllCpus()) {
      return false;
    }
  } else {
    if (!event_selection_set_.OpenEventFilesForThreads(monitored_threads_)) {
      return false;
    }
  }

  // 4. Count events while workload running.
  auto start_time = std::chrono::steady_clock::now();
  if (!event_selection_set_.GetEnableOnExec()) {
    if (!event_selection_set_.EnableEvents()) {
      return false;
    }
  }
  if (workload != nullptr && !workload->Start()) {
    return false;
  }
  while (!signaled) {
    sleep(1);
  }
  auto end_time = std::chrono::steady_clock::now();

  // 5. Read and print counters.
  std::map<const EventType*, std::vector<PerfCounter>> counters_map;
  if (!event_selection_set_.ReadCounters(&counters_map)) {
    return false;
  }
  if (!ShowCounters(counters_map, end_time - start_time)) {
    return false;
  }
  return true;
}

bool StatCommand::ParseOptions(const std::vector<std::string>& args,
                               std::vector<std::string>* non_option_args) {
  std::set<pid_t> tid_set;
  size_t i;
  for (i = 0; i < args.size() && args[i].size() > 0 && args[i][0] == '-'; ++i) {
    if (args[i] == "-a") {
      system_wide_collection_ = true;
    } else if (args[i] == "-e") {
      if (!NextArgumentOrError(args, &i)) {
        return false;
      }
      std::vector<std::string> event_types = android::base::Split(args[i], ",");
      for (auto& event_type : event_types) {
        if (!AddMeasuredEventType(event_type)) {
          return false;
        }
      }
    } else if (args[i] == "--no-inherit") {
      child_inherit_ = false;
    } else if (args[i] == "-p") {
      if (!NextArgumentOrError(args, &i)) {
        return false;
      }
      if (!GetValidThreadsFromProcessString(args[i], &tid_set)) {
        return false;
      }
    } else if (args[i] == "-t") {
      if (!NextArgumentOrError(args, &i)) {
        return false;
      }
      if (!GetValidThreadsFromThreadString(args[i], &tid_set)) {
        return false;
      }
    } else if (args[i] == "--verbose") {
      verbose_mode_ = true;
    } else {
      ReportUnknownOption(args, i);
      return false;
    }
  }

  monitored_threads_.insert(monitored_threads_.end(), tid_set.begin(), tid_set.end());
  if (system_wide_collection_ && !monitored_threads_.empty()) {
    LOG(ERROR) << "Stat system wide and existing processes/threads can't be used at the same time.";
    return false;
  }

  if (non_option_args != nullptr) {
    non_option_args->clear();
    for (; i < args.size(); ++i) {
      non_option_args->push_back(args[i]);
    }
  }
  return true;
}

bool StatCommand::AddMeasuredEventType(const std::string& event_type_name) {
  std::unique_ptr<EventTypeAndModifier> event_type_modifier = ParseEventType(event_type_name);
  if (event_type_modifier == nullptr) {
    return false;
  }
  measured_event_types_.push_back(std::make_pair(event_type_name, *event_type_modifier));
  return true;
}

bool StatCommand::AddDefaultMeasuredEventTypes() {
  for (auto& name : default_measured_event_types) {
    // It is not an error when some event types in the default list are not supported by the kernel.
    const EventType* type = FindEventTypeByName(name);
    if (type != nullptr && IsEventAttrSupportedByKernel(CreateDefaultPerfEventAttr(*type))) {
      AddMeasuredEventType(name);
    }
  }
  if (measured_event_types_.empty()) {
    LOG(ERROR) << "Failed to add any supported default measured types";
    return false;
  }
  return true;
}

bool StatCommand::SetEventSelection() {
  for (auto& pair : measured_event_types_) {
    if (!event_selection_set_.AddEventType(pair.second)) {
      return false;
    }
  }
  event_selection_set_.SetInherit(child_inherit_);
  return true;
}

bool StatCommand::ShowCounters(
    const std::map<const EventType*, std::vector<PerfCounter>>& counters_map,
    std::chrono::steady_clock::duration counting_duration) {
  printf("Performance counter statistics:\n\n");

  for (auto& pair : counters_map) {
    auto& event_type = pair.first;
    auto& counters = pair.second;
    if (verbose_mode_) {
      for (auto& counter : counters) {
        printf("%s: value %'" PRId64 ", time_enabled %" PRId64 ", time_running %" PRId64
               ", id %" PRId64 "\n",
               event_selection_set_.FindEventFileNameById(counter.id).c_str(), counter.value,
               counter.time_enabled, counter.time_running, counter.id);
      }
    }

    PerfCounter sum_counter;
    memset(&sum_counter, 0, sizeof(sum_counter));
    for (auto& counter : counters) {
      sum_counter.value += counter.value;
      sum_counter.time_enabled += counter.time_enabled;
      sum_counter.time_running += counter.time_running;
    }
    bool scaled = false;
    int64_t scaled_count = sum_counter.value;
    if (sum_counter.time_running < sum_counter.time_enabled) {
      if (sum_counter.time_running == 0) {
        scaled_count = 0;
      } else {
        scaled = true;
        scaled_count = static_cast<int64_t>(static_cast<double>(sum_counter.value) *
                                            sum_counter.time_enabled / sum_counter.time_running);
      }
    }
    std::string event_type_name;
    for (auto& pair : measured_event_types_) {
      if (pair.second.event_type.name == event_type->name) {
        event_type_name = pair.first;
      }
    }
    printf("%'30" PRId64 "%s  %s\n", scaled_count, scaled ? "(scaled)" : "       ",
           event_type_name.c_str());
  }
  printf("\nTotal test time: %lf seconds.\n",
         std::chrono::duration_cast<std::chrono::duration<double>>(counting_duration).count());
  return true;
}

__attribute__((constructor)) static void RegisterStatCommand() {
  RegisterCommand("stat", [] { return std::unique_ptr<Command>(new StatCommand); });
}
