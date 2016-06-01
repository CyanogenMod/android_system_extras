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
#include <string.h>

#include <algorithm>
#include <chrono>
#include <set>
#include <string>
#include <vector>

#include <android-base/logging.h>
#include <android-base/strings.h>

#include "command.h"
#include "environment.h"
#include "event_attr.h"
#include "event_fd.h"
#include "event_selection_set.h"
#include "event_type.h"
#include "scoped_signal_handler.h"
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
                "    --cpu cpu_item1,cpu_item2,...\n"
                "                 Collect information only on the selected cpus. cpu_item can\n"
                "                 be a cpu number like 1, or a cpu range like 0-3.\n"
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
    scoped_signal_handler_.reset(
        new ScopedSignalHandler({SIGCHLD, SIGINT, SIGTERM}, signal_handler));
  }

  bool Run(const std::vector<std::string>& args);

 private:
  bool ParseOptions(const std::vector<std::string>& args, std::vector<std::string>* non_option_args);
  bool AddMeasuredEventType(const std::string& event_type_name);
  bool AddDefaultMeasuredEventTypes();
  bool SetEventSelection();
  bool ShowCounters(const std::vector<CountersInfo>& counters, double duration_in_sec);

  bool verbose_mode_;
  bool system_wide_collection_;
  bool child_inherit_;
  std::vector<pid_t> monitored_threads_;
  std::vector<int> cpus_;
  std::vector<EventTypeAndModifier> measured_event_types_;
  EventSelectionSet event_selection_set_;

  std::unique_ptr<ScopedSignalHandler> scoped_signal_handler_;
};

bool StatCommand::Run(const std::vector<std::string>& args) {
  if (!CheckPerfEventLimit()) {
    return false;
  }

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
    if (!event_selection_set_.OpenEventFilesForCpus(cpus_)) {
      return false;
    }
  } else {
    if (!event_selection_set_.OpenEventFilesForThreadsOnCpus(monitored_threads_, cpus_)) {
      return false;
    }
  }

  // 4. Count events while workload running.
  auto start_time = std::chrono::steady_clock::now();
  if (workload != nullptr && !workload->Start()) {
    return false;
  }
  while (!signaled) {
    sleep(1);
  }
  auto end_time = std::chrono::steady_clock::now();

  // 5. Read and print counters.
  std::vector<CountersInfo> counters;
  if (!event_selection_set_.ReadCounters(&counters)) {
    return false;
  }
  double duration_in_sec =
      std::chrono::duration_cast<std::chrono::duration<double>>(end_time - start_time).count();
  if (!ShowCounters(counters, duration_in_sec)) {
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
    } else if (args[i] == "--cpu") {
      if (!NextArgumentOrError(args, &i)) {
        return false;
      }
      cpus_ = GetCpusFromString(args[i]);
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
  measured_event_types_.push_back(*event_type_modifier);
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
  for (auto& event_type : measured_event_types_) {
    if (!event_selection_set_.AddEventType(event_type)) {
      return false;
    }
  }
  event_selection_set_.SetInherit(child_inherit_);
  return true;
}

static std::string ReadableCountValue(uint64_t count,
                                      const EventTypeAndModifier& event_type_modifier) {
  if (event_type_modifier.event_type.name == "cpu-clock" ||
      event_type_modifier.event_type.name == "task-clock") {
    double value = count / 1e6;
    return android::base::StringPrintf("%lf(ms)", value);
  } else {
    std::string s = android::base::StringPrintf("%" PRIu64, count);
    for (size_t i = s.size() - 1, j = 1; i > 0; --i, ++j) {
      if (j == 3) {
        s.insert(s.begin() + i, ',');
        j = 0;
      }
    }
    return s;
  }
}

struct CounterSummary {
  const EventTypeAndModifier* event_type;
  uint64_t count;
  double scale;
  std::string readable_count_str;
  std::string comment;
};

static std::string GetCommentForSummary(const CounterSummary& summary,
                                        const std::vector<CounterSummary>& summaries,
                                        double duration_in_sec) {
  const std::string& type_name = summary.event_type->event_type.name;
  const std::string& modifier = summary.event_type->modifier;
  if (type_name == "task-clock") {
    double run_sec = summary.count / 1e9;
    double cpu_usage = run_sec / duration_in_sec;
    return android::base::StringPrintf("%lf%% cpu usage", cpu_usage * 100);
  }
  if (type_name == "cpu-clock") {
    return "";
  }
  if (type_name == "cpu-cycles") {
    double hz = summary.count / duration_in_sec;
    return android::base::StringPrintf("%lf GHz", hz / 1e9);
  }
  if (type_name == "instructions" && summary.count != 0) {
    for (auto& t : summaries) {
      if (t.event_type->event_type.name == "cpu-cycles" && t.event_type->modifier == modifier) {
        double cycles_per_instruction = t.count * 1.0 / summary.count;
        return android::base::StringPrintf("%lf cycles per instruction", cycles_per_instruction);
      }
    }
  }
  if (android::base::EndsWith(type_name, "-misses")) {
    std::string s;
    if (type_name == "cache-misses") {
      s = "cache-references";
    } else if (type_name == "branch-misses") {
      s = "branch-instructions";
    } else {
      s = type_name.substr(0, type_name.size() - strlen("-misses")) + "s";
    }
    for (auto& t : summaries) {
      if (t.event_type->event_type.name == s && t.event_type->modifier == modifier && t.count != 0) {
        double miss_rate = summary.count * 1.0 / t.count;
        return android::base::StringPrintf("%lf%% miss rate", miss_rate * 100);
      }
    }
  }
  double rate = summary.count / duration_in_sec;
  if (rate > 1e9) {
    return android::base::StringPrintf("%.3lf G/sec", rate / 1e9);
  }
  if (rate > 1e6) {
    return android::base::StringPrintf("%.3lf M/sec", rate / 1e6);
  }
  if (rate > 1e3) {
    return android::base::StringPrintf("%.3lf K/sec", rate / 1e3);
  }
  return android::base::StringPrintf("%.3lf /sec", rate);
}

bool StatCommand::ShowCounters(const std::vector<CountersInfo>& counters, double duration_in_sec) {
  printf("Performance counter statistics:\n\n");

  if (verbose_mode_) {
    for (auto& counters_info : counters) {
      const EventTypeAndModifier* event_type = counters_info.event_type;
      for (auto& counter_info : counters_info.counters) {
        printf("%s(tid %d, cpu %d): count %s, time_enabled %" PRIu64 ", time running %" PRIu64
               ", id %" PRIu64 "\n",
               event_type->name.c_str(), counter_info.tid, counter_info.cpu,
               ReadableCountValue(counter_info.counter.value, *event_type).c_str(),
               counter_info.counter.time_enabled, counter_info.counter.time_running,
               counter_info.counter.id);
      }
    }
  }

  std::vector<CounterSummary> summaries;
  for (auto& counters_info : counters) {
    uint64_t value_sum = 0;
    uint64_t time_enabled_sum = 0;
    uint64_t time_running_sum = 0;
    for (auto& counter_info : counters_info.counters) {
      value_sum += counter_info.counter.value;
      time_enabled_sum += counter_info.counter.time_enabled;
      time_running_sum += counter_info.counter.time_running;
    }
    double scale = 1.0;
    uint64_t scaled_count = value_sum;
    if (time_running_sum < time_enabled_sum) {
      if (time_running_sum == 0) {
        scaled_count = 0;
      } else {
        scale = static_cast<double>(time_enabled_sum) / time_running_sum;
        scaled_count = static_cast<uint64_t>(scale * value_sum);
      }
    }
    CounterSummary summary;
    summary.event_type = counters_info.event_type;
    summary.count = scaled_count;
    summary.scale = scale;
    summary.readable_count_str = ReadableCountValue(summary.count, *summary.event_type);
    summaries.push_back(summary);
  }

  for (auto& summary : summaries) {
    summary.comment = GetCommentForSummary(summary, summaries, duration_in_sec);
  }

  size_t count_column_width = 0;
  size_t name_column_width = 0;
  size_t comment_column_width = 0;
  for (auto& summary : summaries) {
    count_column_width = std::max(count_column_width, summary.readable_count_str.size());
    name_column_width = std::max(name_column_width, summary.event_type->name.size());
    comment_column_width = std::max(comment_column_width, summary.comment.size());
  }

  for (auto& summary : summaries) {
    printf("  %*s  %-*s   # %-*s   (%.0lf%%)\n", static_cast<int>(count_column_width),
           summary.readable_count_str.c_str(), static_cast<int>(name_column_width),
           summary.event_type->name.c_str(), static_cast<int>(comment_column_width),
           summary.comment.c_str(), 1.0 / summary.scale * 100);
  }

  printf("\nTotal test time: %lf seconds.\n", duration_in_sec);
  return true;
}

void RegisterStatCommand() {
  RegisterCommand("stat", [] { return std::unique_ptr<Command>(new StatCommand); });
}
