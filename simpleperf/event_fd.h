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

#ifndef SIMPLE_PERF_EVENT_FD_H_
#define SIMPLE_PERF_EVENT_FD_H_

#include <sys/types.h>

#include <memory>
#include <string>

#include <base/macros.h>

#include "perf_event.h"

class EventAttr;

struct PerfCounter {
  uint64_t value;         // The value of the event specified by the perf_event_file.
  uint64_t time_enabled;  // The enabled time.
  uint64_t time_running;  // The running time.
  uint64_t id;            // The id of the perf_event_file.
};

// EventFd represents an opened perf_event_file.
class EventFd {
 public:
  static std::unique_ptr<EventFd> OpenEventFileForProcess(const EventAttr& attr, pid_t pid);
  static std::unique_ptr<EventFd> OpenEventFileForCpu(const EventAttr& attr, int cpu);
  static std::unique_ptr<EventFd> OpenEventFile(const EventAttr& attr, pid_t pid, int cpu);

  ~EventFd();

  // Give information about this perf_event_file, like (event_name, pid, cpu).
  std::string Name() const;

  // It tells the kernel to start counting and recording events specified by this file.
  bool EnableEvent();

  // It tells the kernel to stop counting and recording events specified by this file.
  bool DisableEvent();

  bool ReadCounter(PerfCounter* counter);

 private:
  EventFd(int perf_event_fd, const std::string& event_name, pid_t pid, int cpu)
      : perf_event_fd_(perf_event_fd), event_name_(event_name), pid_(pid), cpu_(cpu) {
  }

  int perf_event_fd_;
  const std::string event_name_;
  pid_t pid_;
  int cpu_;

  DISALLOW_COPY_AND_ASSIGN(EventFd);
};

#endif  // SIMPLE_PERF_EVENT_FD_H_
