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

#include "event_fd.h"

#include <fcntl.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <memory>

#include <base/logging.h>
#include <base/stringprintf.h>

#include "event_type.h"
#include "event_attr.h"
#include "perf_event.h"
#include "utils.h"

static int perf_event_open(perf_event_attr* attr, pid_t pid, int cpu, int group_fd,
                           unsigned long flags) {
  return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

std::unique_ptr<EventFd> EventFd::OpenEventFileForProcess(const EventAttr& attr, pid_t pid) {
  return OpenEventFile(attr, pid, -1);
}

std::unique_ptr<EventFd> EventFd::OpenEventFileForCpu(const EventAttr& attr, int cpu) {
  return OpenEventFile(attr, -1, cpu);
}

std::unique_ptr<EventFd> EventFd::OpenEventFile(const EventAttr& attr, pid_t pid, int cpu) {
  perf_event_attr perf_attr = attr.Attr();
  std::string event_name = "unknown event";
  const EventType* event_type =
      EventTypeFactory::FindEventTypeByConfig(perf_attr.type, perf_attr.config);
  if (event_type != nullptr) {
    event_name = event_type->name;
  }
  int perf_event_fd = perf_event_open(&perf_attr, pid, cpu, -1, 0);
  if (perf_event_fd == -1) {
    // It depends whether the perf_event_file configuration is supported by the kernel and the
    // machine. So fail to open the file is not an error.
    PLOG(DEBUG) << "open perf_event_file (event " << event_name << ", pid " << pid << ", cpu "
                << cpu << ") failed";
    return nullptr;
  }
  if (fcntl(perf_event_fd, F_SETFD, FD_CLOEXEC) == -1) {
    PLOG(ERROR) << "fcntl(FD_CLOEXEC) for perf_event_file (event " << event_name << ", pid " << pid
                << ", cpu " << cpu << ") failed";
    return nullptr;
  }
  return std::unique_ptr<EventFd>(new EventFd(perf_event_fd, event_name, pid, cpu));
}

EventFd::~EventFd() {
  close(perf_event_fd_);
}

std::string EventFd::Name() const {
  return android::base::StringPrintf("perf_event_file(event %s, pid %d, cpu %d)",
                                     event_name_.c_str(), pid_, cpu_);
}

bool EventFd::EnableEvent() {
  int result = ioctl(perf_event_fd_, PERF_EVENT_IOC_ENABLE, 0);
  if (result < 0) {
    PLOG(ERROR) << "ioctl(enable) " << Name() << " failed";
    return false;
  }
  return true;
}

bool EventFd::DisableEvent() {
  int result = ioctl(perf_event_fd_, PERF_EVENT_IOC_DISABLE, 0);
  if (result < 0) {
    PLOG(ERROR) << "ioctl(disable) " << Name() << " failed";
    return false;
  }
  return true;
}

bool EventFd::ReadCounter(PerfCounter* counter) {
  CHECK(counter != nullptr);
  if (!ReadNBytesFromFile(perf_event_fd_, counter, sizeof(*counter))) {
    PLOG(ERROR) << "ReadCounter from " << Name() << " failed";
    return false;
  }
  return true;
}
