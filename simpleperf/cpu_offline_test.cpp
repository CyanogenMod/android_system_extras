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

#include <gtest/gtest.h>

#include <sys/stat.h>

#include <base/file.h>

#include "event_attr.h"
#include "event_fd.h"
#include "event_type.h"

static std::unique_ptr<EventFd> OpenHardwareEventOnCpu0() {
  const EventType* event_type = EventTypeFactory::FindEventTypeByName("cpu-cycles");
  if (event_type == nullptr) {
    return nullptr;
  }
  perf_event_attr attr = CreateDefaultPerfEventAttr(*event_type);
  return EventFd::OpenEventFile(attr, getpid(), 0);
}

static const char* cpu1_online_path = "/sys/devices/system/cpu/cpu1/online";

static bool HaveCpuOne() {
  struct stat st;
  return (stat(cpu1_online_path, &st) == 0 && S_ISREG(st.st_mode));
}

static void IsCpuOneOnline(bool* online, bool* has_error) {
  std::string content;
  *has_error = true;
  ASSERT_TRUE(android::base::ReadFileToString(cpu1_online_path, &content));
  ASSERT_GT(content.size(), 0U);
  *has_error = false;
  *online = (content[0] == '0') ? false : true;
}

static void SetCpuOneOnline(bool online, bool* has_error, bool* interrupted) {
  *interrupted = false;
  errno = 0;
  int ret = android::base::WriteStringToFile(online ? "1" : "0", cpu1_online_path);
  int saved_errno = errno;
  bool new_state;
  IsCpuOneOnline(&new_state, has_error);
  if (*has_error) {
    return;
  }
  if (new_state == online) {
    return;
  } else if (ret) {
    *interrupted = true;
  } else {
    *has_error = true;
    FAIL() << "Failed to SetCpuOneOnline, online = " << online
           << ", error = " << strerror(saved_errno) << ", new_state = " << new_state;
  }
}

// On some devices like flo, the kernel can't work correctly if a cpu
// is offlined when perf is monitoring a hardware event.
TEST(cpu_offline, smoke) {
  if (!HaveCpuOne()) {
    GTEST_LOG_(INFO) << "This test does nothing on uniprocessor devices.";
    return;
  }

  bool has_error;
  bool interrupted;
  bool saved_online;
  bool success = false;
  IsCpuOneOnline(&saved_online, &has_error);
  // A loop is used in case the test is interrupted by other processes controling cpu hotplug, like
  // mpdecision.
  for (size_t loop_count = 0; !has_error && loop_count < 50; ++loop_count) {
    SetCpuOneOnline(true, &has_error, &interrupted);
    if (has_error || interrupted) {
      continue;
    }

    std::unique_ptr<EventFd> event_fd = OpenHardwareEventOnCpu0();
    ASSERT_TRUE(event_fd != nullptr);

    bool online;
    IsCpuOneOnline(&online, &has_error);
    if (has_error || !online) {
      continue;
    }
    SetCpuOneOnline(false, &has_error, &interrupted);
    if (has_error || interrupted) {
      continue;
    }

    event_fd = nullptr;
    event_fd = OpenHardwareEventOnCpu0();
    ASSERT_TRUE(event_fd != nullptr);
    success = true;
    break;
  }
  SetCpuOneOnline(saved_online, &has_error, &interrupted);
  ASSERT_TRUE(success);
}
