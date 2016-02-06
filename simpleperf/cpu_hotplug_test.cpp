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
#include <unistd.h>
#if defined(__BIONIC__)
#include <sys/system_properties.h>
#endif

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <thread>
#include <unordered_map>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/stringprintf.h>

#include "command.h"
#include "event_attr.h"
#include "event_fd.h"
#include "event_type.h"

static std::unique_ptr<Command> RecordCmd() {
  return CreateCommandInstance("record");
}

#if defined(__BIONIC__)
class ScopedMpdecisionKiller {
 public:
  ScopedMpdecisionKiller() {
    have_mpdecision_ = IsMpdecisionRunning();
    if (have_mpdecision_) {
      DisableMpdecision();
    }
  }

  ~ScopedMpdecisionKiller() {
    if (have_mpdecision_) {
      EnableMpdecision();
    }
  }

 private:
  bool IsMpdecisionRunning() {
    char value[PROP_VALUE_MAX];
    int len = __system_property_get("init.svc.mpdecision", value);
    if (len == 0 || (len > 0 && strstr(value, "stopped") != nullptr)) {
      return false;
    }
    return true;
  }

  void DisableMpdecision() {
    int ret = __system_property_set("ctl.stop", "mpdecision");
    CHECK_EQ(0, ret);
    // Need to wait until mpdecision is actually stopped.
    usleep(500000);
    CHECK(!IsMpdecisionRunning());
  }

  void EnableMpdecision() {
    int ret = __system_property_set("ctl.start", "mpdecision");
    CHECK_EQ(0, ret);
    usleep(500000);
    CHECK(IsMpdecisionRunning());
  }

  bool have_mpdecision_;
};
#else
class ScopedMpdecisionKiller {
 public:
  ScopedMpdecisionKiller() {
  }
};
#endif

static bool IsCpuOnline(int cpu) {
  std::string filename = android::base::StringPrintf("/sys/devices/system/cpu/cpu%d/online", cpu);
  std::string content;
  CHECK(android::base::ReadFileToString(filename, &content)) << "failed to read file " << filename;
  return (content.find('1') != std::string::npos);
}

static void SetCpuOnline(int cpu, bool online) {
  if (IsCpuOnline(cpu) == online) {
    return;
  }
  std::string filename = android::base::StringPrintf("/sys/devices/system/cpu/cpu%d/online", cpu);
  std::string content = online ? "1" : "0";
  CHECK(android::base::WriteStringToFile(content, filename)) << "Write " << content << " to "
                                                             << filename << " failed";
  CHECK_EQ(online, IsCpuOnline(cpu)) << "set cpu " << cpu << (online ? " online" : " offline")
                                     << " failed";
}

static int GetCpuCount() {
  return static_cast<int>(sysconf(_SC_NPROCESSORS_CONF));
}

class CpuOnlineRestorer {
 public:
  CpuOnlineRestorer() {
    for (int cpu = 1; cpu < GetCpuCount(); ++cpu) {
      online_map_[cpu] = IsCpuOnline(cpu);
    }
  }

  ~CpuOnlineRestorer() {
    for (const auto& pair : online_map_) {
      SetCpuOnline(pair.first, pair.second);
    }
  }

 private:
  std::unordered_map<int, bool> online_map_;
};

struct CpuToggleThreadArg {
  int toggle_cpu;
  std::atomic<bool> end_flag;
};

static void CpuToggleThread(CpuToggleThreadArg* arg) {
  while (!arg->end_flag) {
    SetCpuOnline(arg->toggle_cpu, true);
    sleep(1);
    SetCpuOnline(arg->toggle_cpu, false);
    sleep(1);
  }
}

static bool RecordInChildProcess(int record_cpu, int record_duration_in_second) {
  pid_t pid = fork();
  CHECK(pid != -1);
  if (pid == 0) {
    std::string cpu_str = android::base::StringPrintf("%d", record_cpu);
    std::string record_duration_str = android::base::StringPrintf("%d", record_duration_in_second);
    bool ret = RecordCmd()->Run({"-a", "--cpu", cpu_str, "sleep", record_duration_str});
    extern bool system_wide_perf_event_open_failed;
    // It is not an error if perf_event_open failed because of cpu-hotplug.
    if (!ret && !system_wide_perf_event_open_failed) {
      exit(1);
    }
    exit(0);
  }
  int timeout = record_duration_in_second + 10;
  auto end_time = std::chrono::steady_clock::now() + std::chrono::seconds(timeout);
  bool child_success = false;
  while (std::chrono::steady_clock::now() < end_time) {
    int exit_state;
    pid_t ret = waitpid(pid, &exit_state, WNOHANG);
    if (ret == pid) {
      if (WIFSIGNALED(exit_state) || (WIFEXITED(exit_state) && WEXITSTATUS(exit_state) != 0)) {
        child_success = false;
      } else {
        child_success = true;
      }
      break;
    } else if (ret == -1) {
      child_success = false;
      break;
    }
    sleep(1);
  }
  return child_success;
}

// http://b/25193162.
TEST(cpu_offline, offline_while_recording) {
  ScopedMpdecisionKiller scoped_mpdecision_killer;
  CpuOnlineRestorer cpuonline_restorer;

  if (GetCpuCount() == 1) {
    GTEST_LOG_(INFO) << "This test does nothing, because there is only one cpu in the system.";
    return;
  }
  for (int i = 1; i < GetCpuCount(); ++i) {
    if (!IsCpuOnline(i)) {
      SetCpuOnline(i, true);
    }
  }
  // Start cpu hotplugger.
  int test_cpu = GetCpuCount() - 1;
  CpuToggleThreadArg cpu_toggle_arg;
  cpu_toggle_arg.toggle_cpu = test_cpu;
  cpu_toggle_arg.end_flag = false;
  std::thread cpu_toggle_thread(CpuToggleThread, &cpu_toggle_arg);

  const std::chrono::hours test_duration(10);  // Test for 10 hours.
  const double RECORD_DURATION_IN_SEC = 2.9;
  const double SLEEP_DURATION_IN_SEC = 1.3;

  auto end_time = std::chrono::steady_clock::now() + test_duration;
  size_t iterations = 0;
  while (std::chrono::steady_clock::now() < end_time) {
    iterations++;
    GTEST_LOG_(INFO) << "Test for " << iterations << " times.";
    ASSERT_TRUE(RecordInChildProcess(test_cpu, RECORD_DURATION_IN_SEC));
    usleep(static_cast<useconds_t>(SLEEP_DURATION_IN_SEC * 1e6));
  }
  cpu_toggle_arg.end_flag = true;
  cpu_toggle_thread.join();
}

static std::unique_ptr<EventFd> OpenHardwareEventOnCpu(int cpu) {
  std::unique_ptr<EventTypeAndModifier> event_type_modifier = ParseEventType("cpu-cycles");
  if (event_type_modifier == nullptr) {
    return nullptr;
  }
  perf_event_attr attr = CreateDefaultPerfEventAttr(event_type_modifier->event_type);
  return EventFd::OpenEventFile(attr, getpid(), cpu);
}

// http://b/19863147.
TEST(cpu_offline, offline_while_recording_on_another_cpu) {
  ScopedMpdecisionKiller scoped_mpdecision_killer;
  CpuOnlineRestorer cpuonline_restorer;

  if (GetCpuCount() == 1) {
    GTEST_LOG_(INFO) << "This test does nothing, because there is only one cpu in the system.";
    return;
  }

  const size_t TEST_ITERATION_COUNT = 10u;
  for (size_t i = 0; i < TEST_ITERATION_COUNT; ++i) {
    int record_cpu = 0;
    int toggle_cpu = GetCpuCount() - 1;
    SetCpuOnline(toggle_cpu, true);
    std::unique_ptr<EventFd> event_fd = OpenHardwareEventOnCpu(record_cpu);
    ASSERT_TRUE(event_fd != nullptr);
    SetCpuOnline(toggle_cpu, false);
    event_fd = nullptr;
    event_fd = OpenHardwareEventOnCpu(record_cpu);
    ASSERT_TRUE(event_fd != nullptr);
  }
}

int main(int argc, char** argv) {
  InitLogging(argv, android::base::StderrLogger);
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
