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

#include <signal.h>

#include "scoped_signal_handler.h"
#include "utils.h"
#include "workload.h"

static volatile bool signaled;
static void signal_handler(int) {
  signaled = true;
}

TEST(workload, success) {
  signaled = false;
  ScopedSignalHandler scoped_signal_handler({SIGCHLD}, signal_handler);
  auto workload = Workload::CreateWorkload({"sleep", "1"});
  ASSERT_TRUE(workload != nullptr);
  ASSERT_TRUE(workload->GetPid() != 0);
  ASSERT_TRUE(workload->Start());
  while (!signaled) {
  }
}

TEST(workload, execvp_failure) {
  auto workload = Workload::CreateWorkload({"/dev/null"});
  ASSERT_TRUE(workload != nullptr);
  ASSERT_FALSE(workload->Start());
}

static void run_signaled_workload() {
  {
    signaled = false;
    ScopedSignalHandler scoped_signal_handler({SIGCHLD}, signal_handler);
    auto workload = Workload::CreateWorkload({"sleep", "10"});
    ASSERT_TRUE(workload != nullptr);
    ASSERT_TRUE(workload->Start());
    ASSERT_EQ(0, kill(workload->GetPid(), SIGKILL));
    while (!signaled) {
    }
  }
  // Make sure all destructors are called before exit().
  exit(0);
}

TEST(workload, signaled_warning) {
  ASSERT_EXIT(run_signaled_workload(), testing::ExitedWithCode(0),
              "child process was terminated by signal");
}

static void run_exit_nonzero_workload() {
  {
    signaled = false;
    ScopedSignalHandler scoped_signal_handler({SIGCHLD}, signal_handler);
    auto workload = Workload::CreateWorkload({"ls", "nonexistdir"});
    ASSERT_TRUE(workload != nullptr);
    ASSERT_TRUE(workload->Start());
    while (!signaled) {
    }
  }
  // Make sure all destructors are called before exit().
  exit(0);
}

TEST(workload, exit_nonzero_warning) {
  ASSERT_EXIT(run_exit_nonzero_workload(), testing::ExitedWithCode(0),
              "child process exited with exit code");
}
