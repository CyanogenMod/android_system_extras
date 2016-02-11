/*
 * Copyright (C) 2016 The Android Open Source Project
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
#include <errno.h>
#ifdef HAS_KCMP
#include <linux/kcmp.h>
#include <sys/syscall.h>
#endif
#include <unistd.h>

#include <gtest/gtest.h>

#ifdef HAS_KCMP
int kcmp(pid_t pid1, pid_t pid2, int type, unsigned long idx1, unsigned long idx2) {
  return syscall(SYS_kcmp, pid1, pid2, type, 0, idx1, idx2);
}
#endif

TEST(kernel_config, NOT_CONFIG_SYSVIPC) {
#ifdef HAS_KCMP
  pid_t pid = getpid();
  int ret = kcmp(pid, pid, KCMP_SYSVSEM, 0, 0);
  int error = (ret == -1) ? (errno == ENOSYS) ? EOPNOTSUPP : errno : 0;
  EXPECT_EQ(-1, kcmp(pid, pid, KCMP_SYSVSEM, 0, 0));
  EXPECT_EQ(EOPNOTSUPP, error);
#endif
  EXPECT_EQ(-1, access("/proc/sysvipc", F_OK));
  EXPECT_EQ(-1, access("/proc/sysvipc/msg", F_OK));
  EXPECT_EQ(-1, access("/proc/sysvipc/sem", F_OK));
  EXPECT_EQ(-1, access("/proc/sysvipc/shm", F_OK));
}

