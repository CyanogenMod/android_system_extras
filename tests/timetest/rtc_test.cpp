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
#include <fcntl.h>
#include <linux/rtc.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <unistd.h>

#include <gtest/gtest.h>

static int hwtime(int flag, int request, struct rtc_time *tm) {
  int ret;
  do {
    ret = TEMP_FAILURE_RETRY(open("/dev/rtc0", flag));
    if (ret < 0) {
      ret = -errno;
    }
  } while (ret == -EBUSY);
  if (ret < 0) {
    return ret;
  }

  int fd = ret;
  do {
    ret = TEMP_FAILURE_RETRY(ioctl(fd, request, tm));
    if (ret < 0) {
      ret = -errno;
    }
  } while (ret == -EBUSY);
  close(fd);
  return ret;
}

static int rd_hwtime(struct rtc_time *tm) {
  return hwtime(O_RDONLY, RTC_RD_TIME, tm);
}

static int set_hwtime(struct rtc_time *tm) {
  return hwtime(O_WRONLY, RTC_SET_TIME, tm);
}

TEST(time, rtc_rollover) {
  struct rtc_time roll;
  memset(&roll, 0, sizeof(roll));
  ASSERT_LE(0, rd_hwtime(&roll));
  int mday[12] = { 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
  mday[1] = (roll.tm_year % 4) ? 28 : 29;
  ASSERT_LE(0, roll.tm_sec);
  ASSERT_GT(60, roll.tm_sec);
  ASSERT_LE(0, roll.tm_min);
  ASSERT_GT(60, roll.tm_min);
  ASSERT_LE(0, roll.tm_hour);
  ASSERT_GT(24, roll.tm_hour);
  ASSERT_LE(0, roll.tm_mday);
  ASSERT_GE(mday[roll.tm_mon], roll.tm_mday);
  ASSERT_LE(0, roll.tm_mon);
  ASSERT_GT(12, roll.tm_mon);
  ASSERT_LE(0, roll.tm_year);
  ASSERT_GT(138, roll.tm_year);

  // Wait for granular clock
  struct rtc_time save = roll;
  static const useconds_t timeout_sleep = 10000;
  static const int timeout_num = 2000000 / timeout_sleep;
  int timeout;
  for (timeout = timeout_num; timeout && (roll.tm_year == save.tm_year); --timeout) {
    ASSERT_LE(0, rd_hwtime(&save));
    usleep(timeout_sleep);
  }

  memset(&roll, 0, sizeof(roll));
  roll.tm_sec = 59;
  roll.tm_min = 59;
  roll.tm_hour = 23;
  roll.tm_mday = 31;
  roll.tm_mon = 11;
  roll.tm_year = 70;
  roll.tm_wday = 0;
  roll.tm_yday = 0;
  roll.tm_isdst = 0;

  for (roll.tm_year = 70; roll.tm_year < 137; ++roll.tm_year) {
    struct rtc_time tm = roll;
    int __set_hwtime = set_hwtime(&tm);
    // below 2015, permitted to error out.
    if ((__set_hwtime == -EINVAL) && (roll.tm_year < 115)) {
      continue;
    }
    ASSERT_LE(0, __set_hwtime);
    ASSERT_LE(0, rd_hwtime(&tm));
    ASSERT_EQ(roll.tm_sec, tm.tm_sec);
    ASSERT_EQ(roll.tm_min, tm.tm_min);
    ASSERT_EQ(roll.tm_hour, tm.tm_hour);
    ASSERT_EQ(roll.tm_mday, tm.tm_mday);
    ASSERT_EQ(roll.tm_mon, tm.tm_mon);
    ASSERT_EQ(roll.tm_year, tm.tm_year);
    for (timeout = timeout_num; timeout && (roll.tm_year == tm.tm_year); --timeout) {
      ASSERT_LE(0, rd_hwtime(&tm));
      usleep(timeout_sleep);
    }
    ASSERT_EQ(roll.tm_year + 1, tm.tm_year);
    EXPECT_LT(timeout_num * 5 / 100, timeout);
    EXPECT_GT(timeout_num * 95 / 100, timeout);

    // correct saved time to compensate for rollover check
    if (++save.tm_sec >= 60) {
      save.tm_sec = 0;
      if (++save.tm_min >= 60) {
        save.tm_min = 0;
        if (++save.tm_hour >= 24) {
          save.tm_hour = 0;
          mday[1] = (save.tm_year % 4) ? 28 : 29;
          if (++save.tm_mday >= mday[save.tm_mon]) {
            save.tm_mday = 1;
            if (++save.tm_mon >= 12) {
              save.tm_mon = 0;
              ++save.tm_year;
            }
          }
        }
      }
    }
  }

  ASSERT_LE(0, set_hwtime(&save));
  ASSERT_LE(0, rd_hwtime(&roll));

  ASSERT_EQ(save.tm_sec, roll.tm_sec);
  ASSERT_EQ(save.tm_min, roll.tm_min);
  ASSERT_EQ(save.tm_hour, roll.tm_hour);
  ASSERT_EQ(save.tm_mday, roll.tm_mday);
  ASSERT_EQ(save.tm_mon, roll.tm_mon);
  ASSERT_EQ(save.tm_year, roll.tm_year);
}
