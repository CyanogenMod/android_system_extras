/*
 * Copyright (C) 2010 The Android Open Source Project
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
 *
 */

#ifndef _TESTUTIL_H_
#define _TESTUTIL_H_

#include <stdint.h>
#include <stdio.h>
#include <sys/time.h>

#ifdef __cplusplus
extern "C" {
#endif

// Time Utilities
double tv2double(const struct timeval *val);
struct timespec double2ts(double amt);
struct timeval tvDelta(const struct timeval *first,
    const struct timeval *second);
void delay(float amt);

// Pseudo Random Utilities
int testRandBool(void);

// Testcase Output
void testSetLogCatTag(const char *tag);
const char *testGetLogCatTag(void);
void testPrint(FILE *stream, const char *fmt, ...);
#define testPrintI(...) do { \
        testPrint(stdout, __VA_ARGS__); \
    } while (0)
#define testPrintE(...) do { \
        testPrint(stderr, __VA_ARGS__); \
    } while (0)

#ifdef __cplusplus
}
#endif

#endif
