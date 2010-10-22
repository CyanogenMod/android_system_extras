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

#include <testUtil.h>

#include <assert.h>
#include <math.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>
#include <cutils/log.h>

#define ALEN(a) (sizeof(a) / sizeof(a [0]))  // Array length
typedef unsigned int bool_t;
#define true (0 == 0)
#define false (!true)

#define MAXSTR 200

static const char *logCatTag;
static const unsigned int uSecsPerSec = 1000000;
static const unsigned int nSecsPerSec = 1000000000;

// struct timespec to double
double ts2double(const struct timespec *val)
{
    double rv;

    rv = val->tv_sec;
    rv += (double) val->tv_nsec / nSecsPerSec;

    return rv;
}

// struct timeval to double
double tv2double(const struct timeval *val)
{
    double rv;

    rv = val->tv_sec;
    rv += (double) val->tv_usec / uSecsPerSec;

    return rv;
}

// double to struct timespec
struct timespec double2ts(double amt)
{
    struct timespec rv;

    rv.tv_sec = floor(amt);
    rv.tv_nsec = (amt - rv.tv_sec) * nSecsPerSec;
    // TODO: Handle cases where amt is negative
    while ((unsigned) rv.tv_nsec >= nSecsPerSec) {
        rv.tv_nsec -= nSecsPerSec;
        rv.tv_sec++;
    }

    return rv;
}

// double to struct timeval
struct timeval double2tv(double amt)
{
    struct timeval rv;

    rv.tv_sec = floor(amt);
    rv.tv_usec = (amt - rv.tv_sec) * uSecsPerSec;
    // TODO: Handle cases where amt is negative
    while ((unsigned) rv.tv_usec >= uSecsPerSec) {
        rv.tv_usec -= uSecsPerSec;
        rv.tv_sec++;
    }

    return rv;
}

// Delta (difference) between two struct timespec.
// It is expected that the time given by the structure pointed to by
// second, is later than the time pointed to by first.
struct timespec tsDelta(const struct timespec *first,
                        const struct timespec *second)
{
    struct timespec rv;

    assert(first != NULL);
    assert(second != NULL);
    assert(first->tv_nsec >= 0 && first->tv_nsec < nSecsPerSec);
    assert(second->tv_nsec >= 0 && second->tv_nsec < nSecsPerSec);
    rv.tv_sec = second->tv_sec - first->tv_sec;
    if (second->tv_nsec >= first->tv_nsec) {
        rv.tv_nsec = second->tv_nsec - first->tv_nsec;
    } else {
        rv.tv_nsec = (second->tv_nsec + nSecsPerSec) - first->tv_nsec;
        rv.tv_sec--;
    }

    return rv;
}

// Delta (difference) between two struct timeval.
// It is expected that the time given by the structure pointed to by
// second, is later than the time pointed to by first.
struct timeval tvDelta(const struct timeval *first,
                       const struct timeval *second)
{
    struct timeval rv;

    assert(first != NULL);
    assert(second != NULL);
    assert(first->tv_usec >= 0 && first->tv_usec < uSecsPerSec);
    assert(second->tv_usec >= 0 && second->tv_usec < uSecsPerSec);
    rv.tv_sec = second->tv_sec - first->tv_sec;
    if (second->tv_usec >= first->tv_usec) {
        rv.tv_usec = second->tv_usec - first->tv_usec;
    } else {
        rv.tv_usec = (second->tv_usec + uSecsPerSec) - first->tv_usec;
        rv.tv_sec--;
    }

    return rv;
}

void testPrint(FILE *stream, const char *fmt, ...)
{
    char line[MAXSTR];
    va_list args;

    va_start(args, fmt);
    vsnprintf(line, sizeof(line), fmt, args);
    if (stream == stderr) {
        LOG(LOG_ERROR, logCatTag, "%s", line);
    } else {
        LOG(LOG_INFO, logCatTag, "%s", line);
    }
    vfprintf(stream, fmt, args);
    fputc('\n', stream);
}

// Set tag used while logging to the logcat error interface
void testSetLogCatTag(const char *tag)
{
    logCatTag = tag;
}

// Obtain pointer to current log to logcat error interface tag
const char * testGetLogCatTag(void)
{
    return logCatTag;
}

/*
 * Random Boolean
 *
 * Pseudo randomly returns 0 (false) or 1 (true).
 *
 * Precondition: srand48() called to set the seed of
 *   the pseudo random number generator.
 */
int testRandBool(void)
{
    /* Use the most significant bit from lrand48(), because the
     * less significant bits are less random across different seeds
     * (e.g. srand48(x) and srand48(x + n * 4) cause lrand48() to
     * return the same sequence of least significant bits.)
     */
    return (lrand48() & (1U << 30)) ? 0 : 1;
}

// Delays for the number of seconds specified by amt or a greater amount.
// The amt variable is of type float and thus non-integer amounts
// of time can be specified.  This function automatically handles cases
// where nanosleep(2) returns early due to reception of a signal.
void delay(float amt)
{
    struct timespec   start, current, delta;
    struct timespec   remaining;

    // Get the time at which we started
    clock_gettime(CLOCK_MONOTONIC, &start);

    do {
        // Get current time
        clock_gettime(CLOCK_MONOTONIC, &current);

        // How much time is left
        delta = tsDelta(&start, &current);
        if (ts2double(&delta) > amt) { break; }

        // Request to sleep for the remaining time
        remaining = double2ts(amt - ts2double(&delta));
        (void) nanosleep(&remaining, NULL);
    } while (true);
}
