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

/*
 * WiFi load, scan, associate, unload stress test
 *
 * Repeatedly executes the following sequence:
 *
 *   1. Load WiFi driver
 *   2. Start supplicant
 *   3. Random delay
 *   4. Obtain supplicant status (optional)
 *   5. Stop supplicant
 *   6. Unload WiFi driver
 *
 * The "Obtain supplicant status" step is optional and is pseudo
 * randomly performed 50% of the time.  The default range of
 * delay after start supplicant is intentionally selected such
 * that the obtain supplicant status and stop supplicant steps
 * may be performed while the WiFi driver is still performing a scan
 * or associate.  The default values are given by DEFAULT_DELAY_MIN
 * and DEFAULT_DELAY_MAX.  Other values can be specified through the
 * use of the -d and -D command-line options.
 *
 * Each sequence is refered to as a pass and by default an unlimited
 * number of passes are performed.  An override of the range of passes
 * to be executed is available through the use of the -s (start) and
 * -e (end) command-line options.  There is also a default time in
 * which the test executes, which is given by DEFAULT_DURATION and
 * can be overriden through the use of the -t command-line option.
 */

#include <assert.h>
#include <errno.h>
#include <libgen.h>
#include <math.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <hardware_legacy/wifi.h>

#define LOG_TAG "wifiLoadScanAssocTest"
#include <utils/Log.h>
#include <testUtil.h>

#define DEFAULT_START_PASS     0
#define DEFAULT_END_PASS     999
#define DEFAULT_DURATION       FLT_MAX // A fairly long time, so that
                                       // range of passes will have
                                       // precedence
#define DEFAULT_DELAY_MIN      0.0     // Min delay after start supplicant
#define DEFAULT_DELAY_MAX     20.0     // Max delay after start supplicant
#define DELAY_EXP            150.0     // Exponent which determines the
                                       // amount by which values closer
                                       // to DELAY_MIN are favored.

#define CMD_STATUS           "wpa_cli status 2>&1"
#define CMD_STOP_FRAMEWORK   "stop 2>&1"
#define CMD_START_FRAMEWORK  "start 2>&1"

#define MAXSTR      100
#define MAXCMD      500

typedef unsigned int bool_t;
#define true (0 == 0)
#define false (!true)

// Local description of sched_setaffinity(2), sched_getaffinity(2), and
// getcpu(2)
#define CPU_SETSIZE 1024
typedef struct {uint64_t bits[CPU_SETSIZE / 64]; } cpu_set_t;
int sched_setaffinity(pid_t pid, unsigned int cpusetsize, const cpu_set_t *set);
int sched_getaffinity(pid_t pid, unsigned int cpusetsize, cpu_set_t *set);
struct getcpu_cache;
int getcpu(unsigned *cpu, unsigned *node, struct getcpu_cache *tcache);
void CPU_CLR(int cpu, cpu_set_t *set);
int CPU_ISSET(int cpu, const cpu_set_t *set);
void CPU_SET(int cpu, cpu_set_t *set);
void CPU_ZERO(cpu_set_t *set);

// File scope variables
cpu_set_t availCPU;
unsigned int numAvailCPU;
float delayMin = DEFAULT_DELAY_MIN;
float delayMax = DEFAULT_DELAY_MAX;
bool_t driverLoadedAtStart;

// File scope prototypes
static void init(void);
static void execCmd(const char *cmd);
static void randDelay(void);
static void randBind(const cpu_set_t *availSet, int *chosenCPU);

/*
 * Main
 *
 * Performs the following high-level sequence of operations:
 *
 *   1. Command-line parsing
 *
 *   2. Initialization
 *
 *   3. Execute passes that repeatedly perform the WiFi load, scan,
 *      associate, unload sequence.
 *
 *   4. Restore state of WiFi driver to state it was at the
 *      start of the test.
 *
 *   5. Restart framework
 */
int
main(int argc, char *argv[])
{
    FILE *fp;
    int rv, opt;
    int cpu;
    char *chptr;
    unsigned int pass;
    char cmd[MAXCMD];
    float duration = DEFAULT_DURATION;
    unsigned int startPass = DEFAULT_START_PASS, endPass = DEFAULT_END_PASS;
    struct timeval startTime, currentTime, delta;

    testSetLogCatTag(LOG_TAG);

    // Parse command line arguments
    while ((opt = getopt(argc, argv, "d:D:s:e:t:?")) != -1) {
        switch (opt) {
        case 'd': // Minimum Delay
            delayMin = strtod(optarg, &chptr);
            if ((*chptr != '\0') || (delayMin < 0.0)) {
                testPrintE("Invalid command-line specified minimum delay "
                    "of: %s", optarg);
                exit(1);
            }
            break;

        case 'D': // Maximum Delay
            delayMax = strtod(optarg, &chptr);
            if ((*chptr != '\0') || (delayMax < 0.0)) {
                testPrintE("Invalid command-line specified maximum delay "
                    "of: %s", optarg);
                exit(2);
            }
            break;

        case 't': // Duration
            duration = strtod(optarg, &chptr);
            if ((*chptr != '\0') || (duration < 0.0)) {
                testPrintE("Invalid command-line specified duration of: %s",
                    optarg);
                exit(3);
            }
            break;

        case 's': // Starting Pass
            startPass = strtoul(optarg, &chptr, 10);
            if (*chptr != '\0') {
                testPrintE("Invalid command-line specified starting pass "
                    "of: %s", optarg);
                exit(4);
            }
            break;

        case 'e': // Ending Pass
            endPass = strtoul(optarg, &chptr, 10);
            if (*chptr != '\0') {
                testPrintE("Invalid command-line specified ending pass "
                    "of: %s", optarg);
                exit(5);
            }
            break;

        case '?':
        default:
            testPrintE("  %s [options]", basename(argv[0]));
            testPrintE("    options:");
            testPrintE("      -s Starting pass");
            testPrintE("      -e Ending pass");
            testPrintE("      -t Duration");
            testPrintE("      -d Delay min");
            testPrintE("      -D Delay max");
            exit((opt == '?') ? 0 : 6);
        }
    }
    if (delayMax < delayMin) {
        testPrintE("Unexpected maximum delay less than minimum delay");
        testPrintE("  delayMin: %f delayMax: %f", delayMin, delayMax);
        exit(7);
    }
    if (endPass < startPass) {
        testPrintE("Unexpected ending pass before starting pass");
        testPrintE("  startPass: %u endPass: %u", startPass, endPass);
        exit(8);
    }
    if (argc != optind) {
        testPrintE("Unexpected command-line postional argument");
        testPrintE("  %s [-s start_pass] [-e end_pass] [-d duration]",
            basename(argv[0]));
        exit(9);
    }
    testPrintI("duration: %g", duration);
    testPrintI("startPass: %u", startPass);
    testPrintI("endPass: %u", endPass);
    testPrintI("delayMin: %f", delayMin);
    testPrintI("delayMax: %f", delayMax);

    init();

    // For each pass
    gettimeofday(&startTime, NULL);
    for (pass = startPass; pass <= endPass; pass++) {
        // Stop if duration of work has already been performed
        gettimeofday(&currentTime, NULL);
        delta = tvDelta(&startTime, &currentTime);
        if (tv2double(&delta) > duration) { break; }

        testPrintI("==== pass %u", pass);

        // Use a pass dependent sequence of random numbers
        srand48(pass);

        // Load WiFi Driver
        randBind(&availCPU, &cpu);
        if ((rv = wifi_load_driver()) != 0) {
            testPrintE("CPU: %i wifi_load_driver() failed, rv: %i\n",
                cpu, rv);
            exit(20);
        }
        testPrintI("CPU: %i wifi_load_driver succeeded", cpu);

        // Start Supplicant
        randBind(&availCPU, &cpu);
        if ((rv = wifi_start_supplicant()) != 0) {
            testPrintE("CPU: %i wifi_start_supplicant() failed, rv: %i\n",
                cpu, rv);
            exit(21);
        }
        testPrintI("CPU: %i wifi_start_supplicant succeeded", cpu);

        // Sleep a random amount of time
        randDelay();

        /*
         * Obtain WiFi Status
         * Half the time skip this step, which helps increase the
         * level of randomization.
         */
        if (testRandBool()) {
            rv = snprintf(cmd, sizeof(cmd), "%s", CMD_STATUS);
            if (rv >= (signed) sizeof(cmd) - 1) {
                testPrintE("Command too long for: %s\n", CMD_STATUS);
                exit(22);
            }
            execCmd(cmd);
        }

        // Stop Supplicant
        randBind(&availCPU, &cpu);
        if ((rv = wifi_stop_supplicant()) != 0) {
            testPrintE("CPU: %i wifi_stop_supplicant() failed, rv: %i\n",
                cpu, rv);
            exit(23);
        }
        testPrintI("CPU: %i wifi_stop_supplicant succeeded", cpu);

        // Unload WiFi Module
        randBind(&availCPU, &cpu);
        if ((rv = wifi_unload_driver()) != 0) {
            testPrintE("CPU: %i wifi_unload_driver() failed, rv: %i\n",
                cpu, rv);
            exit(24);
        }
        testPrintI("CPU: %i wifi_unload_driver succeeded", cpu);
    }

    // If needed restore WiFi driver to state it was in at the
    // start of the test.  It is assumed that it the driver
    // was loaded, then the wpa_supplicant was also running.
    if (driverLoadedAtStart) {
        // Load driver
        if ((rv = wifi_load_driver()) != 0) {
            testPrintE("main load driver failed, rv: %i", rv);
            exit(25);
        }

        // Start supplicant
        if ((rv = wifi_start_supplicant()) != 0) {
            testPrintE("main start supplicant failed, rv: %i", rv);
            exit(26);
        }

        // Obtain WiFi Status
        rv = snprintf(cmd, sizeof(cmd), "%s", CMD_STATUS);
        if (rv >= (signed) sizeof(cmd) - 1) {
            testPrintE("Command too long for: %s\n", CMD_STATUS);
            exit(22);
        }
        execCmd(cmd);
    }

    // Start framework
    rv = snprintf(cmd, sizeof(cmd), "%s", CMD_START_FRAMEWORK);
    if (rv >= (signed) sizeof(cmd) - 1) {
        testPrintE("Command too long for: %s\n", CMD_START_FRAMEWORK);
        exit(27);
    }
    execCmd(cmd);

    return 0;
}

/*
 * Initialize
 *
 * Perform testcase initialization, which includes:
 *
 *   1. Determine which CPUs are available for use
 *
 *   2. Determine total number of available CPUs
 *
 *   3. Stop framework
 *
 *   4. Determine whether WiFi driver is loaded and if so
 *      stop wpa_supplicant and unload WiFi driver.
 */
void
init(void)
{
    int rv;
    unsigned int n1;
    char cmd[MAXCMD];

    // Use whichever CPUs are available at start of test
    rv = sched_getaffinity(0, sizeof(availCPU), &availCPU);
    if (rv != 0) {
        testPrintE("init sched_getaffinity failed, rv: %i errno: %i",
            rv, errno);
        exit(40);
    }

    // How many CPUs are available
    numAvailCPU = 0;
    for (n1 = 0; n1 < CPU_SETSIZE; n1++) {
        if (CPU_ISSET(n1, &availCPU)) { numAvailCPU++; }
    }
    testPrintI("numAvailCPU: %u", numAvailCPU);

    // Stop framework
    rv = snprintf(cmd, sizeof(cmd), "%s", CMD_STOP_FRAMEWORK);
    if (rv >= (signed) sizeof(cmd) - 1) {
        testPrintE("Command too long for: %s\n", CMD_STOP_FRAMEWORK);
        exit(41);
    }
    execCmd(cmd);

    // Is WiFi driver loaded?
    // If so stop the wpa_supplicant and unload the driver.
    driverLoadedAtStart = is_wifi_driver_loaded();
    testPrintI("driverLoadedAtStart: %u", driverLoadedAtStart);
    if (driverLoadedAtStart) {
        // Stop wpa_supplicant
        // Might already be stopped, in which case request should
        // return immediately with success.
        if ((rv = wifi_stop_supplicant()) != 0) {
            testPrintE("init stop supplicant failed, rv: %i", rv);
            exit(42);
        }
        testPrintI("Stopped wpa_supplicant");

        if ((rv = wifi_unload_driver()) != 0) {
            testPrintE("init unload driver failed, rv: %i", rv);
            exit(43);
        }
        testPrintI("WiFi driver unloaded");
    }

}

/*
 * Execute Command
 *
 * Executes the command pointed to by cmd.  Which CPU executes the
 * command is randomly selected from the set of CPUs that were
 * available during testcase initialization.  Output from the
 * executed command is captured and sent to LogCat Info.  Once
 * the command has finished execution, it's exit status is captured
 * and checked for an exit status of zero.  Any other exit status
 * causes diagnostic information to be printed and an immediate
 * testcase failure.
 */
void
execCmd(const char *cmd)
{
    FILE *fp;
    int rv;
    int status;
    char str[MAXSTR];
    int cpu;

    // Randomly bind to one of the available CPUs
    randBind(&availCPU, &cpu);

    // Display CPU executing on and command to be executed
    testPrintI("CPU: %u cmd: %s", cpu, cmd);

    // Execute the command
    fflush(stdout);
    if ((fp = popen(cmd, "r")) == NULL) {
        testPrintE("execCmd popen failed, errno: %i", errno);
        exit(61);
    }

    // Obtain and display each line of output from the executed command
    while (fgets(str, sizeof(str), fp) != NULL) {
        if ((strlen(str) > 1) && (str[strlen(str) - 1] == '\n')) {
            str[strlen(str) - 1] = '\0';
        }
        testPrintI(" out: %s", str);
        delay(0.1);
    }

    // Obtain and check return status of executed command.
    // Fail on non-zero exit status
    status = pclose(fp);
    if (!(WIFEXITED(status) && (WEXITSTATUS(status) == 0))) {
        testPrintE("Unexpected command failure");
        testPrintE("  status: %#x", status);
        if (WIFEXITED(status)) {
            testPrintE("WEXITSTATUS: %i", WEXITSTATUS(status));
        }
        if (WIFSIGNALED(status)) {
            testPrintE("WTERMSIG: %i", WTERMSIG(status));
        }
        exit(62);
    }
}

/*
 * Random Delay
 *
 * Delays for a random amount of time within the range given
 * by the file scope variables delayMin and delayMax.  The
 * selected amount of delay can come from any part of the
 * range, with a bias towards values closer to delayMin.
 * The amount of bias is determined by the setting of DELAY_EXP.
 * The setting of DELAY_EXP should always be > 1.0, with higher
 * values causing a more significant bias toward the value
 * of delayMin.
 */
void randDelay(void)
{
    const unsigned long nanosecspersec = 1000000000;
    float            fract, biasedFract, amt;
    struct timespec  remaining;
    struct timeval   start, current, delta;

    // Obtain start time
    gettimeofday(&start, NULL);

    // Determine random amount to sleep.
    // Values closer to delayMin are prefered by an amount
    // determined by the value of DELAY_EXP.
    fract = (double) lrand48() / (double) (1UL << 31);
    biasedFract = pow(DELAY_EXP, fract) / pow(DELAY_EXP, 1.0);
    amt = delayMin + ((delayMax - delayMin) * biasedFract);

    do {
        // Get current time
        gettimeofday(&current, NULL);

        // How much time is left
        delta = tvDelta(&start, &current);
        if (tv2double(&delta) > amt) { break; }

        // Request to sleep for the remaining time
        remaining = double2ts(amt - tv2double(&delta));
        (void) nanosleep(&remaining, NULL);
    } while (true);

    testPrintI("delay: %.2f",
        (float) (tv2double(&current) - tv2double(&start)));
}

static void
randBind(const cpu_set_t *availSet, int *chosenCPU)
{
    int rv;
    cpu_set_t cpuset;
    unsigned int chosenAvail, avail, cpu, currentCPU;

    // Randomly bind to a CPU
    // Lower 16 bits from random number generator thrown away,
    // because the low-order bits tend to have the same sequence for
    // different seed values.
    chosenAvail = (lrand48() >> 16) % numAvailCPU;
    CPU_ZERO(&cpuset);
    avail = 0;
    for (cpu = 0; cpu < CPU_SETSIZE; cpu++) {
        if (CPU_ISSET(cpu, availSet)) {
            if (chosenAvail == avail) {
                CPU_SET(cpu, &cpuset);
                break;
            }
            avail++;
        }
    }
    assert(cpu < CPU_SETSIZE);
    sched_setaffinity(0, sizeof(cpuset), &cpuset);

    // Confirm executing on requested CPU
    if ((rv = getcpu(&currentCPU, NULL, NULL)) != 0) {
        testPrintE("randBind getcpu() failed, rv: %i errno: %i", rv, errno);
        exit(80);

    }
    if (currentCPU != cpu) {
        testPrintE("randBind executing on unexpected CPU %i, expected %i",
            currentCPU, cpu);
        exit(81);
    }

    // Let the caller know which CPU was chosen
    *chosenCPU = cpu;
}

// Local implementation of sched_setaffinity(2), sched_getaffinity(2), and
// getcpu(2)
int
sched_setaffinity(pid_t pid, unsigned int cpusetsize, const cpu_set_t *set)
{
    int rv;

    rv = syscall(__NR_sched_setaffinity, pid, cpusetsize, set);

    return rv;
}

int
sched_getaffinity(pid_t pid, unsigned int cpusetsize, cpu_set_t *set)
{
    int rv;

    rv = syscall(__NR_sched_getaffinity, pid, cpusetsize, set);
    if (rv < 0) { return rv; }

    // Kernel implementation of sched_getaffinity() returns the number
    // of bytes in the set that it set.  Set the rest of our set bits
    // to 0.
    memset(((char *) set) + rv, 0x00, sizeof(cpu_set_t) - rv);

    return 0;
}

int
getcpu(unsigned *cpu, unsigned *node, struct getcpu_cache *tcache)
{
    int rv;

    rv = syscall(345, cpu, node, tcache);

    return rv;
}

void
CPU_CLR(int cpu, cpu_set_t *set)
{
    if (cpu < 0) { return; }
    if ((unsigned) cpu >= (sizeof(cpu_set_t) * CHAR_BIT)) { return; }

    *((uint64_t *)set + (cpu / 64)) &= ~(1ULL << (cpu % 64));
}

int
CPU_ISSET(int cpu, const cpu_set_t *set)
{
    if (cpu < 0) { return 0; }
    if ((unsigned) cpu >= (sizeof(cpu_set_t) * CHAR_BIT)) { return 0; }

    if ((*((uint64_t *)set + (cpu / 64))) & (1ULL << (cpu % 64))) {
        return true;
    }

    return false;
}

void
CPU_SET(int cpu, cpu_set_t *set)
{
    if (cpu < 0) { return; }
    if ((unsigned) cpu > (sizeof(cpu_set_t) * CHAR_BIT)) { return; }

    *((uint64_t *)set + (cpu / 64)) |= 1ULL << (cpu % 64);
}

void
CPU_ZERO(cpu_set_t *set)
{
    memset(set, 0x00, sizeof(cpu_set_t));
}
