/*
** Copyright 2010 The Android Open Source Project
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/

/*
 * Micro-benchmarking of sleep/cpu speed/memcpy/memset/memory reads/strcmp.
 */

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <math.h>
#include <sched.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

// The default size of data that will be manipulated in each iteration of
// a memory benchmark. Can be modified with the --data_size option.
#define DEFAULT_DATA_SIZE       1000000000

// Number of nanoseconds in a second.
#define NS_PER_SEC              1000000000

// The maximum number of arguments that a benchmark will accept.
#define MAX_ARGS    2

// Contains information about benchmark options.
typedef struct {
    bool print_average;
    bool print_each_iter;

    int dst_align;
    int dst_or_mask;
    int src_align;
    int src_or_mask;

    int cpu_to_lock;

    int data_size;

    int args[MAX_ARGS];
    int num_args;
} command_data_t;

typedef void *(*void_func_t)();
typedef void *(*memcpy_func_t)(void *, const void *, size_t);
typedef void *(*memset_func_t)(void *, int, size_t);
typedef int (*strcmp_func_t)(const char *, const char *);
typedef char *(*strcpy_func_t)(char *, const char *);

// Struct that contains a mapping of benchmark name to benchmark function.
typedef struct {
    const char *name;
    int (*ptr)(const char *, const command_data_t &, void_func_t func);
    void_func_t func;
} function_t;

// Get the current time in nanoseconds.
uint64_t nanoTime() {
  struct timespec t;

  t.tv_sec = t.tv_nsec = 0;
  clock_gettime(CLOCK_MONOTONIC, &t);
  return static_cast<uint64_t>(t.tv_sec) * NS_PER_SEC + t.tv_nsec;
}

// Allocate memory with a specific alignment and return that pointer.
// This function assumes an alignment value that is a power of 2.
// If the alignment is 0, then use the pointer returned by malloc.
uint8_t *getAlignedMemory(uint8_t *orig_ptr, int alignment, int or_mask) {
  uint64_t ptr = reinterpret_cast<uint64_t>(orig_ptr);
  if (alignment > 0) {
      // When setting the alignment, set it to exactly the alignment chosen.
      // The pointer returned will be guaranteed not to be aligned to anything
      // more than that.
      ptr += alignment - (ptr & (alignment - 1));
      ptr |= alignment | or_mask;
  }

  return reinterpret_cast<uint8_t*>(ptr);
}

// Allocate memory with a specific alignment and return that pointer.
// This function assumes an alignment value that is a power of 2.
// If the alignment is 0, then use the pointer returned by malloc.
uint8_t *allocateAlignedMemory(size_t size, int alignment, int or_mask) {
  uint64_t ptr = reinterpret_cast<uint64_t>(malloc(size + 3 * alignment));
  if (!ptr)
      return NULL;
  return getAlignedMemory((uint8_t*)ptr, alignment, or_mask);
}

static inline double computeAverage(uint64_t time_ns, int size, int copies) {
    return ((size/1024.0) * copies) / ((double)time_ns/NS_PER_SEC);
}

static inline double computeRunningAvg(double avg, double running_avg, size_t cur_idx) {
    return (running_avg / (cur_idx + 1)) * cur_idx + (avg / (cur_idx + 1));
}

static inline double computeRunningSquareAvg(double avg, double square_avg, size_t cur_idx) {
    return (square_avg / (cur_idx + 1)) * cur_idx + (avg / (cur_idx + 1)) * avg;
}

static inline double computeStdDev(double square_avg, double running_avg) {
    return sqrt(square_avg - running_avg * running_avg);
}

static inline void printIter(uint64_t time_ns, const char *name, int size, int copies, double avg) {
    printf("%s %dx%d bytes took %.06f seconds (%f MB/s)\n",
           name, copies, size, (double)time_ns/NS_PER_SEC, avg/1024.0);
}

static inline void printSummary(uint64_t time_ns, const char *name, int size, int copies, double running_avg, double std_dev, double min, double max) {
    printf("  %s %dx%d bytes average %.2f MB/s std dev %.4f min %.2f MB/s max %.2f MB/s\n",
           name, copies, size, running_avg/1024.0, std_dev/1024.0, min/1024.0,
           max/1024.0);
}

#define MAINLOOP(cmd_data, BENCH, COMPUTE_AVG, PRINT_ITER, PRINT_AVG) \
    uint64_t time_ns;                                                 \
    int iters = cmd_data.args[1];                                     \
    bool print_average = cmd_data.print_average;                      \
    bool print_each_iter = cmd_data.print_each_iter;                  \
    double min = 0.0, max = 0.0, running_avg = 0.0, square_avg = 0.0; \
    double avg;                                                       \
    for (int i = 0; iters == -1 || i < iters; i++) {                  \
        time_ns = nanoTime();                                         \
        BENCH;                                                        \
        time_ns = nanoTime() - time_ns;                               \
        avg = COMPUTE_AVG;                                            \
        if (print_average) {                                          \
            running_avg = computeRunningAvg(avg, running_avg, i);     \
            square_avg = computeRunningSquareAvg(avg, square_avg, i); \
            if (min == 0.0 || avg < min) {                            \
                min = avg;                                            \
            }                                                         \
            if (avg > max) {                                          \
                max = avg;                                            \
            }                                                         \
        }                                                             \
        if (print_each_iter) {                                        \
            PRINT_ITER;                                               \
        }                                                             \
    }                                                                 \
    if (print_average) {                                              \
        PRINT_AVG;                                                    \
    }

#define MAINLOOP_DATA(name, cmd_data, size, BENCH)                    \
    int copies = cmd_data.data_size/size;                             \
    int j;                                                            \
    MAINLOOP(cmd_data,                                                \
             for (j = 0; j < copies; j++) {                           \
                 BENCH;                                               \
             },                                                       \
             computeAverage(time_ns, size, copies),                   \
             printIter(time_ns, name, size, copies, avg),             \
             double std_dev = computeStdDev(square_avg, running_avg); \
             printSummary(time_ns, name, size, copies, running_avg,   \
                          std_dev, min, max));

int benchmarkSleep(const char *name, const command_data_t &cmd_data, void_func_t func) {
    int delay = cmd_data.args[0];
    MAINLOOP(cmd_data, sleep(delay),
             (double)time_ns/NS_PER_SEC,
             printf("sleep(%d) took %.06f seconds\n", delay, avg);,
             printf("  sleep(%d) average %.06f seconds std dev %f min %.06f seconds max %0.6f seconds\n", \
                    delay, running_avg, computeStdDev(square_avg, running_avg), \
                    min, max));

    return 0;
}

int benchmarkCpu(const char *name, const command_data_t &cmd_data, void_func_t func) {
    // Use volatile so that the loop is not optimized away by the compiler.
    volatile int cpu_foo;

    MAINLOOP(cmd_data,
             for (cpu_foo = 0; cpu_foo < 100000000; cpu_foo++),
             (double)time_ns/NS_PER_SEC,
             printf("cpu took %.06f seconds\n", avg),
             printf("  cpu average %.06f seconds std dev %f min %0.6f seconds max %0.6f seconds\n", \
                    running_avg, computeStdDev(square_avg, running_avg), min, max));

    return 0;
}

int benchmarkMemset(const char *name, const command_data_t &cmd_data, void_func_t func) {
    int size = cmd_data.args[0];
    memset_func_t memset_func = reinterpret_cast<memset_func_t>(func);

    uint8_t *dst = allocateAlignedMemory(size, cmd_data.dst_align, cmd_data.dst_or_mask);
    if (!dst)
        return -1;

    MAINLOOP_DATA(name, cmd_data, size, memset_func(dst, 0, size));

    return 0;
}

int benchmarkMemcpy(const char *name, const command_data_t &cmd_data, void_func_t func) {
    int size = cmd_data.args[0];
    memcpy_func_t memcpy_func = reinterpret_cast<memcpy_func_t>(func);

    uint8_t *src = allocateAlignedMemory(size, cmd_data.src_align, cmd_data.src_or_mask);
    if (!src)
        return -1;
    uint8_t *dst = allocateAlignedMemory(size, cmd_data.dst_align, cmd_data.dst_or_mask);
    if (!dst)
        return -1;

    // Initialize the source and destination to known values.
    // If not initialized, the benchmark results are skewed.
    memset(src, 0xff, size);
    memset(dst, 0, size);

    MAINLOOP_DATA(name, cmd_data, size, memcpy_func(dst, src, size));

    return 0;
}

int benchmarkMemread(const char *name, const command_data_t &cmd_data, void_func_t func) {
    int size = cmd_data.args[0];

    uint32_t *src = reinterpret_cast<uint32_t*>(malloc(size));
    if (!src)
        return -1;
    memset(src, 0xff, size);

    // Use volatile so the compiler does not optimize away the reads.
    volatile int foo;
    size_t k;
    MAINLOOP_DATA(name, cmd_data, size,
                  for (k = 0; k < size/sizeof(uint32_t); k++) foo = src[k]);

    return 0;
}

int benchmarkStrcmp(const char *name, const command_data_t &cmd_data, void_func_t func) {
    int size = cmd_data.args[0];
    strcmp_func_t strcmp_func = reinterpret_cast<strcmp_func_t>(func);

    char *string1 = reinterpret_cast<char*>(allocateAlignedMemory(size, cmd_data.src_align, cmd_data.src_or_mask));
    if (!string1)
        return -1;
    char *string2 = reinterpret_cast<char*>(allocateAlignedMemory(size, cmd_data.dst_align, cmd_data.dst_or_mask));
    if (!string2)
        return -1;

    for (int i = 0; i < size - 1; i++) {
        string1[i] = (char)(32 + (i % 96));
        string2[i] = string1[i];
    }
    string1[size-1] = '\0';
    string2[size-1] = '\0';

    int retval;
    MAINLOOP_DATA(name, cmd_data, size,
                  retval = strcmp_func(string1, string2); \
                  if (retval != 0) printf("%s failed, return value %d\n", name, retval));

    return 0;
}

int benchmarkStrcpy(const char *name, const command_data_t &cmd_data, void_func_t func) {
    int size = cmd_data.args[0];
    strcpy_func_t strcpy_func = reinterpret_cast<strcpy_func_t>(func);

    char *src = reinterpret_cast<char*>(allocateAlignedMemory(size, cmd_data.src_align, cmd_data.src_or_mask));
    if (!src)
        return -1;
    char *dst = reinterpret_cast<char*>(allocateAlignedMemory(size, cmd_data.dst_align, cmd_data.dst_or_mask));
    if (!dst)
        return -1;

    for (int i = 0; i < size - 1; i++) {
        src[i] = (char)(32 + (i % 96));
    }
    src[size-1] = '\0';
    memset(dst, 0, size);

    MAINLOOP_DATA(name, cmd_data, size, strcpy_func(dst, src));

    return 0;
}


// Create the mapping structure.
function_t function_table[] = {
    { "sleep", benchmarkSleep, NULL },
    { "cpu", benchmarkCpu, NULL },
    { "memread", benchmarkMemread, NULL },
    { "memset", benchmarkMemset, reinterpret_cast<void_func_t>(memset) },
    { "memcpy", benchmarkMemcpy, reinterpret_cast<void_func_t>(memcpy) },
    { "strcmp", benchmarkStrcmp, reinterpret_cast<void_func_t>(strcmp) },
    { "strcpy", benchmarkStrcpy, reinterpret_cast<void_func_t>(strcpy) },
};

void usage() {
    printf("Usage:\n");
    printf("  micro_bench [--data_size DATA_BYTES] [--print_average]\n");
    printf("              [--no_print_each_iter] [--lock_to_cpu CORE]\n");
    printf("    --data_size DATA_BYTES\n");
    printf("      For the data benchmarks (memcpy/memset/memread) the approximate\n");
    printf("      size of data, in bytes, that will be manipulated in each iteration.\n");
    printf("    --print_average\n");
    printf("      Print the average and standard deviation of all iterations.\n");
    printf("    --no_print_each_iter\n");
    printf("      Do not print any values in each iteration.\n");
    printf("    --lock_to_cpu CORE\n");
    printf("      Lock to the specified CORE. The default is to use the last core found.\n");
    printf("    ITERS\n");
    printf("      The number of iterations to execute each benchmark. If not\n");
    printf("      passed in then run forever.\n");
    printf("  micro_bench sleep TIME_TO_SLEEP [ITERS]\n");
    printf("    TIME_TO_SLEEP\n");
    printf("      The time in seconds to sleep.\n");
    printf("  micro_bench cpu UNUSED [ITERS]\n");
    printf("  micro_bench [--dst_align ALIGN] memset NUM_BYTES [ITERS]\n");
    printf("    --dst_align ALIGN\n");
    printf("      Align the memset destination pointer to ALIGN. The default is to use the\n");
    printf("      value returned by malloc.\n");
    printf("  micro_bench [--src_align ALIGN] [--dst_align ALIGN] strcpy NUM_BYTES [ITERS]\n");
    printf("    --src_align ALIGN\n");
    printf("      Align the strcpy source string to ALIGN. The default is to use the\n");
    printf("      value returned by malloc.\n");
    printf("    --dst_align ALIGN\n");
    printf("      Align the strcpy destination string to ALIGN. The default is to use the\n");
    printf("      value returned by malloc.\n");
    printf("  micro_bench [--src_align ALIGN] [--dst_align ALIGN] strcmp NUM_BYTES [ITERS]\n");
    printf("    --src_align ALIGN\n");
    printf("      Align the first strcmp string to ALIGN. The default is to use the\n");
    printf("      value returned by malloc.\n");
    printf("    --dst_align ALIGN\n");
    printf("      Align the second strcmp string to ALIGN. The default is to use the\n");
    printf("      value returned by malloc.\n");
    printf("  micro_bench memread NUM_BYTES [ITERS]\n");
}

function_t *processOptions(int argc, char **argv, command_data_t *cmd_data) {
    function_t *command = NULL;

    // Initialize the command_flags.
    cmd_data->print_average = false;
    cmd_data->print_each_iter = true;
    cmd_data->dst_align = 0;
    cmd_data->src_align = 0;
    cmd_data->src_or_mask = 0;
    cmd_data->dst_or_mask = 0;
    cmd_data->num_args = 0;
    cmd_data->cpu_to_lock = -1;
    cmd_data->data_size = DEFAULT_DATA_SIZE;
    for (int i = 0; i < MAX_ARGS; i++) {
        cmd_data->args[i] = -1;
    }

    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '-') {
            int *save_value = NULL;
            if (strcmp(argv[i], "--print_average") == 0) {
              cmd_data->print_average = true;
            } else if (strcmp(argv[i], "--no_print_each_iter") == 0) {
              cmd_data->print_each_iter = false;
            } else if (strcmp(argv[i], "--dst_align") == 0) {
              save_value = &cmd_data->dst_align;
            } else if (strcmp(argv[i], "--src_align") == 0) {
              save_value = &cmd_data->src_align;
            } else if (strcmp(argv[i], "--dst_or_mask") == 0) {
              save_value = &cmd_data->dst_or_mask;
            } else if (strcmp(argv[i], "--src_or_mask") == 0) {
              save_value = &cmd_data->src_or_mask;
            } else if (strcmp(argv[i], "--lock_to_cpu") == 0) {
              save_value = &cmd_data->cpu_to_lock;
            } else if (strcmp(argv[i], "--data_size") == 0) {
              save_value = &cmd_data->data_size;
            } else {
                printf("Unknown option %s\n", argv[i]);
                return NULL;
            }
            if (save_value) {
                // Checking both characters without a strlen() call should be
                // safe since as long as the argument exists, one character will
                // be present (\0). And if the first character is '-', then
                // there will always be a second character (\0 again).
                if (i == argc - 1 || (argv[i + 1][0] == '-' && !isdigit(argv[i + 1][1]))) {
                    printf("The option %s requires one argument.\n",
                           argv[i]);
                    return NULL;
                }
                *save_value = (int)strtol(argv[++i], NULL, 0);
            }
        } else if (!command) {
            for (size_t j = 0; j < sizeof(function_table)/sizeof(function_t); j++) {
                if (strcmp(argv[i], function_table[j].name) == 0) {
                    command = &function_table[j];
                    break;
                }
            }
            if (!command) {
                printf("Uknown command %s\n", argv[i]);
                return NULL;
            }
        } else if (cmd_data->num_args > MAX_ARGS) {
            printf("More than %d number arguments passed in.\n", MAX_ARGS);
            return NULL;
        } else {
            cmd_data->args[cmd_data->num_args++] = atoi(argv[i]);
        }
    }

    // Check the arguments passed in make sense.
    if (cmd_data->num_args != 1 && cmd_data->num_args != 2) {
        printf("Not enough arguments passed in.\n");
        return NULL;
    } else if (cmd_data->dst_align < 0) {
        printf("The --dst_align option must be greater than or equal to 0.\n");
        return NULL;
    } else if (cmd_data->src_align < 0) {
        printf("The --src_align option must be greater than or equal to 0.\n");
        return NULL;
    } else if (cmd_data->data_size <= 0) {
        printf("The --data_size option must be a positive number.\n");
        return NULL;
    } else if ((cmd_data->dst_align & (cmd_data->dst_align - 1))) {
        printf("The --dst_align option must be a power of 2.\n");
        return NULL;
    } else if ((cmd_data->src_align & (cmd_data->src_align - 1))) {
        printf("The --src_align option must be a power of 2.\n");
        return NULL;
    } else if (!cmd_data->src_align && cmd_data->src_or_mask) {
        printf("The --src_or_mask option requires that --src_align be set.\n");
        return NULL;
    } else if (!cmd_data->dst_align && cmd_data->dst_or_mask) {
        printf("The --dst_or_mask option requires that --dst_align be set.\n");
        return NULL;
    } else if (cmd_data->src_or_mask > cmd_data->src_align) {
        printf("The value of --src_or_mask cannot be larger that --src_align.\n");
        return NULL;
    } else if (cmd_data->dst_or_mask > cmd_data->dst_align) {
        printf("The value of --src_or_mask cannot be larger that --src_align.\n");
        return NULL;
    }

    return command;
}

bool raisePriorityAndLock(int cpu_to_lock) {
    cpu_set_t cpuset;

    if (setpriority(PRIO_PROCESS, 0, -20)) {
        perror("Unable to raise priority of process.\n");
        return false;
    }

    CPU_ZERO(&cpuset);
    if (sched_getaffinity(0, sizeof(cpuset), &cpuset) != 0) {
        perror("sched_getaffinity failed");
        return false;
    }

    if (cpu_to_lock < 0) {
        // Lock to the last active core we find.
        for (int i = 0; i < CPU_SETSIZE; i++) {
            if (CPU_ISSET(i, &cpuset)) {
                cpu_to_lock = i;
            }
        }
    } else if (!CPU_ISSET(cpu_to_lock, &cpuset)) {
        printf("Cpu %d does not exist.\n", cpu_to_lock);
        return false;
    }

    if (cpu_to_lock < 0) {
        printf("Cannot find any valid cpu to lock.\n");
        return false;
    }

    CPU_ZERO(&cpuset);
    CPU_SET(cpu_to_lock, &cpuset);
    if (sched_setaffinity(0, sizeof(cpuset), &cpuset) != 0) {
        perror("sched_setaffinity failed");
        return false;
    }

    return true;
}

int main(int argc, char **argv) {
    command_data_t cmd_data;

    function_t *command = processOptions(argc, argv, &cmd_data);
    if (!command) {
      usage();
      return -1;
    }

    if (!raisePriorityAndLock(cmd_data.cpu_to_lock)) {
      return -1;
    }

    printf("%s\n", command->name);
    return (*command->ptr)(command->name, cmd_data, command->func);
}
