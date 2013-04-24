/*
 * Copyright (C) 2013 The Android Open Source Project
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

#include <pthread.h>
#include <sched.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <unistd.h>
#include <ctype.h>

#include <map>
#include <vector>

#include "bandwidth.h"


typedef struct {
    const char *name;
    bool int_type;
} option_t;

option_t bandwidth_opts[] = {
    { "size", true },
    { "num_warm_loops", true },
    { "num_loops", true },
    { "type", false },
    { NULL, false },
};

option_t per_core_opts[] = {
    { "size", true },
    { "num_warm_loops", true},
    { "num_loops", true },
    { "type", false },
    { NULL, false },
};

option_t multithread_opts[] = {
    { "size", true },
    { "num_warm_loops", true},
    { "num_loops", true },
    { "type", false },
    { "num_threads", true },
    { NULL, false },
};

typedef union {
    int int_value;
    const char *char_value;
} arg_value_t;
typedef std::map<const char*, arg_value_t> arg_t;

bool processBandwidthOptions(int argc, char** argv, option_t options[],
                             arg_t *values) {
    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '-' && argv[i][1] == '-' && !isdigit(argv[i][2])) {
            char *arg = &argv[i][2];

            for (int j = 0; options[j].name != NULL; j++) {
                if (strcmp(arg, options[j].name) == 0) {
                    const char *name = options[j].name;
                    if (i == argc - 1) {
                        printf("The option --%s requires an argument.\n", name);
                        return false;
                    }
                    if (options[j].int_type) {
                        (*values)[name].int_value = strtol(argv[++i], NULL, 0);
                    } else {
                        (*values)[name].char_value = argv[++i];
                    }
                }
            }
        }
    }

    return true;
}

BandwidthBenchmark *createBandwidthBenchmarkObject(arg_t values) {
    BandwidthBenchmark *bench = NULL;

    const char *name = values["type"].char_value;
    size_t size = 0;
    if (values.count("size") > 0) {
        size = values["size"].int_value;
    }
    if (strcmp(name, "copy_ldrd_strd") == 0) {
        bench = new CopyLdrdStrdBenchmark(size);
    } else if (strcmp(name, "copy_ldmia_stmia") == 0) {
        bench = new CopyLdmiaStmiaBenchmark(size);
    } else if (strcmp(name, "copy_vld_vst") == 0) {
        bench = new CopyVldVstBenchmark(size);
    } else if (strcmp(name, "copy_vldmia_vstmia") == 0) {
        bench = new CopyVldmiaVstmiaBenchmark(size);
    } else if (strcmp(name, "memcpy") == 0) {
        bench = new MemcpyBenchmark(size);
    } else if (strcmp(name, "write_strd") == 0) {
        bench = new WriteStrdBenchmark(size);
    } else if (strcmp(name, "write_stmia") == 0) {
        bench = new WriteStmiaBenchmark(size);
    } else if (strcmp(name, "write_vst") == 0) {
        bench = new WriteVstBenchmark(size);
    } else if (strcmp(name, "write_vstmia") == 0) {
        bench = new WriteVstmiaBenchmark(size);
    } else if (strcmp(name, "memset") == 0) {
        bench = new MemsetBenchmark(size);
    }

    if (bench) {
        if (values.count("num_warm_loops") > 0) {
            bench->set_num_loops(values["num_warm_loops"].int_value);
        }
        if (values.count("num_loops") > 0) {
            bench->set_num_loops(values["num_loops"].int_value);
        }
    }

    return bench;
}

bool getAvailCpus(std::vector<int> *cpu_list) {
    cpu_set_t cpuset;

    CPU_ZERO(&cpuset);
    if (sched_getaffinity(0, sizeof(cpuset), &cpuset) != 0) {
        perror("sched_getaffinity failed.");
        return false;
    }

    for (int i = 0; i < CPU_SETSIZE; i++) {
        if (CPU_ISSET(i, &cpuset)) {
            cpu_list->push_back(i);
        }
    }

    return true;
}

typedef struct {
    int core;
    BandwidthBenchmark *bench;
    double  avg_mb;
    volatile bool *run;
} thread_arg_t;

void *runBandwidthThread(void *data) {
    thread_arg_t *arg = reinterpret_cast<thread_arg_t *>(data);

    if (arg->core >= 0) {
        cpu_set_t cpuset;
        CPU_ZERO(&cpuset);
        CPU_SET(arg->core, &cpuset);
        if (sched_setaffinity(0, sizeof(cpuset), &cpuset) != 0) {
            perror("sched_setaffinity failed");
            return NULL;
        }
    }

    // Spinloop waiting for the run variable to get set to true.
    while (!*arg->run) {
    }

    double avg_mb = 0;
    for (int run = 1; ; run++) {
        arg->bench->run();
        if (!*arg->run) {
            // Throw away the last data point since it's possible not
            // all of the threads are running at this point.
            break;
        }
        avg_mb = (avg_mb/run) * (run-1) + arg->bench->mb_per_sec()/run;
    }
    arg->avg_mb = avg_mb;

    return NULL;
}

bool processThreadArgs(int argc, char** argv, option_t options[],
                       arg_t *values) {
    // Use some smaller values for the number of loops.
    (*values)["num_warm_loops"].int_value = 1000000;
    (*values)["num_loops"].int_value = 10000000;

    if (!processBandwidthOptions(argc, argv, options, values)) {
        return false;
    }
    if (values->count("size") > 0 && ((*values)["size"].int_value % 64) != 0) {
        printf("The size values must be a multiple of 64.\n");
        return false;
    }
    if (values->count("type") == 0) {
        printf("Must specify the type value.\n");
        return false;
    }

    BandwidthBenchmark *bench = createBandwidthBenchmarkObject(*values);
    if (!bench) {
        printf("Unknown type %s\n", (*values)["type"].char_value);
        return false;
    }

    if (setpriority(PRIO_PROCESS, 0, -20)) {
        perror("Unable to raise priority of process.");
        return false;
    }

    printf("Calculating optimum run time...\n");
    nsecs_t t = system_time();
    bench->run();
    t = system_time() - t;
    // Since this is only going to be running single threaded, assume that
    // if the number is set to ten times this value, we should get at least
    // a couple of samples per thread.
    int run_time = int((t/1000000000.0)*10 + 0.5) + 5;

    (*values)["run_time"].int_value = run_time;
    (*values)["size"].int_value = bench->size();
    (*values)["num_warm_loops"].int_value = bench->num_warm_loops();
    (*values)["num_loops"].int_value = bench->num_loops();
    delete bench;

    return true;
}

bool runThreadedTest(thread_arg_t args[], int num_threads, int run_time) {
    pthread_t threads[num_threads];
    volatile bool run = false;

    int rc;
    for (int i = 0; i < num_threads; i++) {
        args[i].run = &run;
        rc = pthread_create(&threads[i], NULL, runBandwidthThread,
                            (void*)&args[i]);
        if (rc != 0) {
            printf("Failed to launch thread %d\n", i);
            return false;
        }
    }

    // Kick start the threads.
    run = true;

    // Let the threads run.
    sleep(run_time);

    // Stop the threads.
    run = false;

    // Wait for the threads to complete.
    for (int i = 0; i < num_threads; i++) {
        rc = pthread_join(threads[i], NULL);
        if (rc != 0) {
            printf("Thread %d failed to join.\n", i);
            return false;
        }
        printf("Thread %d: bandwidth using %s %0.2f MB/s\n", i,
               args[i].bench->getName(), args[i].avg_mb);
    }

    return true;
}

int per_core_bandwidth(int argc, char** argv) {
    arg_t values;
    if (!processThreadArgs(argc, argv, per_core_opts, &values)) {
        return -1;
    }

    std::vector<int> cpu_list;
    if (!getAvailCpus(&cpu_list)) {
        printf("Failed to get available cpu list.\n");
        return -1;
    }

    thread_arg_t args[cpu_list.size()];

    int i = 0;
    for (std::vector<int>::iterator it = cpu_list.begin();
         it != cpu_list.end(); ++it, ++i) {
        args[i].core = *it;
        args[i].bench = createBandwidthBenchmarkObject(values);
    }

    printf("Running on %d cores\n", cpu_list.size());
    printf("  run_time = %ds\n", values["run_time"].int_value);
    printf("  size = %d\n", values["size"].int_value);
    printf("  num_warm_loops = %d\n", values["num_warm_loops"].int_value);
    printf("  num_loops = %d\n", values["num_loops"].int_value);
    printf("\n");

    if (!runThreadedTest(args, cpu_list.size(), values["run_time"].int_value)) {
        return -1;
    }

    return 0;
}

int multithread_bandwidth(int argc, char** argv) {
    arg_t values;
    if (!processThreadArgs(argc, argv, multithread_opts, &values)) {
        return -1;
    }
    if (values.count("num_threads") == 0) {
        printf("Must specify the num_threads value.\n");
        return -1;
    }
    int num_threads = values["num_threads"].int_value;

    thread_arg_t args[num_threads];

    int i = 0;
    for (int i = 0; i < num_threads; i++) {
        args[i].core = -1;
        args[i].bench = createBandwidthBenchmarkObject(values);
    }

    printf("Running %d threads\n", num_threads);
    printf("  run_time = %ds\n", values["run_time"].int_value);
    printf("  size = %d\n", values["size"].int_value);
    printf("  num_warm_loops = %d\n", values["num_warm_loops"].int_value);
    printf("  num_loops = %d\n", values["num_loops"].int_value);
    printf("\n");

    if (!runThreadedTest(args, num_threads, values["run_time"].int_value)) {
        return -1;
    }

    return 0;
}

int copy_bandwidth(int argc, char** argv) {
    arg_t values;
    values["size"].int_value = 0;
    values["num_loops"].int_value = BandwidthBenchmark::DEFAULT_NUM_LOOPS;
    values["num_warm_loops"].int_value = BandwidthBenchmark::DEFAULT_NUM_WARM_LOOPS;
    if (!processBandwidthOptions(argc, argv, bandwidth_opts, &values)) {
        return -1;
    }
    size_t size = values["size"].int_value;
    if ((size % 64) != 0) {
        printf("The size value must be a multiple of 64.\n");
        return -1;
    }

    if (setpriority(PRIO_PROCESS, 0, -20)) {
        perror("Unable to raise priority of process.");
        return -1;
    }

    std::vector<BandwidthBenchmark*> bench_objs;
    bench_objs.push_back(new CopyLdrdStrdBenchmark(size));
    bench_objs.push_back(new CopyLdmiaStmiaBenchmark(size));
    bench_objs.push_back(new CopyVldVstBenchmark(size));
    bench_objs.push_back(new CopyVldmiaVstmiaBenchmark(size));
    bench_objs.push_back(new MemcpyBenchmark(size));

    printf("Benchmarking copy bandwidth\n");
    printf("  size = %d\n", bench_objs[0]->size());
    printf("  num_warm_loops = %d\n", values["num_warm_loops"].int_value);
    printf("  num_loops = %d\n\n", values["num_loops"].int_value);
    for (std::vector<BandwidthBenchmark*>::iterator it = bench_objs.begin();
         it != bench_objs.end(); ++it) {
        (*it)->set_num_warm_loops(values["num_warm_loops"].int_value);
        (*it)->set_num_loops(values["num_loops"].int_value);
        (*it)->run();
        printf("  Copy bandwidth with %s: %0.2f MB/s\n", (*it)->getName(),
               (*it)->mb_per_sec());
    }

    return 0;
}

int write_bandwidth(int argc, char** argv) {
    arg_t values;
    values["size"].int_value = 0;
    values["num_loops"].int_value = BandwidthBenchmark::DEFAULT_NUM_LOOPS;
    values["num_warm_loops"].int_value = BandwidthBenchmark::DEFAULT_NUM_WARM_LOOPS;
    if (!processBandwidthOptions(argc, argv, bandwidth_opts, &values)) {
        return -1;
    }

    size_t size = values["size"].int_value;
    if ((size % 64) != 0) {
        printf("The size value must be a multiple of 64.\n");
        return 1;
    }

    if (setpriority(PRIO_PROCESS, 0, -20)) {
        perror("Unable to raise priority of process.");
        return -1;
    }

    std::vector<BandwidthBenchmark*> bench_objs;
    bench_objs.push_back(new WriteStrdBenchmark(size));
    bench_objs.push_back(new WriteStmiaBenchmark(size));
    bench_objs.push_back(new WriteVstBenchmark(size));
    bench_objs.push_back(new WriteVstmiaBenchmark(size));
    bench_objs.push_back(new MemsetBenchmark(size));

    printf("Benchmarking write bandwidth\n");
    printf("  size = %d\n", bench_objs[0]->size());
    printf("  num_warm_loops = %d\n", values["num_warm_loops"].int_value);
    printf("  num_loops = %d\n\n", values["num_loops"].int_value);
    for (std::vector<BandwidthBenchmark*>::iterator it = bench_objs.begin();
         it != bench_objs.end(); ++it) {
        (*it)->set_num_warm_loops(values["num_warm_loops"].int_value);
        (*it)->set_num_loops(values["num_loops"].int_value);
        (*it)->run();
        printf("  Write bandwidth with %s: %0.2f MB/s\n", (*it)->getName(),
               (*it)->mb_per_sec());
    }

    return 0;
}
