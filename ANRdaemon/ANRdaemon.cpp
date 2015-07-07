/*
 * Copyright (c) 2015, The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer
 *     in the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Google, Inc. nor the names of its contributors
 *     may be used to endorse or promote products derived from this
 *     software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <binder/IBinder.h>
#include <binder/IServiceManager.h>
#include <binder/Parcel.h>

#include <ctime>
#include <cutils/properties.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <utils/Log.h>
#include <utils/String8.h>
#include <utils/Trace.h>
#include <zlib.h>

using namespace android;

#define CHECK_PERIOD 1  // in sec
#define TRACING_CHECK_PERIOD 500000 // in micro sec
#define MIN_BUFFER_SIZE 4
#define MIN_BUFFER_SIZE_STR "4"
#define MAX_BUFFER_SIZE 128
#define MAX_BUFFER_SIZE_STR "128"
#define CPU_STAT_ENTRIES 7 // number of cpu stat entries

#ifdef LOG_TAG
#undef LOG_TAG
#endif

#define LOG_TAG "anrdaemon"

typedef struct cpu_stat {
    unsigned long utime, ntime, stime, itime;
    unsigned long iowtime, irqtime, sirqtime, steal;
    unsigned long total;
} cpu_stat_t;

/* Make the logging on/off threshold equal to 95% cpu usage. */
static int idle_threshold = 5;

static bool quit = false;
static bool suspend= false;
static bool err = false;
static char err_msg[100];
static bool tracing = false;

static const char *buf_size_kb = "16";
static uint64_t tag = 0;
static const char* apps = "";

static cpu_stat_t new_cpu;
static cpu_stat_t old_cpu;
static Vector<String16> targets;

/* Log certain kernel activity when enabled */
static bool log_sched = false;
static bool log_stack = false;
static bool log_irq   = false;
static bool log_sync  = false;
static bool log_workq = false;

/* Paths for debugfs controls*/
static const char* dfs_trace_output_path =
    "/d/tracing/trace";
static const char* dfs_irq_path =
    "/d/tracing/events/irq/enable";
static const char* dfs_sync_path =
    "/d/tracing/events/sync/enable";
static const char* dfs_workq_path =
    "/d/tracing/events/workqueue/enable";
static const char* dfs_stack_path =
    "/d/tracing/options/stacktrace";
static const char* dfs_sched_switch_path =
    "/d/tracing/events/sched/sched_switch/enable";
static const char* dfs_sched_wakeup_path =
    "/d/tracing/events/sched/sched_wakeup/enable";
static const char* dfs_control_path =
    "/d/tracing/tracing_on";
static const char* dfs_buffer_size_path =
    "/d/tracing/buffer_size_kb";
static const char* dfs_tags_property = "debug.atrace.tags.enableflags";
static const char* dfs_apps_property = "debug.atrace.app_cmdlines";

/*
 * Read accumulated cpu data from /proc/stat
 */
static void get_cpu_stat(cpu_stat_t *cpu) {
    FILE *fp = NULL;
    const char *params = "cpu  %lu %lu %lu %lu %lu %lu %lu %*d %*d %*d\n";

    if ((fp = fopen("/proc/stat", "r")) == NULL) {
        err = true;
        sprintf(err_msg, "can't read from /proc/stat with errno %d", errno);
    } else {
        if (fscanf(fp, params, &cpu->utime, &cpu->ntime,
                &cpu->stime, &cpu->itime, &cpu->iowtime, &cpu->irqtime,
                &cpu->sirqtime) != CPU_STAT_ENTRIES) {
            /*
             * If failed in getting status, new_cpu won't be updated and
             * is_heavy_loaded() will return false.
             */
            ALOGE("Error in getting cpu status. Skipping this check.");
            return;
        }

        cpu->total = cpu->utime + cpu->ntime + cpu->stime + cpu->itime
            + cpu->iowtime + cpu->irqtime + cpu->sirqtime;

        fclose(fp);
    }
}

/*
 * Calculate cpu usage in the past interval.
 * If tracing is on, increase the idle threshold by 1% so that we do not
 * turn on and off tracing frequently whe the cpu load is right close to
 * threshold.
 */
static bool is_heavy_load(void) {
    unsigned long diff_idle, diff_total;
    int threshold = idle_threshold + (tracing?1:0);
    get_cpu_stat(&new_cpu);
    diff_idle = new_cpu.itime - old_cpu.itime;
    diff_total = new_cpu.total - old_cpu.total;
    old_cpu = new_cpu;
    return (diff_idle * 100 < diff_total * threshold);
}

/*
 * Force the userland processes to refresh their property for logging.
 */
static void dfs_poke_binder(Vector<String16> services) {
    sp<IServiceManager> sm = defaultServiceManager();
    services = sm->listServices();
    for (size_t i = 0; i < services.size(); i++) {
        sp<IBinder> obj = sm->checkService(services[i]);
        if (obj != NULL) {
            Parcel data;
            obj->transact(IBinder::SYSPROPS_TRANSACTION, data, NULL, 0);
        }
    }
}

/*
 * Enable/disable a debugfs property by writing 0/1 to its path.
 */
static int dfs_enable(bool enable, const char* path) {
    int fd = open(path, O_WRONLY);
    if (fd == -1) {
        err = true;
        sprintf(err_msg, "Can't open %s. Error: %d", path, errno);
        return -1;
    }
    const char* control = (enable?"1":"0");
    ssize_t len = strlen(control);
    int max_try = 10; // Fail if write was interrupted for 10 times
    while (write(fd, control, len) != len) {
        if (errno == EINTR && max_try-- > 0)
            continue;

        err = true;
        sprintf(err_msg, "Error %d in writing to %s.", errno, path);
    }
    close(fd);
    return (err?-1:0);
}

/*
 * Set the userland tracing properties.
 */
static void dfs_set_property(uint64_t mtag, const char* mapp, bool enable) {
    char buf[64];
    snprintf(buf, 64, "%#" PRIx64, mtag);
    if (property_set(dfs_tags_property, buf) < 0) {
        err = true;
        sprintf(err_msg, "Failed to set debug tags system properties.");
    }

    if (strlen(mapp) > 0
            && property_set(dfs_apps_property, mapp) < 0) {
        err = true;
        sprintf(err_msg, "Failed to set debug applications.");
    }

    if (log_sched) {
        dfs_enable(enable, dfs_sched_switch_path);
        dfs_enable(enable, dfs_sched_wakeup_path);
    }
    if (log_stack) {
        dfs_enable(enable, dfs_stack_path);
    }
    if (log_irq) {
        dfs_enable(enable, dfs_irq_path);
    }
    if (log_sync) {
        dfs_enable(enable, dfs_sync_path);
    }
    if (log_workq) {
        dfs_enable(enable, dfs_workq_path);
    }
}

/*
 * Start logging when cpu usage is high. Meanwhile, moniter the cpu usage and
 * stop logging when it drops down.
 */
static void start_tracing(void) {
    ALOGD("High cpu usage, start logging.");

    dfs_set_property(tag, apps, true);
    dfs_poke_binder(targets);

    if (dfs_enable(true, dfs_control_path) != 0) {
        ALOGE("Failed to start tracing.");
        return;
    }
    tracing = true;

    /* Stop logging when cpu usage drops or the daemon is suspended.*/
    do {
        usleep(TRACING_CHECK_PERIOD);
    } while (!suspend && is_heavy_load());

    if (dfs_enable(false, dfs_control_path) != 0) {
        ALOGE("Failed to stop tracing.");
    }

    dfs_set_property(0, "", false);
    dfs_poke_binder(targets);

    ALOGD("Usage back to low, stop logging.");
    tracing = false;
}

/*
 * Set the tracing log buffer size.
 * Note the actual buffer size will be buf_size_kb * number of cores.
 * E.g. for dory, the total buffer size is buf_size_kb * 4.
 */
static int set_tracing_buffer_size(void) {
    int fd = open(dfs_buffer_size_path, O_WRONLY);
    if (fd == -1) {
        err = true;
        sprintf(err_msg, "Can't open atrace buffer size file under /d/tracing.");
        return -1;
    }
    ssize_t len = strlen(buf_size_kb);
    if (write(fd, buf_size_kb, len) != len) {
        err = true;
        sprintf(err_msg, "Error in writing to atrace buffer size file.");
    }
    close(fd);
    return (err?-1:0);

}

/*
 * Main loop to moniter the cpu usage and decided whether to start logging.
 */
static void start(void) {
    if ((set_tracing_buffer_size()) != 0)
        return;
    get_cpu_stat(&old_cpu);
    sleep(CHECK_PERIOD);

    while (!quit && !err) {
        if (!suspend && is_heavy_load()) {
            /*
             * Increase process priority to make sure we can stop logging when
             * necessary and do not overwrite the buffer
             */
            setpriority(PRIO_PROCESS, 0, -20);
            start_tracing();
            setpriority(PRIO_PROCESS, 0, 0);
        }
        sleep(CHECK_PERIOD);
    }
    return;
}

/*
 * Dump the log in a compressed format for systrace to visualize.
 */
static void dump_trace()
{
    int remain_attempts = 5;
    suspend = true;
    while (tracing) {
        ALOGI("Waiting logging to stop.");
        usleep(TRACING_CHECK_PERIOD);
        remain_attempts--;
        if (remain_attempts == 0) {
            ALOGE("Can't stop logging after 5 attempts. Dump aborted.");
            return;
        }
    }

    /*
     * Create a dump file "dump_of_anrdaemon.<current_time>" under /data/anr/
     */
    time_t now = time(0);
    struct tm  tstruct;
    char time_buf[80];
    char path_buf[200];
    const char* header = " done\nTRACE:\n";
    ssize_t header_len = strlen(header);
    tstruct = *localtime(&now);
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d.%X", &tstruct);
    sprintf(path_buf, "/data/anr/dump_of_anrdaemon.%s", time_buf);
    int output_fd = creat(path_buf, S_IRWXU);
    if (output_fd == -1) {
        ALOGE("Failed to create %s. Dump aborted.", path_buf);
        return;
    }

    if (write(output_fd, header, strlen(header)) != header_len) {
        ALOGE("Failed to write the header.");
        close(output_fd);
        return;
    }

    int trace_fd = open(dfs_trace_output_path, O_RDWR);
    if (trace_fd == -1) {
        ALOGE("Failed to open %s. Dump aborted.", dfs_trace_output_path);
        close(output_fd);
        return;
    }

    z_stream zs;
    uint8_t *in, *out;
    int result, flush;

    memset(&zs, 0, sizeof(zs));
    result = deflateInit(&zs, Z_DEFAULT_COMPRESSION);
    if (result != Z_OK) {
        ALOGE("error initializing zlib: %d\n", result);
        close(trace_fd);
        close(output_fd);
        return;
    }

    const size_t bufSize = 64*1024;
    in = (uint8_t*)malloc(bufSize);
    out = (uint8_t*)malloc(bufSize);
    flush = Z_NO_FLUSH;

    zs.next_out = out;
    zs.avail_out = bufSize;

    do {
        if (zs.avail_in == 0) {
            result = read(trace_fd, in, bufSize);
            if (result < 0) {
                ALOGE("error reading trace: %s", strerror(errno));
                result = Z_STREAM_END;
                break;
            } else if (result == 0) {
                flush = Z_FINISH;
            } else {
                zs.next_in = in;
                zs.avail_in = result;
            }
        }

        if (zs.avail_out == 0) {
            result = write(output_fd, out, bufSize);
            if ((size_t)result < bufSize) {
                ALOGE("error writing deflated trace: %s", strerror(errno));
                result = Z_STREAM_END;
                zs.avail_out = bufSize;
                break;
            }
            zs.next_out = out;
            zs.avail_out = bufSize;
        }

    } while ((result = deflate(&zs, flush)) == Z_OK);

    if (result != Z_STREAM_END) {
        ALOGE("error deflating trace: %s\n", zs.msg);
    }

    if (zs.avail_out < bufSize) {
        size_t bytes = bufSize - zs.avail_out;
        result = write(output_fd, out, bytes);
        if ((size_t)result < bytes) {
            ALOGE("error writing deflated trace: %s", strerror(errno));
        }
    }

    result = deflateEnd(&zs);
    if (result != Z_OK) {
        ALOGE("error cleaning up zlib: %d\n", result);
    }

    free(in);
    free(out);

    close(trace_fd);
    close(output_fd);

    suspend = false;
    ALOGI("Finished dump. Output file stored at: %s", path_buf);
}

static void handle_signal(int signo)
{
    switch (signo) {
        case SIGQUIT:
            suspend = true;
            quit = true;
            break;
        case SIGSTOP:
            suspend = true;
            break;
        case SIGCONT:
            suspend = false;
            break;
        case SIGUSR1:
            dump_trace();
    }
}

/*
 * Set the signal handler:
 * SIGQUIT: Reset debugfs and tracing property and terminate the daemon.
 * SIGSTOP: Stop logging and suspend the daemon.
 * SIGCONT: Resume the daemon as normal.
 * SIGUSR1: Dump the logging to a compressed format for systrace to visualize.
 */
static void register_sighandler(void)
{
    struct sigaction sa;
    sigset_t block_mask;

    sigemptyset(&block_mask);
    sigaddset (&block_mask, SIGQUIT);
    sigaddset (&block_mask, SIGSTOP);
    sigaddset (&block_mask, SIGCONT);
    sigaddset (&block_mask, SIGUSR1);

    sa.sa_flags = 0;
    sa.sa_mask = block_mask;
    sa.sa_handler = handle_signal;
    sigaction(SIGQUIT, &sa, NULL);
    sigaction(SIGSTOP, &sa, NULL);
    sigaction(SIGCONT, &sa, NULL);
    sigaction(SIGUSR1, &sa, NULL);
}

static void show_help(void) {

    fprintf(stderr, "usage: ANRdaemon [options] [categoris...]\n");
    fprintf(stdout, "Options includes:\n"
                    "   -a appname  enable app-level tracing for a comma "
                       "separated list of cmdlines\n"
                    "   -t N        cpu threshold for logging to start "
                        "(min = 50, max = 100, default = 95)\n"
                    "   -s N        use a trace buffer size of N KB "
                        "default to 16KB\n"
                    "   -h          show helps\n");
    fprintf(stdout, "Categoris includes:\n"
                    "   am         - activity manager\n"
                    "   sm         - sync manager\n"
                    "   input      - input\n"
                    "   app        - application\n"
                    "   dalvik     - dalvik VM\n"
                    "   irq        - kernel irq events\n"
                    "   sched      - kernel scheduler activity\n"
                    "   stack      - kernel stack\n"
                    "   sync       - kernel sync activity\n"
                    "   workq      - kernel work queues\n");
    fprintf(stdout, "Control includes:\n"
                    "   SIGQUIT: terminate the process\n"
                    "   SIGSTOP: suspend all function of the daemon\n"
                    "   SIGCONT: resume the normal function\n"
                    "   SIGUSR1: dump the current logging in a compressed form\n");
    exit(0);
}

static int get_options(int argc, char *argv[]) {
    int opt = 0;
    int threshold;
    while ((opt = getopt(argc, argv, "a:s:t:h")) >= 0) {
        switch(opt) {
            case 'a':
                apps = optarg;
                break;
            case 's':
                if (atoi(optarg) > MAX_BUFFER_SIZE)
                    buf_size_kb = MAX_BUFFER_SIZE_STR;
                else if (atoi(optarg) < MIN_BUFFER_SIZE)
                    buf_size_kb = MIN_BUFFER_SIZE_STR;
                else
                    buf_size_kb = optarg;
                break;
            case 't':
                threshold = atoi(optarg);
                if (threshold > 100 || threshold < 50) {
                    fprintf(stderr, "logging threshold should be 50-100\n");
                    return 1;
                }
                idle_threshold = 100 - threshold;
                break;
            case 'h':
                show_help();
                break;
            default:
                fprintf(stderr, "Error in getting options.\n"
                        "run \"%s -h\" for usage.\n", argv[0]);
                return 1;
        }
    }

    for (int i = optind; i < argc; i++) {
        if (strcmp(argv[i], "am") == 0) {
            tag |= ATRACE_TAG_ACTIVITY_MANAGER;
        } else if (strcmp(argv[i], "input") == 0) {
            tag |= ATRACE_TAG_INPUT;
        } else if (strcmp(argv[i], "sm") == 0) {
            tag |= ATRACE_TAG_SYNC_MANAGER;
        } else if (strcmp(argv[i], "app") == 0) {
            tag |= ATRACE_TAG_APP;
        } else if (strcmp(argv[i], "dalvik") == 0) {
            tag |= ATRACE_TAG_DALVIK;
        } else if (strcmp(argv[i], "sched") == 0) {
            log_sched = true;
        } else if (strcmp(argv[i], "stack") == 0) {
            log_stack = true;
        } else if (strcmp(argv[i], "workq") == 0) {
            log_workq = true;
        } else if (strcmp(argv[i], "irq") == 0) {
            log_irq = true;
        } else if (strcmp(argv[i], "sync") == 0) {
            log_sync = true;
        } else {
            fprintf(stderr, "invalid category: %s\n"
                    "run \"%s -h\" for usage.\n", argv[i], argv[0]);
            return 1;
        }
    }

    bool kernel_log = log_sched || log_stack || log_workq || log_irq || log_sync;
    bool app_log = (tag == 0);

    /*
     * There are ~80 services. Too expensive to poke all of them. Just include
     * service that may help high CPU ANR analysis.
     */
    if (app_log) {
       targets.push_back(String16("activity"));
       targets.push_back(String16("alarm"));
       targets.push_back(String16("appops"));
       targets.push_back(String16("cpuinfo"));
       targets.push_back(String16("meminfo"));
       targets.push_back(String16("procstats"));
       targets.push_back(String16("input"));
       targets.push_back(String16("lancherapps"));
       targets.push_back(String16("bluetooth_manager"));
       targets.push_back(String16("SurfaceFlinger"));
       targets.push_back(String16("ClockworkProxyNativeService"));
    }
    if (!kernel_log && !app_log) {
        tag |= ATRACE_TAG_ACTIVITY_MANAGER;
        targets.push_back(String16("activity"));
    }

    return 0;
}

int main(int argc, char *argv[])
{
    if(get_options(argc, argv) != 0)
        return 1;

    if (daemon(0, 0) != 0)
        return 1;

    register_sighandler();

    /* Clear any the trace log file by overwrite it with a new file */
    int fd = creat(dfs_trace_output_path, 0);
    if (fd == -1) {
        ALOGE("Faield to open and cleaup previous log");
        return 1;
    }
    close(fd);

    ALOGI("ANRdaemon starting");
    start();

    if (err)
        ALOGE("ANRdaemon stopped due to Error: %s", err_msg);

    ALOGI("ANRdaemon terminated.");

    return (err?1:0);
}
