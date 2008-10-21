/*
 * Copyright (C) 2008 The Android Open Source Project
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

#include <dirent.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include <pagemap/pagemap.h>

struct proc_info {
    pid_t pid;
    pm_memusage_t usage;
    unsigned long wss;
};

static void usage(char *myname);
static int getprocname(pid_t pid, char *buf, size_t len);
static int numcmp(long long a, long long b);

#define declare_sort(field) \
    static int sort_by_ ## field (const void *a, const void *b)

declare_sort(vss);
declare_sort(rss);
declare_sort(pss);
declare_sort(uss);

int (*compfn)(const void *a, const void *b);
static int order;

#define MAX_PROCS 256

int main(int argc, char *argv[]) {
    pm_kernel_t *ker;
    pm_process_t *proc;
    pid_t *pids;
    struct proc_info *procs[MAX_PROCS];
    size_t num_procs;
    char cmdline[256];
    int error;

    #define WS_OFF   0
    #define WS_ONLY  1
    #define WS_RESET 2
    int ws;

    int i, j;

    compfn = &sort_by_pss;
    order = -1;
    ws = WS_OFF;

    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-v")) { compfn = &sort_by_vss; continue; }
        if (!strcmp(argv[i], "-r")) { compfn = &sort_by_rss; continue; }
        if (!strcmp(argv[i], "-p")) { compfn = &sort_by_pss; continue; }
        if (!strcmp(argv[i], "-u")) { compfn = &sort_by_uss; continue; }
        if (!strcmp(argv[i], "-w")) { ws = WS_ONLY; continue; }
        if (!strcmp(argv[i], "-W")) { ws = WS_RESET; continue; }
        if (!strcmp(argv[i], "-R")) { order *= -1; continue; }
        if (!strcmp(argv[i], "-h")) { usage(argv[0]); exit(0); }
        fprintf(stderr, "Invalid argument \"%s\".\n", argv[i]);
        usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    error = pm_kernel_create(&ker);
    if (error) {
        fprintf(stderr, "Error creating kernel interface -- "
                        "does this kernel have pagemap?\n");
        exit(EXIT_FAILURE);
    }

    error = pm_kernel_pids(ker, &pids, &num_procs);
    if (error) {
        fprintf(stderr, "Error listing processes.\n");
        exit(EXIT_FAILURE);
    }

    for (i = 0; i < num_procs; i++) {
        procs[i] = malloc(sizeof(struct proc_info));
        if (!procs[i]) {
            fprintf(stderr, "malloc: %s\n", strerror(errno));
            exit(EXIT_FAILURE);
        }
        procs[i]->pid = pids[i];
        error = pm_process_create(ker, pids[i], &proc);
        if (!error) {
            switch (ws) {
            case WS_OFF:
                pm_process_usage(proc, &procs[i]->usage);
                break;
            case WS_ONLY:
                pm_process_workingset(proc, &procs[i]->usage, 0);
                break;
            case WS_RESET:
                pm_process_workingset(proc, NULL, 1);
                break;
            }
            pm_process_destroy(proc);
        } else {
            fprintf(stderr, "warning: could not create process interface for %d\n", pids[i]);
            pm_memusage_zero(&procs[i]->usage);
        }
    }

    free(pids);

    if (ws == WS_RESET) exit(0);

    j = 0;
    for (i = 0; i < num_procs; i++) {
        if (procs[i]->usage.vss)
            procs[j++] = procs[i];
    }
    num_procs = j;

    qsort(procs, num_procs, sizeof(procs[0]), compfn);

    if (ws)
        printf("%5s  %7s  %7s  %7s  %s\n", "PID", "WRss", "WPss", "WUss", "cmdline");
    else
        printf("%5s  %7s  %7s  %7s  %7s  %s\n", "PID", "Vss", "Rss", "Pss", "Uss", "cmdline");
    for (i = 0; i < num_procs; i++) {
        getprocname(procs[i]->pid, cmdline, sizeof(cmdline));
        if (ws)
            printf("%5d  %6dK  %6dK  %6dK  %s\n",
                procs[i]->pid,
                procs[i]->usage.rss / 1024,
                procs[i]->usage.pss / 1024,
                procs[i]->usage.uss / 1024,
                cmdline
            );
        else
            printf("%5d  %6dK  %6dK  %6dK  %6dK  %s\n",
                procs[i]->pid,
                procs[i]->usage.vss / 1024,
                procs[i]->usage.rss / 1024,
                procs[i]->usage.pss / 1024,
                procs[i]->usage.uss / 1024,
                cmdline
            );
    }

    return 0;
}

static void usage(char *myname) {
    fprintf(stderr, "Usage: %s [ -W ] [ -v | -r | -p | -u | -h ]\n"
                    "    -v  Sort by VSS.\n"
                    "    -r  Sort by RSS.\n"
                    "    -p  Sort by PSS.\n"
                    "    -u  Sort by USS.\n"
                    "        (Default sort order is PSS.)\n"
                    "    -R  Reverse sort order (default is descending).\n"
                    "    -w  Display statistics for working set only.\n"
                    "    -W  Reset working set of all processes.\n"
                    "    -h  Display this help screen.\n",
    myname);
}

static int getprocname(pid_t pid, char *buf, size_t len) {
    char filename[20];
    FILE *f;

    sprintf(filename, "/proc/%d/cmdline", pid);
    f = fopen(filename, "r");
    if (!f) { *buf = '\0'; return 1; }
    if (!fgets(buf, len, f)) { *buf = '\0'; return 2; }
    fclose(f);
    return 0;
}

static int numcmp(long long a, long long b) {
    if (a < b) return -1;
    if (a > b) return 1;
    return 0;
}

#define create_sort(field, compfn) \
    static int sort_by_ ## field (const void *a, const void *b) { \
        return order * compfn( \
            (*((struct proc_info**)a))->usage.field, \
            (*((struct proc_info**)b))->usage.field \
        ); \
    }

create_sort(vss, numcmp)
create_sort(rss, numcmp)
create_sort(pss, numcmp)
create_sort(uss, numcmp)
