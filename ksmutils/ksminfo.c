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

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <stdint.h>
#include <getopt.h>

#include <pagemap/pagemap.h>

#define MAX_FILENAME  64

#define GROWTH_FACTOR 10

#define NO_PATTERN    0x100

#define PR_SORTED       1
#define PR_VERBOSE      2

static void usage(char *myname);
static int getprocname(pid_t pid, char *buf, int len);
static void print_ksm_pages(pm_map_t **maps, size_t num_maps, uint8_t pr_flags);
static bool is_pattern(uint8_t *data, size_t len);
static int cmp_pages(const void *a, const void *b);
extern uint32_t hashword(const uint32_t *, size_t, int32_t);

struct ksm_page {
    uint32_t hash;
    unsigned long *vaddr;
    size_t vaddr_len, vaddr_size;
    uint16_t pattern;
};

int main(int argc, char *argv[]) {
    pm_kernel_t *ker;
    pm_process_t *proc;
    pid_t pid;
    pm_map_t **maps;
    size_t num_maps;
    char cmdline[256]; // this must be within the range of int
    int error;
    int rc = EXIT_SUCCESS;
    uint8_t pr_flags = 0;

    opterr = 0;
    do {
        int c = getopt(argc, argv, "hvs");
        if (c == -1)
            break;

        switch (c) {
            case 's':
                pr_flags |= PR_SORTED;
                break;
            case 'v':
                pr_flags |= PR_VERBOSE;
                break;
            case 'h':
                usage(argv[0]);
                exit(EXIT_SUCCESS);
            case '?':
                fprintf(stderr, "unknown option: %c\n", optopt);
                usage(argv[0]);
                exit(EXIT_FAILURE);
        }
    } while (1);

    if (optind != argc - 1) {
        usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    pid = strtoul(argv[optind], NULL, 10);
    if (pid == 0) {
        fprintf(stderr, "Invalid PID\n");
        exit(EXIT_FAILURE);
    }

    error = pm_kernel_create(&ker);
    if (error) {
        fprintf(stderr, "Error creating kernel interface -- "
                        "does this kernel have pagemap?\n");
        exit(EXIT_FAILURE);
    }

    error = pm_process_create(ker, pid, &proc);
    if (error) {
        fprintf(stderr, "warning: could not create process interface for %d\n", pid);
        exit(EXIT_FAILURE);
    }

    error = pm_process_maps(proc, &maps, &num_maps);
    if (error) {
        fprintf(stderr, "warning: could not read process map for %d\n", pid);
        rc = EXIT_FAILURE;
        goto destroy_proc;
    }

    if (getprocname(pid, cmdline, sizeof(cmdline)) < 0) {
        cmdline[0] = '\0';
    }
    printf("%s (%u):\n", cmdline, pid);
    printf("Warning: this tool only compares the KSM CRCs of pages, there is a chance of "
            "collisions\n");
    print_ksm_pages(maps, num_maps, pr_flags);

    free(maps);
destroy_proc:
    pm_process_destroy(proc);
    return rc;
}

static void print_ksm_pages(pm_map_t **maps, size_t num_maps, uint8_t pr_flags) {
    size_t i, j, k;
    size_t len;
    uint64_t *pagemap;
    size_t map_len;
    uint64_t flags;
    pm_kernel_t *ker;
    int error;
    unsigned long vaddr;
    int fd;
    off_t off;
    char filename[MAX_FILENAME];
    uint32_t *data;
    uint32_t hash;
    struct ksm_page *pages;
    size_t pages_len, pages_size;

    if (num_maps <= 0)
        return;

    ker = maps[0]->proc->ker;
    error = snprintf(filename, MAX_FILENAME, "/proc/%d/mem", pm_process_pid(maps[0]->proc));
    if (error < 0 || error >= MAX_FILENAME) {
        return;
    }

    data = malloc(pm_kernel_pagesize(ker));
    if (data == NULL) {
        fprintf(stderr, "warning: not enough memory to malloc data buffer\n");
        return;
    }

    fd = open(filename, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "warning: could not open %s\n", filename);
        goto err_open;
    }

    pages = NULL;
    pages_size = 0;
    pages_len = 0;

    for (i = 0; i < num_maps; i++) {
        error = pm_map_pagemap(maps[i], &pagemap, &map_len);
        if (error) {
            fprintf(stderr, "warning: could not read the pagemap of %d\n",
                    pm_process_pid(maps[i]->proc));
        }
        for (j = 0; j < map_len; j++) {
            error = pm_kernel_flags(ker, pagemap[j], &flags);
            if (error) {
                fprintf(stderr, "warning: could not read flags for pfn at address 0x%016llx\n",
                        pagemap[i]);
                continue;
            }
            if (!(flags & PM_PAGE_KSM)) {
                continue;
            }
            vaddr = pm_map_start(maps[i]) + j * pm_kernel_pagesize(ker);
            off = lseek(fd, vaddr, SEEK_SET);
            if (off == (off_t)-1) {
                fprintf(stderr, "warning: could not lseek to 0x%08lx\n", vaddr);
                continue;
            }
            len = read(fd, data, pm_kernel_pagesize(ker));
            if (len != pm_kernel_pagesize(ker)) {
                fprintf(stderr, "warning: could not read page at 0x%08lx\n", vaddr);
                continue;
            }

            hash = hashword(data, pm_kernel_pagesize(ker) / sizeof(*data), 17);

            for (k = 0; k < pages_len; k++) {
                if (pages[k].hash == hash) break;
            }

            if (k == pages_len) {
                if (pages_len == pages_size) {
                    struct ksm_page *tmp = realloc(pages,
                            (pages_size + GROWTH_FACTOR) * sizeof(*pages));
                    if (tmp == NULL) {
                        fprintf(stderr, "warning: not enough memory to realloc pages struct\n");
                        free(pagemap);
                        goto err_realloc;
                    }
                    memset(&tmp[k], 0, sizeof(tmp[k]) * GROWTH_FACTOR);
                    pages = tmp;
                    pages_size += GROWTH_FACTOR;
                }
                pages[pages_len].hash = hash;
                pages[pages_len].pattern = is_pattern((uint8_t *)data, pm_kernel_pagesize(ker)) ?
                        (data[0] & 0xFF) : NO_PATTERN;
                pages_len++;
            }

            if (pr_flags & PR_VERBOSE) {
                if (pages[k].vaddr_len == pages[k].vaddr_size) {
                    unsigned long *tmp = realloc(pages[k].vaddr,
                            (pages[k].vaddr_size + GROWTH_FACTOR) * sizeof(*(pages[k].vaddr)));
                    if (tmp == NULL) {
                        fprintf(stderr, "warning: not enough memory to realloc vaddr array\n");
                        free(pagemap);
                        goto err_realloc;
                    }
                    memset(&tmp[pages[k].vaddr_len], 0, sizeof(tmp[pages[k].vaddr_len]) * GROWTH_FACTOR);
                    pages[k].vaddr = tmp;
                    pages[k].vaddr_size += GROWTH_FACTOR;
                }
                pages[k].vaddr[pages[k].vaddr_len] = vaddr;
            }
            pages[k].vaddr_len++;
        }
        free(pagemap);
    }

    if (pr_flags & PR_SORTED) {
        qsort(pages, pages_len, sizeof(*pages), cmp_pages);
    }

    for (i = 0; i < pages_len; i++) {
        if (pages[i].pattern != NO_PATTERN) {
            printf("0x%02x byte pattern: ", pages[i].pattern);
        } else {
            printf("KSM CRC 0x%08x:", pages[i].hash);
        }
        printf(" %4d page", pages[i].vaddr_len);
        if (pages[i].vaddr_len > 1) {
            printf("s");
        }
        printf("\n");

        if (pr_flags & PR_VERBOSE) {
            j = 0;
            while (j < pages[i].vaddr_len) {
                printf("                   ");
                for (k = 0; k < 8 && j < pages[i].vaddr_len; k++, j++) {
                    printf(" 0x%08lx", pages[i].vaddr[j]);
                }
                printf("\n");
            }
        }
    }

err_realloc:
    if (pr_flags & PR_VERBOSE) {
        for (i = 0; i < pages_len; i++) {
            free(pages[i].vaddr);
        }
    }
    free(pages);
err_pages:
    close(fd);
err_open:
    free(data);
}

static void usage(char *myname) {
    fprintf(stderr, "Usage: %s [-s | -v | -h ] <pid>\n"
                    "    -s  Sort pages by usage count.\n"
                    "    -v  Verbose: print virtual addresses.\n"
                    "    -h  Display this help screen.\n",
    myname);
}

static int cmp_pages(const void *a, const void *b) {
    const struct ksm_page *pg_a = a;
    const struct ksm_page *pg_b = b;

    return pg_b->vaddr_len - pg_a->vaddr_len;
}

static bool is_pattern(uint8_t *data, size_t len) {
    size_t i;
    uint8_t first_byte = data[0];

    for (i = 1; i < len; i++) {
        if (first_byte != data[i]) return false;
    }

    return true;
}

/*
 * Get the process name for a given PID. Inserts the process name into buffer
 * buf of length len. The size of the buffer must be greater than zero to get
 * any useful output.
 *
 * Note that fgets(3) only declares length as an int, so our buffer size is
 * also declared as an int.
 *
 * Returns 0 on success, a positive value on partial success, and -1 on
 * failure. Other interesting values:
 *   1 on failure to create string to examine proc cmdline entry
 *   2 on failure to open proc cmdline entry
 *   3 on failure to read proc cmdline entry
 */
static int getprocname(pid_t pid, char *buf, int len) {
    char *filename;
    FILE *f;
    int rc = 0;
    static const char* unknown_cmdline = "<unknown>";

    if (len <= 0) {
        return -1;
    }

    if (asprintf(&filename, "/proc/%zd/cmdline", pid) < 0) {
        rc = 1;
        goto exit;
    }

    f = fopen(filename, "r");
    if (f == NULL) {
        rc = 2;
        goto releasefilename;
    }

    if (fgets(buf, len, f) == NULL) {
        rc = 3;
        goto closefile;
    }

closefile:
    (void) fclose(f);
releasefilename:
    free(filename);
exit:
    if (rc != 0) {
        /*
         * The process went away before we could read its process name. Try
         * to give the user "<unknown>" here, but otherwise they get to look
         * at a blank.
         */
        if (strlcpy(buf, unknown_cmdline, (size_t)len) >= (size_t)len) {
            rc = 4;
        }
    }

    return rc;
}

