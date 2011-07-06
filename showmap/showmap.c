#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

#include <ctype.h>
#include <stddef.h>

typedef struct mapinfo mapinfo;

struct mapinfo {
    mapinfo *next;
    unsigned start;
    unsigned end;
    unsigned size;
    unsigned rss;
    unsigned pss;
    unsigned shared_clean;
    unsigned shared_dirty;
    unsigned private_clean;
    unsigned private_dirty;
    char name[1];
};

// 6f000000-6f01e000 rwxp 00000000 00:0c 16389419   /android/lib/libcomposer.so
// 012345678901234567890123456789012345678901234567890123456789
// 0         1         2         3         4         5

int parse_header(char* line, int len, mapinfo** mi) {
    unsigned long start;
    unsigned long end;
    char name[128];

    name[0] = '\0';

    // Sometimes the name is missing.
    if (sscanf(line, "%lx-%lx %*s %*lx %*x:%*x %*ld %127s", &start, &end, name) < 2) {
        return 0;
    }

    if (name[0] == '\0') {
        if ((start >= 0x10000000) && (start < 0x40000000)) {
            strlcpy(name, "[stack]", sizeof(name));
        } else if (start > 0x50000000) {
            strlcpy(name, "[lib_bss]", sizeof(name));
        } else {
            strlcpy(name, "[anon]", sizeof(name));
        }
    }

    const int name_size = strlen(name) + 1;
    struct mapinfo* info = calloc(1, sizeof(mapinfo) + name_size);
    if (info == NULL) {
        return -1;
    }

    info->start = start;
    info->end = end;
    strlcpy(info->name, name, name_size);

    *mi = info;

    return 0;
}

int parse_field(mapinfo* mi, char* line) {
    char field[64];
    int size;

    if (sscanf(line, "%63s %d kB", field, &size) != 2) {
        return -1;
    }

    if (!strcmp(field, "Size:")) {
        mi->size = size;
    } else if (!strcmp(field, "Rss:")) {
        mi->rss = size;
    } else if (!strcmp(field, "Pss:")) {
        mi->pss = size;
    } else if (!strcmp(field, "Shared_Clean:")) {
        mi->shared_clean = size;
    } else if (!strcmp(field, "Shared_Dirty:")) {
        mi->shared_dirty = size;
    } else if (!strcmp(field, "Private_Clean:")) {
        mi->private_clean = size;
    } else if (!strcmp(field, "Private_Dirty:")) {
        mi->private_dirty = size;
    }

    return 0;
}

mapinfo *read_mapinfo(FILE *fp)
{
    char line[1024];
    mapinfo *current = NULL;
    int len;
    int skip;

    while (fgets(line, sizeof(line), fp) != 0) {
        if (current != NULL) {
            parse_field(current, line);
        }

        len = strlen(line);
        if (len < 1) {
            return NULL;
        }
        line[--len] = 0;

        mapinfo *next = NULL;
        if (parse_header(line, len, &next) < 0) {
            goto err;
        } else if (next != NULL) {
            next->next = current;
            current = next;
            continue;
        }
    }

    return current;

err:
    while (current != NULL) {
        mapinfo* next = current->next;
        free(current);
        current = next;
    }

    return NULL;
}


mapinfo *load_maps(int pid, int verbose)
{
    char tmp[128];
    FILE *fp;
    mapinfo *milist = 0;
    mapinfo *mi;
    
    snprintf(tmp, sizeof(tmp), "/proc/%d/smaps", pid);
    fp = fopen(tmp, "r");
    if (fp == 0) {
        fprintf(stderr, "cannot open /proc/%d/smaps: %s\n", pid, strerror(errno));
        return NULL;
    }

    milist = read_mapinfo(fp);
    fclose(fp);

    if (!milist) {
        fprintf(stderr, "could not read /proc/%d/smaps\n", pid);
        return NULL;
    }
    
    /* if not verbose, coalesce mappings from the same entity */
    if (!verbose) {
        mapinfo* current = milist;
        mapinfo* last = NULL;

        while (current != NULL) {
            mapinfo* next = current->next;

            if (last != NULL
                    && ((current->name[0] != '[' && !strcmp(last->name, current->name))
                        || !strcmp(current->name, "[lib_bss]"))) {
                last->size += current->size;
                last->rss += current->rss;
                last->pss += current->pss;
                last->shared_clean += current->shared_clean;
                last->shared_dirty += current->shared_dirty;
                last->private_clean += current->private_clean;
                last->private_dirty += current->private_dirty;
                last->end = current->end;

                last->next = next;
                free(current);
            } else {
                last = current;
            }

            current = next;
        }
    }

    return milist;
}

static int verbose = 0;
static int terse = 0;
static int addresses = 0;

int show_map(int pid)
{
    mapinfo *milist;
    mapinfo *mi;
    unsigned shared_dirty = 0;
    unsigned shared_clean = 0;
    unsigned private_dirty = 0;
    unsigned private_clean = 0;
    unsigned rss = 0;
    unsigned pss = 0;
    unsigned size = 0;
    
    milist = load_maps(pid, verbose);
    if (milist == NULL) {
        return 1;
    }

    if (addresses) {
        printf("start    end      shared   private  object\n");
        printf("-------- -------- -------- -------- ------------------------------\n");
    } else {
        printf("virtual                    shared   shared   private  private\n");
        printf("size     RSS      PSS      clean    dirty    clean    dirty    object\n");
        printf("-------- -------- -------- -------- -------- -------- -------- ------------------------------\n");
    }

    for (mi = milist; mi;) {
        mapinfo* last = mi;

        shared_clean += mi->shared_clean;
        shared_dirty += mi->shared_dirty;
        private_clean += mi->private_clean;
        private_dirty += mi->private_dirty;
        rss += mi->rss;
        pss += mi->pss;
        size += mi->size;
        
        if (terse && !mi->private_dirty) {
            goto out;
        }

        if (addresses) {
            printf("%08x %08x %8d %8d %s\n", mi->start, mi->end,
                   mi->shared_clean + mi->shared_dirty,
                   mi->private_clean + mi->private_dirty,
                   mi->name);
        } else {
            printf("%8d %8d %8d %8d %8d %8d %8d %s\n", mi->size,
                   mi->rss,
                   mi->pss,
                   mi->shared_clean, mi->shared_dirty,
                   mi->private_clean, mi->private_dirty,
                   mi->name);
        }

out:
        mi = mi->next;
        free(last);
    }

    if (addresses) {
        printf("-------- -------- -------- -------- ------------------------------\n");
        printf("                  %8d %8d TOTAL\n", 
               shared_dirty + shared_clean, 
               private_dirty + private_clean);
    } else {
        printf("-------- -------- -------- -------- -------- -------- -------- ------------------------------\n");
        printf("%8d %8d %8d %8d %8d %8d %8d TOTAL\n", size,
               rss, pss,
               shared_clean, shared_dirty,
               private_clean, private_dirty);
    }

    return 0;
}

int main(int argc, char *argv[])
{
    int usage = 1;
    
    for (argc--, argv++; argc > 0; argc--, argv++) {
        if (!strcmp(argv[0],"-v")) {
            verbose = 1;
            continue;
        }
        if (!strcmp(argv[0],"-t")) {
            terse = 1;
            continue;
        }
        if (!strcmp(argv[0],"-a")) {
            addresses = 1;
            continue;
        }
        show_map(atoi(argv[0]));
        usage = 0;
    }

    if (usage) {
        fprintf(stderr,
                "showmap [-t] [-v] [-c] <pid>\n"
                "        -t = terse (show only items with private pages)\n"
                "        -v = verbose (don't coalesce adjacant maps)\n"
                "        -a = addresses (show virtual memory map)\n"
                );
    }

    return 0;
}
