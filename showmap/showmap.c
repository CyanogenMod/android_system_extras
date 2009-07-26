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

mapinfo *read_mapinfo(FILE *fp)
{
    char line[1024];
    mapinfo *mi;
    int len;
    int skip;

again:
    skip = 0;
    
    if(fgets(line, 1024, fp) == 0) return 0;

    len = strlen(line);
    if(len < 1) return 0;
    line[--len] = 0;

    mi = calloc(1, sizeof(mapinfo) + len + 16);
    if(mi == 0) return 0;

    mi->start = strtoul(line, 0, 16);
    mi->end = strtoul(line + 9, 0, 16);

    if(len < 50) {
        if((mi->start >= 0x10000000) && (mi->start < 0x40000000)) {
            strcpy(mi->name, "[stack]");
        } else if(mi->start > 0x50000000) {
            strcpy(mi->name, "[lib_bss]");
        } else {
            strcpy(mi->name, "[anon]");
        }
    } else {
        strcpy(mi->name, line + 49);
    }

    if(fgets(line, 1024, fp) == 0) goto oops;
    if(sscanf(line, "Size: %d kB", &mi->size) != 1) goto oops;
    if(fgets(line, 1024, fp) == 0) goto oops;
    if(sscanf(line, "Rss: %d kB", &mi->rss) != 1) goto oops;
    if(fgets(line, 1024, fp) == 0) goto oops;
    if(sscanf(line, "Pss: %d kB", &mi->pss) == 1)
        if(fgets(line, 1024, fp) == 0) goto oops;
    if(sscanf(line, "Shared_Clean: %d kB", &mi->shared_clean) != 1) goto oops;
    if(fgets(line, 1024, fp) == 0) goto oops;
    if(sscanf(line, "Shared_Dirty: %d kB", &mi->shared_dirty) != 1) goto oops;
    if(fgets(line, 1024, fp) == 0) goto oops;
    if(sscanf(line, "Private_Clean: %d kB", &mi->private_clean) != 1) goto oops;
    if(fgets(line, 1024, fp) == 0) goto oops;
    if(sscanf(line, "Private_Dirty: %d kB", &mi->private_dirty) != 1) goto oops;

    if(fgets(line, 1024, fp) == 0) goto oops; // Referenced
    if(fgets(line, 1024, fp) == 0) goto oops; // Swap
    if(fgets(line, 1024, fp) == 0) goto oops; // KernelPageSize
    if(fgets(line, 1024, fp) == 0) goto oops; // MMUPageSize

    if(skip) {
        free(mi);
        goto again;
    }

    return mi;
oops:
    fprintf(stderr, "WARNING: Format of /proc/<pid>/smaps has changed!\n");
    free(mi);
    return 0;
}


mapinfo *load_maps(int pid, int verbose)
{
    char tmp[128];
    FILE *fp;
    mapinfo *milist = 0;
    mapinfo *mi;
    
    sprintf(tmp, "/proc/%d/smaps", pid);
    fp = fopen(tmp, "r");
    if(fp == 0) return 0;
    
    while((mi = read_mapinfo(fp)) != 0) {
            /* if not verbose, coalesce mappings from the same entity */
        if(!verbose && milist) {
            if((!strcmp(mi->name, milist->name) && (mi->name[0] != '[')) 
               || !strcmp(mi->name,"[lib_bss]")) {
                milist->size += mi->size;
                milist->rss += mi->rss;
                milist->pss += mi->pss;
                milist->shared_clean += mi->shared_clean;
                milist->shared_dirty += mi->shared_dirty;
                milist->private_clean += mi->private_clean;
                milist->private_dirty += mi->private_dirty;
                milist->end = mi->end;
                free(mi);
                continue;
            }
        }

        mi->next = milist;
        milist = mi;
    }
    fclose(fp);
    
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
    if(milist == 0) {
        fprintf(stderr,"cannot get /proc/smaps for pid %d\n", pid);
        return 1;
    }

    if(addresses) {
        printf("start    end      shared   private  object\n");
        printf("-------- -------- -------- -------- ------------------------------\n");
    } else {
        printf("virtual                    shared   shared   private  private\n");
        printf("size     RSS      PSS      clean    dirty    clean    dirty    object\n");
        printf("-------- -------- -------- -------- -------- -------- -------- ------------------------------\n");
    }
    for(mi = milist; mi; mi = mi->next){
        shared_clean += mi->shared_clean;
        shared_dirty += mi->shared_dirty;
        private_clean += mi->private_clean;
        private_dirty += mi->private_dirty;
        rss += mi->rss;
        pss += mi->pss;
        size += mi->size;
        
        if(terse && !mi->private_dirty) continue;

        if(addresses) {
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
    }
    if(addresses) {
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
    
    for(argc--, argv++; argc > 0; argc--, argv++) {
        if(!strcmp(argv[0],"-v")) {
            verbose = 1;
            continue;
        }
        if(!strcmp(argv[0],"-t")) {
            terse = 1;
            continue;
        }
        if(!strcmp(argv[0],"-a")) {
            addresses = 1;
            continue;
        }
        show_map(atoi(argv[0]));
        usage = 0;
    }

    if(usage) {
        fprintf(stderr,
                "showmap [-t] [-v] [-c] <pid>\n"
                "        -t = terse (show only items with private pages)\n"
                "        -v = verbose (don't coalesce adjacant maps)\n"
                "        -a = addresses (show virtual memory map)\n"
                );
    }

	return 0;
}
