#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>

int  main( void )
{
    char  hostname[512];
    int   ret;

    ret = gethostname(hostname, sizeof(hostname));
    if (ret < 0) {
        printf("gethostname() returned error %d: %s\n", errno, strerror(errno));
        return 1;
    }

    printf("gethostname() returned '%s'\n", hostname);
    return 0;
}
