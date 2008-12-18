#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <netdb.h>

int  main( int  argc, char**  argv )
{
    char*            hostname = "localhost";
    struct hostent*  hent;
    int    i, ret;

    if (argc > 1)
        hostname = argv[1];

    hent = gethostbyname(hostname);
    if (hent == NULL) {
        printf("gethostbyname(%s) returned NULL !!\n", hostname);
        return 1;
    }
    printf( "gethostbyname(%s) returned:\n", hostname);
    printf( "  name: %s\n", hent->h_name );
    printf( "  aliases:" );
    for (i = 0; hent->h_aliases[i] != NULL; i++)
        printf( " %s", hent->h_aliases[i] );
    printf( "\n" );
    printf( "  address type: " );
    switch (hent->h_addrtype) {
        case AF_INET:  printf( "AF_INET\n"); break;
        case AF_INET6: printf( "AF_INET6\n"); break;
        default: printf("UNKNOWN (%d)\n", hent->h_addrtype);
    }
    printf( "  address: " );
    switch (hent->h_addrtype) {
        case AF_INET:
            {
                const char*  dot = "";
                for (i = 0; i < hent->h_length; i++) {
                    printf("%s%d", dot, ((unsigned char*)hent->h_addr)[i]);
                    dot = ".";
                }
            }
            break;

        default:
            for (i = 0; i < hent->h_length; i++) {
                printf( "%02x", ((unsigned char*)hent->h_addr)[i] );
            }
    }
    printf("\n");
    return 0;
}
