#include <stdio.h>
#include <arpa/inet.h>  /* for htons() etc.. */

static char  tab[8];

static void
read4( int  o, unsigned val )
{
    unsigned  v = htonl(val);
    unsigned  v2;

    tab[o+0] = (char)(v >> 24);
    tab[o+1] = (char)(v >> 16);
    tab[o+2] = (char)(v >> 8);
    tab[o+3] = (char)(v);

    printf( "read4: offset=%d value=%08x: ", o, val );
    fflush(stdout);

    v2 = *(unsigned*)(tab+o);

    if (v2 != val) {
        printf( "FAIL (%08x)\n", v2 );
    } else {
        printf( "ok\n" );
    }
}

static void
writ4( int  o, unsigned val )
{
    unsigned  v = htonl(val);
    unsigned  v2;

    printf( "writ4: offset=%d value=%08x: ", o, val );
    fflush(stdout);

    *(unsigned*)(tab+o) = v;

    v2 = ((unsigned)tab[o+0] << 24) |
         ((unsigned)tab[o+1] << 16) |
         ((unsigned)tab[o+2] << 8 ) |
         ((unsigned)tab[o+3]      );

    if (v2 != val) {
        printf( "FAIL (%08x)\n", v2 );
    } else {
        printf( "ok\n" );
    }
}

static void
read2( int  o, unsigned val )
{
    unsigned short v = htons(val);
    unsigned short v2;

    tab[o+0] = (char)(v >> 8);
    tab[o+1] = (char)(v);

    printf( "read2: offset=%d value=%08x: ", o, val );
    fflush(stdout);

    v2 = *(unsigned short*)(tab+o);

    if (v2 != val) {
        printf( "FAIL (%04x)\n", v2 );
    } else {
        printf( "ok\n" );
    }
}

static void
writ2( int  o, unsigned val )
{
    unsigned short v = htons(val);
    unsigned short v2;

    printf( "writ2: offset=%d value=%08x: ", o, val );
    fflush(stdout);

    *(unsigned short*)(tab+o) = v;

    v2 = ((unsigned)tab[o+0] << 8) |
         ((unsigned)tab[o+1]       );

    if (v2 != val) {
        printf( "FAIL (%08x)\n", v2 );
    } else {
        printf( "ok\n" );
    }
}



int  main(void)
{
    read4( 0, 0x12345678 );
    writ4( 0, 0x12345678 );
    read4( 1, 0x12345678 );
    writ4( 1, 0x12345678 );
    read4( 2, 0x12345678 );
    writ4( 2, 0x12345678 );
    read4( 3, 0x12345678 );
    writ4( 3, 0x12345678 );

    read2( 0, 0x1234 );
    writ2( 0, 0x1234 );
    read2( 1, 0x1234 );
    writ2( 1, 0x1234 );
    read2( 2, 0x1234 );
    writ2( 2, 0x1234 );
    read2( 3, 0x1234 );
    writ2( 3, 0x1234 );

    return 0;
}
