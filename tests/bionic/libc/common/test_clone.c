/* Check that clone() is implemented and properly works
 */
#define __GNU_SOURCE 1
#include <stdio.h>
#include <errno.h>
#include <sched.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <stdarg.h>
#include <string.h>

static int
clone_child (void *arg)
{
 errno = 0;
 ptrace (PTRACE_TRACEME, 0, 0, 0);
 if (errno != 0)
   perror ("ptrace");
 if (kill (getpid (), SIGSTOP) < 0)
   perror ("kill");
 return 0;
}

#define PAGE_SIZE 4096
#define STACK_SIZE (4 * PAGE_SIZE)

char clone_stack[STACK_SIZE] __attribute__ ((aligned (PAGE_SIZE)));

int
main ()
{
 int pid,child;
 int status;

 pid = clone (clone_child, clone_stack + 3 * PAGE_SIZE,
              CLONE_VM | SIGCHLD, NULL);
 if (pid < 0)
   {
     perror ("clone");
     exit (1);
   }
 printf ("child pid %d\n", pid);

 //sleep(20);
 child = waitpid (pid, &status, 0);
 printf("waitpid returned %d\n", child);
 if (child < 0) {
   perror ("waitpid");
   return 1;
 }
 printf ("child %d, status 0x%x\n", child, status);
 return 0;
}
