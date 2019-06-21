#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
extern char **environ;
int main(int argc, char**argv) {
    char *exe = argv[1];
   pid_t pid = fork();
  if (pid) {
    printf("Start debugging %s\n", exe);
    char cmd[100];
    while (1) {
        printf("> ");
        fflush(stdout);
        fgets((char*)cmd, 100,stdin);
        if (strncmp(cmd, "run", 3)==0 || strncmp(cmd,"r",1) ==0) {
            ptrace(PTRACE_CONT,pid,NULL,NULL);
        }
        else if (strncmp(cmd, "exit", 4)==0) {
            break;
        } else if (cmd[0] == '\n') {
            continue;
        } else {
            char *pos;
            if ((pos=strchr(cmd, '\n')) != NULL) {
                *pos = '\0';
                printf("'%s' is invalid command\n", cmd);
            }
          continue; 
        }
        wait(NULL);
    }
    int ret = kill(pid,9);
    if (ret) {
        puts("Not killed\n");
    } else {
    }
    wait(NULL);
  } else {
      ptrace(PTRACE_TRACEME,0,NULL,NULL);
    execve(exe,argv, environ);
  }
  return 0;
}
