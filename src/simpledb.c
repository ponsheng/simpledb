#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <elftool.h>

extern char **environ;
enum state {
    DB_INIT = 1, DB_LOADED=2, DB_RUNNING=4};

enum state dbstate = DB_INIT;

void print_elf(char *elf, elf_handle_t *eh) {
    elf_strtab_t *tab = NULL;
    if (!eh) {
        puts("Failed");
        return;
    }
    elf_load_all(eh);
    for (tab = eh->strtab; tab != NULL; tab = tab->next) {
        if (tab->id == eh->shstrndx) break;
    }
    int i;
    for (i = 0; i < eh->shnum; i++) {
        if (strncmp(&tab->data[eh->shdr[i].name], ".text", 5) == 0) {
            break;
        }
    }
    elf_shdr_t text_section = eh->shdr[i];
    printf("program '%s' loaded. Entry point 0x%lx. [TEXT] vaddr:0x%llx, offset:0x%llx, size:0x%llx\n", elf, eh->entrypoint, text_section.addr,  text_section.offset, text_section.size);
    elf_close(eh);
}

int checkS(enum state s) {
    if (s & dbstate) {
        return 1;
    }
    return 0;
}

int parse_input(char *cmd, char **arg, int *arg_count);
elf_handle_t *open_elf(char *elf_name);
void print_eip(pid_t pid);

#define N 200
#define COMMAND_BUFFER_SIZE 100
#define ARG_LIMIT 5

int main(int argc, char**argv) {

    char *elf_name;
    char cmd[COMMAND_BUFFER_SIZE];
    char *arg[ARG_LIMIT];
    int arg_count;
    char buf[N];
    elf_handle_t *eh = NULL;
    pid_t pid, ppid;

    elf_init();
    ppid = getpid();

    if (argc > 1) {
        eh = open_elf(elf_name = argv[1]);
    }
    while (1) {
        switch (dbstate) {
            case DB_INIT:
                printf("[INIT]");
                break;
            case DB_LOADED:
                printf("[LOADED]");
                break;
            case DB_RUNNING:
                printf("[RUNNING]");
                print_eip(pid);
                break;
        }
        printf("> ");
        fflush(stdout);
        if (! fgets(cmd, COMMAND_BUFFER_SIZE, stdin)) {
            goto EXIT;
        }
        int ret = parse_input(cmd, arg, &arg_count);
        if (ret) {
            continue;
        }
        // Switch cmd
        if (strncmp(arg[0], "load", 4)==0) {
            if (dbstate == DB_INIT) {
                eh = open_elf(elf_name = arg[1]);
                continue;
            }
            goto INVALID;
        } else if (strncmp(arg[0], "run", 3)==0 || strncmp(arg[0],"r",1) ==0) {
            ptrace(PTRACE_CONT,pid,NULL,NULL);
            wait(NULL);
        } else if (strncmp(arg[0], "counti", 6) ==0) {
            int count = 0;
            int status;
            while (1) {
                if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) < 0) {
                    puts("error");
                    break;
                }
                count++;

                wait(&status);
                if (WIFEXITED(status)) {
                    break;
                }
            }
            printf("run %d instructions\n", count);
        } else if (strncmp(arg[0], "start", 5) ==0 && checkS(DB_LOADED)) {
            pid = fork();
            if (pid) {
                dbstate = DB_RUNNING;
                wait(NULL);
            } else {
                ptrace(PTRACE_TRACEME,0,NULL,NULL);
                execve(elf_name,argv, environ);
            }
        } else if (strncmp(arg[0], "vmmap", 5) ==0 || arg[0][0] == 'm') {
            if (dbstate == DB_LOADED) {

            } else if (dbstate == DB_RUNNING) {
                char file_name[100];
                sprintf(file_name, "/proc/%d/maps", pid);
                FILE *f = fopen(file_name, "r");
                if (!f) {
                    printf("Open file %s failed\n", file_name);
                    continue;
                }
                fgets(buf, N,f);
                while(fgets(buf, N, f) != NULL) {
                    printf("%s", buf);
                }
                fclose(f);
            }
        } else if (strncmp(arg[0], "si", 2)==0 && checkS(DB_RUNNING)) {
            if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) < 0) {
                puts("error");
                break;
            }
            wait(NULL);
        } else if (strncmp(arg[0], "exit", 4)==0) {
EXIT:
            if (dbstate == DB_RUNNING) {
                if (kill(pid,9)) {
                    puts("Kill failed");
                } else {
                    puts("Kill successfully");
                }
            } else {
                puts("");
            }
            break;
        } else {
INVALID:
        printf("'%s' is a invalid command\n", arg[0]);
        }
    }
    return 0;
}



int parse_input(char *cmd, char **arg, int *arg_count) {
    // delete new line
    char *pos;
    if ((pos=strchr(cmd, '\n')) != NULL) {
        *pos = '\0';
    }
    arg[0] = strtok(cmd, " ");
    if (arg[0] == NULL) {
        return -1;
    }
    (*arg_count) = 1;
    for (int i = 1; i < ARG_LIMIT; i++, (*arg_count)++) {
        arg[i] = strtok(NULL, " ");
        if (arg[i] == NULL) {
            break;
        }
    }
    return 0;
}

elf_handle_t * open_elf(char *elf) {
    elf_handle_t *eh = elf_open(elf);
    if (eh == NULL) {
        printf("Unable to load elf: %s\n", elf);
    } else {
        print_elf(elf, eh);
        dbstate = DB_LOADED;
    }
    return eh;
}
void print_eip(pid_t pid) {
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    printf(" @0x%llx", regs.rip);
}
