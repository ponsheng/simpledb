#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <elftool.h>

enum state { DB_INIT = 1, DB_LOADED=2, DB_RUNNING=4};

struct break_point {
    void *addr;
    int used;
};

struct break_point bps[10];
int bpcount=0;

extern char **environ;
enum state dbstate = DB_INIT;

int checkS(enum state s) {
    if (s & dbstate) {
        return 1;
    }
    return 0;
} 

int parse_input(char *cmd, char **arg, int *arg_count);
elf_handle_t *open_elf(char *elf_name);
void print_eip(pid_t pid);
void print_elf(char *elf, elf_handle_t *eh);
void print_help();

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
        char *eof = fgets(cmd, COMMAND_BUFFER_SIZE, stdin);
        if (!eof) {
            goto EXIT;
        }
        int ret = parse_input(cmd, arg, &arg_count);
        if (ret) {
            continue;
        }
       
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
            dbstate = DB_LOADED;
        } else if (strncmp(arg[0], "start", 5) ==0 && checkS(DB_LOADED)) {
            pid = fork();
            if (pid) {
                dbstate = DB_RUNNING;
                wait(NULL);
                printf("%s started as pid %d\n", elf_name, pid);
            } else {
                ptrace(PTRACE_TRACEME,0,NULL,NULL);
                execve(elf_name,argv, environ);
            }
        } else if (strncmp(arg[0], "vmmap", 5) ==0 || arg[0][0] == 'm') {
            if (dbstate == DB_LOADED) {
                // TODO
            } else if (dbstate == DB_RUNNING) {
                char file_name[100];
                sprintf(file_name, "/proc/%d/maps", pid);
                FILE *f = fopen(file_name, "r");
                if (!f) {
                    printf("Open file %s failed\n", file_name);
                    continue;
                }
                while(fgets(buf, N, f) != NULL) {
                    printf("%s", buf);
                }
                fclose(f);
            }

        } else if ((strncmp(arg[0], "break", 5) ==0 || arg[0][0] == 'b') && checkS(DB_RUNNING | DB_LOADED)) {
            if (arg_count < 2) {
                puts("No argrument");
                continue;
            }
            void *addr;
            int ret = sscanf(arg[1], "0x%p",&addr);
            if (ret < 1) {
                puts("Addr should be 0x_____");
                continue;
            }
            for (int i = 0; i < bpcount+1; i++) {
                if (bps[i].used == 0) {
                    bps[i].used = 1;
                    bps[i].addr = addr;
                    bpcount++;
                    break;
                }
            }

        } else if (strncmp(arg[0], "list", 4) ==0 || arg[0][0] == 'l') {
            if (bpcount==0) {
                puts("No break point set");
            } else {
                int cur = 0;
                for (int i = 0; i < bpcount; i++,cur++) {
                    if (bps[cur].used != 1) {
                        cur++;
                    }
                    printf("Break point #%d: 0x%p\n", cur, bps[cur].addr);
                }
            }
        } else if (strncmp(arg[0], "help", 4) ==0 || arg[0][0] == 'h') {
			print_help();

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

void print_help() {
char *help_meg = "\
[States]\n\
{Initial, Loaded, Running}\n\
\n\
[Commands]\n\
<Inital>\n\
    load {path/to/a/program}: load a elf\n\
\n\
<Loaded>\n\
    start: start the program and stop at the first instruction\n\
\n\
<Running>\n\
    dump (x) addr [length]: dump memory content\n\
    cont (c): continue execution\n\
    getregs: show registers\n\
    set (s) reg val: get a single value to a register\n\
    si: step into instruction\n\
\n\
<Loaded or Running>\n\
    disasm (d) addr: disassemble instructions in a file or a memory region\n\
    break (b) {instruction-address}: add a break point\n\
    run (r) : run the program\n\
    vmmap (m) : show memory layout\n\
\n\
<Any>\n\
    help (h) : show this message\n\
    list (l) : list break points\n\
    delete {break-point-id}: remove a break point\n\
    exit (q) : terminate the debugger\n\
";
	puts(help_meg);
}
