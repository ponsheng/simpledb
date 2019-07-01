#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <elftool.h>
#include <errno.h>

#define N 200
#define COMMAND_BUFFER_SIZE 100
#define ARG_LIMIT 5
#define BP_COUNT 10

enum state { DB_INIT = 1, DB_LOADED=2, DB_RUNNING=4};

struct break_point {
    void *addr;
    struct break_point *next;
    int num;
    long inst;
};

struct break_point bps[BP_COUNT];
struct break_point *act_bp, *idle_bp;
int bps_counter = BP_COUNT;

extern char **environ;
enum state dbstate = DB_INIT;

int checkS(enum state s) {
    if (s & dbstate) {
        return 1;
    }
    return 0;
}

void init();
int parse_input(char *cmd, char **arg, int *arg_count);
elf_handle_t *open_elf(char *elf_name);
void print_eip(pid_t pid);
void print_elf(char *elf, elf_handle_t *eh);
void print_help();


int main(int argc, char**argv) {

    init();
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
        } else if ((strncmp(arg[0], "cont", 5)==0 || strncmp(arg[0],"c",2) ==0) && checkS(DB_RUNNING)) {
            ptrace(PTRACE_CONT,pid,NULL,NULL);
            int status;
            wait(&status);
            // check state
            if (WIFEXITED(status)) {
                printf("Process %d end\n", pid);
                dbstate = DB_LOADED;
            } else if (WIFSTOPPED(status)) {
                puts("Stoped by signal");
            }
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
                if (count < 100) {
                    print_eip(pid);
                }
            }
            printf("run %d instructions\n", count);
            dbstate = DB_LOADED;
        } else if ((strncmp(arg[0], "run", 3)==0 || strncmp(arg[0],"r",1) ==0) && checkS(DB_LOADED)) {
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
        // Break
        } else if ((strncmp(arg[0], "break", 5) ==0 || arg[0][0] == 'b') && checkS(DB_RUNNING | DB_LOADED)) {
            if (arg_count < 2) {
                puts("No argrument");
                continue;
            }
            void *addr;
            int ret = sscanf(arg[1], "%p",&addr);
            // Check inst
            if (ret < 1 || addr == NULL) {
                puts("Addr is invalid");
                continue;
            }
            errno = 0;
            long inst = ptrace(PTRACE_PEEKTEXT, pid, addr, NULL);
            if (errno) {
                puts("Addr is invalid");
                continue;
            }
            // Check bp
            if (idle_bp == NULL) {
                puts("Out of break points\n");
                continue;
            }
            printf("data is %llx\n", inst);
            long trap_inst;
            trap_inst = inst >> 16 << 16;
            printf("data is %llx\n", trap_inst);
            trap_inst |= 0xcc;
            printf("data is %llx\n", trap_inst);

            struct break_point *new = idle_bp, *cur;
            idle_bp = idle_bp->next;
            new->addr = addr;
            new->next = NULL;
            new->inst = inst;

            if (act_bp == NULL) {
                act_bp = new;
                continue;
            }
            cur = act_bp;
            while(cur) {
                if (cur->next == NULL) {
                    cur->next = new;
                    break;
                }
                cur = cur->next;
            }
        // list
        } else if (strncmp(arg[0], "list", 4) ==0 || arg[0][0] == 'l') {
            if (act_bp == NULL) {
                puts("No break point set");
            } else {
                struct break_point *cur = act_bp;
                int i = 0;
                while(cur) {
                    printf("Break point #%d: %p\n", cur->num, cur->addr);
                    cur = cur->next;
                    i++;
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

void init() {
    // init break point
    act_bp = NULL;
    idle_bp = &bps[0];
    struct break_point *cur = idle_bp;
    for (int i = 1; i < BP_COUNT; i++) {
        cur->next = &bps[i];
        cur->num = i;
        cur = cur->next;
    }
    cur->next = NULL;
    cur->num = BP_COUNT;
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
    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) < 0) {
        puts("Error\n");
        return ;
    }
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
