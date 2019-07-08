#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>

#include "elftool.h"
#include "simpledb.h"

#define N 200
#define COMMAND_BUFFER_SIZE 100
#define ARG_LIMIT 5
#define BP_COUNT 10

#define DEBUG

#ifdef DEBUG
#define DP(...) printf("[DEBUG] "__VA_ARGS__);
#else
#define DP(...)
#endif

enum state { DB_INIT = 1, DB_LOADED=2, DB_RUNNING=4};

struct break_point {
    void *addr;
    struct break_point *next;
    int num;
    long inst;
};

struct break_point bps[BP_COUNT];
struct break_point *act_bp, *idle_bp, *todo_bp;
int bps_counter = BP_COUNT;
pid_t pid, ppid;

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
void print_rip();
void *get_rip();
void print_elf(char *elf, elf_handle_t *eh);
int wait_process(int single_step, struct break_point **hitBP);
void print_help();
int setBP(struct break_point*, void*addr);
int unsetBP(struct break_point *bp);
struct break_point *lookupBP(void *addr);


int main(int argc, char**argv) {

    init();
    char *elf_name;
    char cmd[COMMAND_BUFFER_SIZE];
    char *arg[ARG_LIMIT];
    int arg_count;
    char buf[N];
    elf_handle_t *eh = NULL;

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
                print_rip();
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
        if (strncmp(arg[0], "load", 5)==0) {
            if (dbstate != DB_INIT) {
                goto INVALID;
            }
            eh = open_elf(elf_name = arg[1]);
            dbstate = DB_LOADED;
        // cont
        } else if (strncmp(arg[0], "cont", 5)==0 || strncmp(arg[0],"c",2) ==0) {
            if (!checkS(DB_RUNNING)) {
                goto INVALID;
            }
            // Check todo list
            if (todo_bp) {
                DP("There is todo bp\n");
                // single
                if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL)) {
                    puts("Error PTRACE_SINGLESTEP");
                    break;
                }
                // Next instr touch break point
                struct break_point *hitBP = NULL;
                wait_process(1, &hitBP);

                if (hitBP) {
                    continue;
                }
            }
            DP("Continue\n");

            if (ptrace(PTRACE_CONT,pid,NULL,NULL)) {
                printf("Error PTRACE_CONT %s\n", __LINE__);
                continue;
            }
            wait_process(0, NULL);

        // TO BE REMOVE
        } else if (strncmp(arg[0], "counti", 7) ==0) {
            if (!checkS(DB_RUNNING)) {
                goto INVALID;
            }
            int count = 0;
            int status;
            while (1) {
                if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL)) {
                    puts("Error PTRACE_SINGLESTEP");
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
        } else if (strncmp(arg[0], "run", 4)==0 || strncmp(arg[0],"r",2) ==0) {
            if (!checkS(DB_LOADED)) {
                goto INVALID;
            }
            pid = fork();
            if (pid) {
                dbstate = DB_RUNNING;
                wait(NULL);
                printf("%s started as pid %d\n", elf_name, pid);
            } else {
                ptrace(PTRACE_TRACEME,0,NULL,NULL);
                execve(elf_name,argv, environ);
            }
        } else if (strncmp(arg[0], "vmmap", 6) ==0 || strncmp(arg[0],"m",2) ==0) {
            if (dbstate == DB_RUNNING) {
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
            } else {
                goto INVALID;
            }
        // Break
        } else if (strncmp(arg[0], "break", 6) ==0 || strncmp(arg[0],"b",2) ==0) {
            if (checkS(DB_INIT | DB_LOADED)) {
                goto INVALID;
            }
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
            // Check bp
            if (idle_bp == NULL) {
                puts("Out of break points");
                continue;
            }
            // check if addr overlap
            struct break_point *cur = act_bp;
            while (cur) {
                if (cur->addr == addr) {
                    break;
                }
                cur = cur->next;
            }
            if (cur) {
                printf("Addr %p have register as break point #%d\n", addr, cur->num);
                continue;
            }

            struct break_point *new = idle_bp;
            if (setBP(new, addr)) {
                printf("Failed to set Break Point\n");
                continue;
            }
            idle_bp = idle_bp->next;
            new->next = NULL;
            printf("Set break point #%d: %p\n", new->num, new->addr);

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

            // check if addr eq rip
            if (addr == get_rip()) {
                unsetBP(new);
                if (todo_bp) {
                    DP("todo list is not empty");
                }
                todo_bp = new;
            }
        // list
        } else if (strncmp(arg[0], "list", 5) ==0 || strncmp(arg[0],"l",2) ==0) {
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
        // delete
        } else if (strncmp(arg[0], "delete", 7) ==0) {
            int id;
            if (sscanf(arg[1], "%d",&id) < 1) {
                puts("Invalid break point id\n");
                continue;
            }
            struct break_point *cur = act_bp, *last = NULL, *tmp;
            while (cur) {
                if (cur->num == id) {
                    break;
                }
                last = cur;
                cur = cur->next;
            }
            if (!cur) {
                puts("Invalid break point id");
                continue;
            }
            if (todo_bp == cur) {
                todo_bp = NULL;
            }
            unsetBP(cur);
            printf("Delete break point #%d\n", cur->num);
            if (last) {
                last->next = cur->next;
            } else {
                act_bp = cur->next;
            }
            cur->num = ++bps_counter;
            cur->next = NULL;
            if (idle_bp) {
                tmp = idle_bp;
                while (tmp->next) {
                    tmp = tmp->next;
                }
                tmp->next = cur;
            } else {
                idle_bp = cur;
            }

        } else if (strncmp(arg[0], "disasm", 7) ==0 || strncmp(arg[0],"d",2) ==0) {
            if (!checkS(DB_RUNNING)) {
                goto INVALID;
            }
            void *addr = get_rip();
            int size = 10;
            long insts[size];
            int i;

            for (i = 0; i < size; i++) {
                    errno = 0;
                    long inst = ptrace(PTRACE_PEEKTEXT, pid, addr+sizeof(long)*i, NULL);
                    if (errno) {
                        puts("Error Addr is invalid");
                        break;
                    }
                    insts[i] = inst;
            }
            if (i != size) {
                puts("Error PTRACE_PEEKTEXT");
                continue;
            }
            print_disasm(insts, size, addr);
        } else if (strncmp(arg[0], "help", 5) ==0 || strncmp(arg[0],"h",2) ==0) {
			print_help();

        } else if (strncmp(arg[0], "si", 3)==0 && checkS(DB_RUNNING)) {
            if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL)) {
                puts("Error PTRACE_SINGLESTEP");
                break;
            }
            struct break_point *hitBP = NULL;
            wait_process(1, &hitBP);

            // Check todo list
        } else if (strncmp(arg[0], "exit", 5)==0) {
EXIT:
            if (dbstate == DB_RUNNING) {
                if (kill(pid,9)) {
                    puts("Kill failed");
                } else {
                    puts("Kill successfully");
                }
            }
            puts("Exit");
            return 0;
        } else {
INVALID:
        printf("'%s' is a invalid command\n", arg[0]);
        }
    }
    puts("Exit");
    return 0;
}

void init() {
    // init break point
    act_bp = NULL;
    todo_bp = NULL;
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
void print_rip() {
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) < 0) {
        puts("Error PTRACE_GETREGS\n");
        return ;
    }
    printf(" @0x%llx", regs.rip);
}
void *get_rip() {
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) < 0) {
        puts("Error PTRACE_GETREGS\n");
        return 0;
    }
    return (void*)regs.rip;
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
    run (r) : run the program\n\
\n\
<Running>\n\
    dump (x) addr [length]: dump memory content\n\
    cont (c): continue execution\n\
    getregs: show registers\n\
    set (s) reg val: get a single value to a register\n\
    si: step into instruction\n\
    break (b) {instruction-address}: add a break point\n\
    vmmap (m) : show memory layout\n\
\n\
<Loaded or Running>\n\
    disasm (d) addr: disassemble instructions in a file or a memory region\n\
\n\
<Any>\n\
    help (h) : show this message\n\
    list (l) : list break points\n\
    delete {break-point-id}: remove a break point\n\
    exit (q) : terminate the debugger\n\
";
	puts(help_meg);
}

int wait_process(int single_mode, struct break_point **hitBP) {
    int status;
    wait(&status);
    // check state

    if (WIFEXITED(status)) {
        printf("Process %d end\n", pid);
        dbstate = DB_LOADED;
        return 0;
    } else if (WIFSTOPPED(status) && single_mode) {
        if (!hitBP) {
            DP("Error %s\n", __LINE__);
        }
        void *addr = get_rip();
        if (todo_bp) {
            setBP(todo_bp, NULL);
            todo_bp = NULL;
        }
        // check next instr if is break
        errno = 0;
        long inst = ptrace(PTRACE_PEEKTEXT, pid, addr, NULL);
        if (errno) {
            puts("Addr is invalid");
            return 1;
        }
        if ((0xff & inst) == 0xcc) {
            DP("Next inst is bp\n");
            struct break_point *bp;
            if (bp = lookupBP(addr)) {
                unsetBP(bp);
                if (todo_bp) {
                    DP("todo list is not empty");
                }
                todo_bp = bp;
                *hitBP = bp;
                printf("Break Point #%d hit\n", (*hitBP)->num);
            }
        }
    } else if (WIFSTOPPED(status)) {
        // Stopped by break point
        struct break_point *cur;
        void *addr = get_rip()-1;
        if (!(cur = lookupBP(addr))) {
            puts("SIGTRAP?");
            return 1;
        }
        printf("Break Point #%d hit\n", cur->num);
        // restore inst
        if (unsetBP(cur)) {
            return 1;
        }
        // put into todolist
        if (todo_bp) {
            puts("todo_bp is not empty");
            return 1;
        }
        todo_bp = cur;
        // restore rip
        struct user_regs_struct regs;
        if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) < 0) {
            puts("Error getregs");
            return 1;
        }
        regs.rip = (long long) addr;
        if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) < 0) {
            puts("Error setregs");
            return 1;
        }
    } else {
        puts("Unknown wait result");
    }
    return 0;
}

int setBP(struct break_point *bp, void *addr) {
    long inst, trap_inst;

    errno = 0;
    if (addr) {
        bp->addr = addr;
    }
    DP("Set break_point #%d : %p\n", bp->num, bp->addr);

    inst = ptrace(PTRACE_PEEKTEXT, pid, bp->addr, NULL);
    if (errno) {
        puts("Error Addr is invalid");
        return 1;
    }

    if (addr) {
        bp->inst = inst & 0xff;
    }
    trap_inst = inst >> 8 << 8;
    trap_inst |= 0xcc;
    if (ptrace(PTRACE_POKETEXT, pid, bp->addr, trap_inst)) {
        puts("error");
        return 1;
    }
    return 0;
}

int unsetBP(struct break_point *bp) {
    DP("Unset break_point #%d : %p\n", bp->num, bp->addr);
    errno = 0;
    long inst = ptrace(PTRACE_PEEKTEXT, pid, bp->addr, NULL);
    if (errno) {
        puts("Error Addr is invalid");
        return 1;
    }

    inst = inst >> 8 << 8;
    inst |= bp->inst;

    if (ptrace(PTRACE_POKETEXT, pid, bp->addr, inst)) {
        puts("Error POKETEXT");
        return 1;
    }
    return 0;
}

struct break_point *lookupBP(void *addr) {
    struct break_point *cur = act_bp;
    while (cur) {
        if (cur->addr == addr) {
            break;
        }
        cur = cur->next;
    }
    return cur;
}
