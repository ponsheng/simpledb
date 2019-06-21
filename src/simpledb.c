#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <elftool.h>

extern char **environ;
enum state {
    DB_INIT, DB_LOADED, DB_RUNNING};
enum state dbstate = DB_INIT;
char *elf = NULL;
elf_shdr_t text_section;
void print_elf(elf_handle_t *eh) {
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
    text_section = eh->shdr[i];
    printf("program '%s' loaded. entry point 0x4000b0 0x%lx, vaddr 0x%llx 0x4000b0, offset 0x%llx 0xb0, size 0x%llx 0x23\n", elf, eh->entrypoint, text_section.addr,  text_section.offset, text_section.size);
    //elf_close(eh); 
}
#define N 200
int main(int argc, char**argv) {
    char *pos;
    int size = 0;
    elf_handle_t *eh = NULL;
    elf_init();
    pid_t pid, ppid;
    char cmd[100];
    char *tok = NULL;
    char buf[N];
    ppid = getpid();
    if (argc > 1) {
        elf = argv[1];
        eh = elf_open(elf);
        if (eh == NULL){
            puts("Unable to load elf");
        } else {
            print_elf(eh);
            dbstate = DB_LOADED;
        }
    }
    while (1) {
        printf("> ");
        fflush(stdout);
        fgets((char*)cmd, 100,stdin);
        if ((pos=strchr(cmd, '\n')) != NULL) {
            size = (int)(pos-cmd);
            *pos = '\0';
        }
        if (dbstate == DB_INIT) {
            if (strncmp(cmd, "load", 4)==0) {
                strtok(cmd, " ");
                tok = strtok(NULL, " ");
                elf = tok;
                eh = elf_open(elf);
                if (eh == NULL) {
                    printf("Unable to load elf: %s\n", elf);
                } else {
                    print_elf(eh);
                    dbstate = DB_LOADED;
                }
            } else {
                goto INVALID;
            }
            continue;
        }
        if (strncmp(cmd, "run", 3)==0 || strncmp(cmd,"r",1) ==0) {
            ptrace(PTRACE_CONT,pid,NULL,NULL);
            wait(NULL);
            continue;
        } else if (strncmp(cmd, "start", 5) ==0) {
            if (dbstate != DB_LOADED) {
                goto INVALID;
            }
            pid = fork();
            if (pid) {
                dbstate = DB_RUNNING;

            } else {
                ptrace(PTRACE_TRACEME,0,NULL,NULL);
                execve(elf,argv, environ);
            }
            continue;
        } else if (strncmp(cmd, "vmmap", 5) ==0 || cmd[0] == 'm') {
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
                continue;
            }
        } else if (strncmp(cmd, "exit", 4)==0) {
            break;
        } else {
        //    continue; 
        }
INVALID:
        tok = strtok(cmd, " ");
        if (tok != NULL) {
            printf("'%s' is invalid command\n", cmd);
        }
    }
/*        int ret = kill(pid,9);
        if (ret) {
            puts("Not killed\n");
        } else {
        }
        wait(NULL);
     } else {
     }*/
    return 0;
}
