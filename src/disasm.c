#include <stdio.h>
#include <stdint.h>

#include <capstone/capstone.h>

csh handle;

void print_disasm(long *inst, size_t size, void *addr) {
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        return;
    }
    cs_insn *insn;
    int count = cs_disasm(handle, (const uint8_t *)inst, size*sizeof(long), (uint64_t)addr, 0, &insn);
    if (count > 0) {
        for (int i = 0; i < count; i++) {
            printf("%p\t%s\t%s\n", insn[i].address, insn[i].mnemonic, insn[i].op_str);
        }
        cs_free(insn, count);
    } else {
        puts("Failed to disasm");
    }
    cs_close(&handle);
}
