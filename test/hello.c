#include <stdio.h>
#include <inttypes.h>

int f(int i) {
    printf("hello get %d\n", i);
    return i;
}

int main() {
    f(222);
    uint64_t rip;
   asm volatile("1: lea 1b(%%rip), %0;": "=a"(rip));
    printf("%" PRIx64 "; %" PRIu64 " bytes from main start\n",
           rip, rip - (uint64_t)main);
    return 0;
}
