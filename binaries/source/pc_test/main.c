#include <stdint.h>
#include "stubs.h"

extern void pwned(void);

int main(void) {
    volatile int dummy = 0;
    if (dummy) pwned(); 
    uintptr_t addr;
    _read(0, (char*)&addr, sizeof(addr));
    // flip all bits to test how the solver works
    addr = ~addr;
    ((void (*)(void))addr)();
    return 0;
}
