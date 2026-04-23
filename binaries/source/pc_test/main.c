#include <stdint.h>

extern int _read(int fd, char* buf, int len);
extern void pwned(void);

int main(void) {
    uintptr_t addr;
    _read(0, (char*)&addr, sizeof(addr));
    // flip all bits to test how the solver works
    addr = ~addr;
    ((void (*)(void))addr)();
    volatile int dummy = 0;
    if (dummy) pwned(); 
    return 0;
}
