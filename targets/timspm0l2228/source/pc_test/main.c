#include <stdint.h>

extern void pwned(void);
extern void init_device(void);
extern int _read(int fd, char* buf, int len);

int main(void) {
    init_device();
    volatile int dummy = 0;
    if (dummy) pwned(); 
    uintptr_t addr;
    _read(0, (char*)&addr, sizeof(addr));
    // flip all bits to test how the solver works
    addr = ~addr;
    ((void (*)(void))addr)();
    return 0;
}
