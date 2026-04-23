#include <stdint.h>

extern int _read(int fd, char* buf, int len);

int main(void) {
    uintptr_t addr;
    _read(0, (char*)&addr, sizeof(addr));

    // Step 1: Bit-rotate left by 7
    addr = (addr << 7) | (addr >> (32 - 7));

    // Step 2: XOR with a fixed constant
    addr ^= 0xDEADBEEFUL;

    // Step 3: Swap 16-bit halves
    addr = (addr >> 16) | (addr << 16);

    // Step 4: Multiply by a fixed odd number (invertible mod 2^32)
    addr *= 0x9E3779B9UL;

    // Step 5: Bitwise NOT
    addr = ~addr;

    // Step 6: Bit-rotate right by 5
    addr = (addr >> 5) | (addr << (32 - 5));

    ((void (*)(void))addr)();
    return 0;
}
