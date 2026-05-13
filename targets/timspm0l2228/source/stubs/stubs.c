#include <errno.h>

void _exit(int status) {
    while(1);  // no exit on the real device
}

int _read(int fd, char *buf, int len) {
    // TODO: read from UART0
    return len;
}

int _write(int fd, char *buf, int len) {
    // TODO: write to UART0
    return len;
}

void _fini(void) {}
void _init(void) {}
