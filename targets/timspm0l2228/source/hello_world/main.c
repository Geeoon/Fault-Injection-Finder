#include "string.h"

extern int _write(int fd, char* buf, int len);
extern void init_device(void);

int main(void) {
    init_device();
    while (1) {
        _write(0, "hello world!\n", strlen("hello world!\n"));
    }
}
