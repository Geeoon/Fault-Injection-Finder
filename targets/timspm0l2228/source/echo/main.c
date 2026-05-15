#include "string.h"

extern int _read(int fd, char* buf, int len);
extern int _write(int fd, char* buf, int len);
extern void init_device(void);

int main(void) {
    init_device();
    char buf[100] = {0};
    while (1) {
        _read(0, buf, 10);
        _write(0, buf, 10);
    }
}
