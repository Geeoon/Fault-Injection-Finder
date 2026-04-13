#include "string.h"

extern int _write(int fd, char* buf, int len);

int main() {
    _write(0, "hello world!\n", strlen("hello world!\n"));
    return 0;
}
