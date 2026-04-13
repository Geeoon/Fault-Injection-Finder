#include "string.h"

extern int _read(int fd, char* buf, int len);
extern int _write(int fd, char* buf, int len);

int main() {
    char input;
    while (1) {
        _read(0, &input, 1);
        _write(0, &input, 1);
    }
    return 0;
}
