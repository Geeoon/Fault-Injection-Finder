#include "string.h"

extern int _read(int fd, char* buf, int len);
extern int _write(int fd, char* buf, int len);

int main() {
    char input;
    // prevents gcc from optimizing away everything after the loop
    volatile int dummy = 1;
    while (dummy) {
        _read(0, &input, 1);
        _write(0, &input, 1);
    }
    return 0;
}
