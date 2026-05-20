#include "string.h"
#include "stubs.h"

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
