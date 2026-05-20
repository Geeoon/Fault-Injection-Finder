#include "string.h"
#include "stubs.h"

int main() {
    // prevents gcc from optimizing away the stuff aster the loop
    volatile int dummy = 1;
    while (dummy) {}
    _write(0, "escaped the loop", strlen("escaped the loop"));
    return 0;
}
