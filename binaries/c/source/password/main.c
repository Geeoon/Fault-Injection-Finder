#include "string.h"
#include "stubs.h"
#define PASSWORD "password123"

int main() {
    char input[100];
    do {
        int n = _read(0, input, 99);
        input[n - 1] = '\0';
    } while(strncmp(input, PASSWORD, 100) != 0);
    _write(0, "access granted.", strlen("access granted."));
    return 0;
}