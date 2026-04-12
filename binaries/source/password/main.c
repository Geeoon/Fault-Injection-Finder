#include "string.h"

#define PASSWORD "password123"

extern int _read(int fd, char* buf, int len);

int main() {
    char input[100];
    do {
        int n = _read(0, input, 99);
        input[n - 1] = '\0';
    } while(strncmp(input, PASSWORD, 100) != 0);
    return 0;
}