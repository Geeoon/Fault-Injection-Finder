#include "string.h"
#define PASSWORD "password123"

extern void init_device(void);
extern int _write(int fd, char* buf, int len);
extern int _read(int fd, char* buf, int len);

int main() {
    init_device();
    char input[100];
    do {
        _write(0, "enter a password:", strlen("enter a password:"));
        int n = _read(0, input, strlen(PASSWORD) + 1);
        input[n - 1] = '\0';
    } while(strncmp(input, PASSWORD, strlen(PASSWORD)) != 0);
    _write(0, "access granted.", strlen("access granted."));
    return 0;
}
