#include "string.h"
#define PASSWORD "password123"
#define PWD_LEN 11

extern void init_device(void);
extern int _write(int fd, char* buf, int len);
extern int _read(int fd, char* buf, int len);
extern void pwned(void);
extern void led_blip(void);

int main() {
    init_device();
    volatile int lol = 0;
    if (lol) pwned();
    char input[PWD_LEN];
    volatile int out;
    do {
        _write(0, "\nenter a password:", strlen("\nenter a password:"));
        int n = _read(0, input, PWD_LEN);
        out = strncmp(input, PASSWORD, PWD_LEN);
        led_blip();
    } while(out != 0);
    _write(0, "\naccess granted.\n", strlen("access granted.\n"));
    while (1) {}
}
