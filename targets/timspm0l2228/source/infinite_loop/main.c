#include "string.h"

extern void init_device(void);
extern int _read(int fd, char* buf, int len);
extern int _write(int fd, char* buf, int len);
extern void pwned(void);
extern void led_blip(void);

int main() {
    // prevents gcc from optimizing away the stuff aster the loop
    init_device();
    char temp;
    volatile int lol = 0;
    if (lol) pwned();
    
    volatile int dummy = 1;
    while (dummy) {
        _read(0, &temp, 1);  // wait for input
        led_blip();
    }
    _write(0, "escaped the loop", strlen("escaped the loop"));
    return 0;
}
