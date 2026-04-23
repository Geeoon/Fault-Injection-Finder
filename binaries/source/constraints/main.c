#include <stdint.h>

extern int _read(int fd, char* buf, int len);
extern int _write(int fd, char* buf, int len);
extern void pwned(void);

int main() {
    uint8_t input;
    _read(0, &input, 1);
    
    if (input > 0x10) {
        if (input > 0x20) {
            _write(0, "1", 1);
        } else {
            _write(0, "2", 1);
        }
    } else {
        _write(0, "3", 1);
    }
    volatile int dummy = 0;
    if (dummy) pwned(); 
    return 0;
}
