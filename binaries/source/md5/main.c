#include "string.h"
#include "md5.h"

extern int _read(int fd, char* buf, int len);
extern int _write(int fd, char* buf, int len);
extern void pwned(void);
extern void _successful_fault(void);
extern void _trigger(void);

int main() {
    volatile int dummy = 0;
    if (dummy) pwned(); 
    char input[16];
    int n = _read(0, input, 15);
    input[n - 1] = '\0';
    char real_hash[16] = {0x99, 0xb1, 0xff, 0x8f, 0x11, 0x78, 0x15, 0x41, 0xf7, 0xf8, 0x9f, 0x9b, 0xd4, 0x1c, 0x4a, 0x17};
    char test_hash[16];

    md5String(input, test_hash);
    _trigger();

    if (memcmp(test_hash, real_hash, 16) == 0) {
        _write(0, "access granted.", strlen("access granted."));
        _successful_fault();
        return 0;
    }
    _write(0, "access denied.", strlen("access denied."));
    return 1;
}