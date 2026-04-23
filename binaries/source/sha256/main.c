#include "string.h"
#include "sha256.h"

extern int _read(int fd, char* buf, int len);
extern int _write(int fd, char* buf, int len);
extern void pwned(void);
extern void _successful_fault(void);

int main() {
    char input[16];
    int n = _read(0, input, 15);
    input[n - 1] = '\0';
    char real_hash[32] = {0x2c, 0xf2, 0x4d, 0xba, 0x5f, 0xb0, 0xa3, 0x0e, 0x26, 0xe8, 0x3b, 0x2a, 0xc5, 0xb9, 0xe2, 0x9e, 0x1b, 0x16, 0x1e, 0x5c, 0x1f, 0xa7, 0x42, 0x5e, 0x73, 0x04, 0x33, 0x62, 0x93, 0x8b, 0x98, 0x24};
    char test_hash[32];

    sha256_easy_hash(input, strlen(input), test_hash);

    if (memcmp(test_hash, real_hash, 32) == 0) {
        _write(0, "access granted.", strlen("access granted."));
        _successful_fault();
        return 0;
    }
    _write(0, "access denied.", strlen("access denied."));
    volatile int dummy = 0;
    if (dummy) pwned(); 
    return 1;
}