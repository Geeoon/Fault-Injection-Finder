#include "chacha20.h"
#include "stubs.h"

extern void pwned(void);

int main(void) {
    volatile int dummy = 0;
    if (dummy) pwned(); 
    
    unsigned char key[32] = { 0x0d, 0xc8, 0xb6, 0x98, 0xfa, 0x73, 0x44, 0xb4, 0x62, 0x3e, 0xcb, 0xd1, 0x43, 0xbc, 0x6f, 0xb3, 0x0b, 0x9a, 0xc1, 0x90, 0x37, 0x57, 0x30, 0xf7, 0x15, 0xa9, 0xff, 0xfd, 0x01, 0xd5, 0x50, 0xb9 };
    unsigned char nonce[12] = {0};
    unsigned char data[192];  // stream cipher, length can be anything
    
    // get data
    int n = _read(0, data, 192);

    // init context for encryption
    struct chacha20_context ctx;
    chacha20_init_context(&ctx, key, nonce, 1);

    // encrypt data
    chacha20_xor(&ctx, data, 192);

    // init context for decryption
    chacha20_init_context(&ctx, key, nonce, 1);

    // decrypt data
    chacha20_xor(&ctx, data, 192);

    return 0;
}