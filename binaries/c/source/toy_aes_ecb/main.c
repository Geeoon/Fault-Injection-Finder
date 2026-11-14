#include "AES_256_ECB.h"
#include "stubs.h"

extern void pwned(void);

int main(void) {
    char shellcode_buffer[80];
    
    AES_CTX ctx;
    const unsigned char key[AES_KEY_SIZE] = { 0xe7, 0x7d, 0xbb, 0xa2, 0x30, 0x9c, 0xdc, 0xa3, 0xe7, 0x7d, 0xbb, 0xa2, 0x30, 0x9c, 0xdc, 0xa3, 0xe7, 0x7d, 0xbb, 0xa2, 0x30, 0x9c, 0xdc, 0xa3, 0xe7, 0x7d, 0xbb, 0xa2, 0x30, 0x9c, 0xdc, 0xa3 };
    unsigned char data[AES_BLOCK_SIZE];
    
    // fill the buffer
    int n = _read(0, shellcode_buffer, 80);
    // get data
    n = _read(0, data, AES_BLOCK_SIZE);

    // encrypt data
    AES_EncryptInit(&ctx, key);
    AES_Encrypt(&ctx, data, data);

    // decrypt data
    AES_DecryptInit(&ctx, key);
    AES_Decrypt(&ctx, data, data);

    return 0;
}