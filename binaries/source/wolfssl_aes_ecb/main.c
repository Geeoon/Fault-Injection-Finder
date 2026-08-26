#include "string.h"
#include "wolfssl/wolfcrypt/aes.h"
#include "stubs.h"

extern void pwned(void);

int main() {
    volatile int dummy = 0;
    if (dummy) pwned();

    char message[16];
    // get message from input
    _read(0, message, 16);

    const char key[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15 };
    
    char out[16];
    Aes enc;
    int ret = wc_AesInit(&enc, NULL, INVALID_DEVID);
    if (ret != 0) {
        _write(0, "a", 1);
        return 0;
    }
    wc_AesSetKey(&enc, key, 16, NULL, AES_ENCRYPTION);
    wc_AesEcbEncrypt(&enc, out, message, 16);
    char round[16];
    wc_AesSetKey(&enc, key, 16, NULL, AES_DECRYPTION);
    wc_AesEcbDecrypt(&enc, round, out, 16);
    return 1;
}
