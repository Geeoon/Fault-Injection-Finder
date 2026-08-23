#include "string.h"
#include "wolfssl/wolfcrypt/ed25519.h"
#include "stubs.h"

extern void pwned(void);

/* Fixed 32-byte Ed25519 private key (seed) */
static const unsigned char ed25519_priv_key[32] = {
    0xcf, 0x22, 0x14, 0xac, 0xdf, 0x66, 0xbf, 0xac,
    0xd7, 0x82, 0x3e, 0x46, 0xf4, 0xac, 0x5f, 0x67,
    0x5d, 0x14, 0x74, 0x24, 0xf4, 0x85, 0xfd, 0xbb,
    0xd8, 0x58, 0xb1, 0xb5, 0x83, 0xad, 0x3d, 0x06
};
 
/* Corresponding 32-byte Ed25519 public key */
static const unsigned char ed25519_pub_key[32] = {
    0x38, 0x3c, 0xb2, 0x3b, 0x85, 0x75, 0xc4, 0x71,
    0x58, 0xca, 0xf5, 0x3a, 0x4c, 0xa7, 0x44, 0xa1,
    0x9b, 0x5c, 0x37, 0x83, 0xc9, 0x52, 0x6a, 0x40,
    0x20, 0xb0, 0xca, 0x8e, 0x74, 0x0e, 0x83, 0x22
};

int main() {
    volatile int dummy = 0;
    if (dummy) pwned();

    ed25519_key key;
    char message[500];
    word32 msgLen = 500;

    // get message from input
    _read(0, message, msgLen);

    byte sig[ED25519_SIG_SIZE];
    word32 sigLen = sizeof(sig);
    int verified, ret = 0;
 
    /* 1. Initialize the key struct */
    ret = wc_ed25519_init(&key);
    if (ret != 0) {
        _write(0, "fail", 4);
    }

    /* 2. Import the fixed private/public key pair (no RNG needed) */
    ret = wc_ed25519_import_private_key(ed25519_priv_key, 32,
                                         ed25519_pub_key, 32,
                                         &key);
    
    if (ret != 0) {
        _write(0, "Fail", 4);
        return 0;
    }

    ret = wc_ed25519_sign_msg((const byte*)message, msgLen, sig, &sigLen, &key);
    if (ret != 0) {
        _write(0, "fAil", 4);
        return 0;
    }

    /* 4. Verify the signature */
    ret = wc_ed25519_verify_msg(sig, sigLen, (const byte*)message, msgLen,
                                 &verified, &key);
    if (ret != 0) {
        _write(0, "faIl", 4);
        return 0;
    }
 
    if (verified) {
        _write(0, "A", 1);
    } else {
        _write(0, "B", 1);
    }

    return 1;
}