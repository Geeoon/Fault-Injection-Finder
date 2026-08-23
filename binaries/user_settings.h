#ifndef USER_SETTINGS_H
#define USER_SETTINGS_H

/* Crypto-only, no TLS stack */
#define WOLFCRYPT_ONLY

/* No OS/libc facilities available */
#define NO_FILESYSTEM
#define NO_WRITEV
#define NO_MAIN_DRIVER
#define SINGLE_THREADED

/* No hardware RNG / entropy source on bare metal */
#define WC_NO_RNG

/* Avoid ARM asm variants not valid on Cortex-M0+ (no DSP/NEON etc.) */
#define NO_ASM

/* Trim unneeded default-on algorithms/features you don't need yet */
#define NO_RSA
#define NO_DH
#define NO_DSA
#define NO_PWDBASED
#define NO_CERTS
#define NO_SESSION_CACHE

/* Save flash: skip human-readable error strings */
#define NO_ERROR_STRINGS

/* Enable the algorithm you actually use */
#define HAVE_BLAKE2
#define WOLFSSL_SHA512
#define HAVE_ECC
#define HAVE_ED25519

#endif /* USER_SETTINGS_H */