#ifndef STUBS_H
#define STUBS_H
#include <stdint.h>
#include <sys/stat.h>

#define EXIT_ADDR    (volatile int*)0x3000000
#define RW_ADDR      (volatile char*)0x3001000
#define FAULT_ADDR   (volatile int*)0x3002000
#define TRIGGER_ADDR (volatile int*)0x3003000

static inline __attribute__((always_inline)) void _successful_fault(void) {
    *FAULT_ADDR = 0;
}

static inline __attribute__((always_inline)) void _trigger(void) {
    *TRIGGER_ADDR = 0;
}

// unicorn hooks
int _read(int fd, char *buf, int len);
int _write(int fd, char *buf, int len);

void _exit(int status);
void _fini(void);
void _init(void);
// should NOT be used
int _lseek(int fd, int offset, int whence);
// should NOT be used
int _close(int fd);
// should NOT be used
void *_sbrk(int incr);
// should NOT be used
int _isatty(int fd);
// should NOT be used
int _kill(int pid, int sig);
// should NOT be used
int _getpid(void);
// should NOT be used
int _fstat(int fd, struct stat *st);
#endif  // STUBS_H
