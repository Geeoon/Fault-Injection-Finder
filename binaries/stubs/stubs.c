#include <sys/stat.h>
#include <errno.h>

#define EXIT_ADDR (int*)0x10000
#define RW_ADDR (char*)0x11000

// unicorn hook
void _exit(int status) {
    *EXIT_ADDR = status;
    while(1);
}

int _read(int fd, char *buf, int len) {
    for (int i = 0; i < len; i++) buf[i] = *RW_ADDR;
    return len;
}

int _write(int fd, char *buf, int len) {
    for (int i = 0; i < len; i++) *RW_ADDR = buf[i];
    return len;
}

// should NOT be used
int _lseek(int fd, int offset, int whence) {
    return -1;
}

// should NOT be used
int _close(int fd) {
    return -1;
}

// should NOT be used
void *_sbrk(int incr) {
    return (void *)-1;
}

// should NOT be used
int _isatty(int fd) {
    return -1;
}

// should NOT be used
int _kill(int pid, int sig) {
    return -1;
}

// should NOT be used
int _getpid(void) {
    return -1;
}

// should NOT be used
int _fstat(int fd, struct stat *st) {
    return -1;
}
