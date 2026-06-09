extern int _write(int fd, char* buf, int len);

void pwned(void) {
    while (1) _write(0, "pwned!", 6);
}

void pwned2(void) {
    while (1) _write(0, "pwned2!", 7);
}

void pwned3(void) {
    while (1) _write(0, "pwned3!", 7);
}

void pwned4(void) {
    while (1) _write(0, "pwned4!", 7);
}
