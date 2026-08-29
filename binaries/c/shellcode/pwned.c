extern int _write(int fd, char* buf, int len);

void pwned(void) {
    _write(0, "pwned!", 6);
    while (1) ;
}
