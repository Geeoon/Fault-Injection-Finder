CC=gcc

CFLAGS += -O0
CFLAGS += -g2

all: infinite_loop.elf password.elf

infinite_loop.elf: source/infinite_loop/main.c
	$(CC) $(CFLAGS) $^ -o $@

password.elf: source/password/main.c
	$(CC) $(CFLAGS) $^ -o $@
