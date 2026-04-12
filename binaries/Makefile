# CC=gcc
CC=arm-none-eabi-gcc
OBJCOPY=arm-none-eabi-objcopy
CFLAGS += -O0
# CFLAGS += --specs=nosys.specs
# CFLAGS += -nostdlib


# CFLAGS += -g2

.PRECIOUS: %.s %.elf

all: infinite_loop.bin password.bin

stubs.s: stubs/stubs.c
	$(CC) $(CFLAGS) -S $^ -o $@

%.s: source/%/main.c
	$(CC) $(CFLAGS) -S $^ -o $@

%.elf: %.s stubs.s
	$(CC) $(CFLAGS) $^ -o $@

%.bin: %.elf
	$(OBJCOPY) -O binary $< $@

clean:
	rm -f *.s *.elf *.o *.bin
