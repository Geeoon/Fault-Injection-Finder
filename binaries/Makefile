# CC=gcc
CC=arm-none-eabi-gcc
OBJCOPY=arm-none-eabi-objcopy
CFLAGS += -O0
CFLAGS += -ffunction-sections
CFLAGS += -fdata-sections
LDFLAGS += -Wl,--gc-sections
LDFLAGS += -nostartfiles
LDFLAGS += -T linkerfile.ld
# CFLAGS += -nostdlib
# CFLAGS += --specs=nosys.specs
# CFLAGS += -g2

.PRECIOUS: %.s %.elf

all: infinite_loop.bin password.bin exit.bin

stubs.s: stubs/stubs.c
	$(CC) $(CFLAGS) -S $^ -o $@

%.s: source/%/main.c
	$(CC) $(CFLAGS) -S $^ -o $@

%.elf: %.s stubs.s startup.s
	$(CC) $(CFLAGS) $^ $(LDFLAGS) -o $@

%.bin: %.elf
	$(OBJCOPY) -O binary $< $@

clean:
	rm -f infinite_loop.* password.* stubs.*
