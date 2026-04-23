# CC=gcc
CC=arm-none-eabi-gcc
OBJCOPY=arm-none-eabi-objcopy
ifneq ($(NO_THUMB),1)
CFLAGS += -march=armv6-m -mthumb  # specific to ARM-Cortex-M0+, comment line for ARM32
endif
CFLAGS += -O2
CFLAGS += -ffunction-sections
CFLAGS += -fdata-sections
LDFLAGS += -Wl,--gc-sections
LDFLAGS += -nostartfiles
LDFLAGS += -T linkerfile.ld
# CFLAGS += -nostdlib
# CFLAGS += --specs=nosys.specs
# CFLAGS += -g2

.PRECIOUS: %.s %.elf

all: infinite_loop.bin password.bin exit.bin hello_world.bin echo.bin pc_test.bin sha256.bin aes_ecb.bin pc_test_complex.bin constraints.bin

stubs.s: stubs/stubs.c
	$(CC) $(CFLAGS) -S $^ -o $@

pwned.s: shellcode/pwned.c
	$(CC) $(CFLAGS) -S $^ -o $@

%.s: source/%/main.c
	$(CC) $(CFLAGS) -S $^ -o $@

%.s: source/%/main.s
	cp $< $@

# Compile extra (non-main) .c files in a target's directory to .o
source/%/%.o: source/%/%.c
	$(CC) $(CFLAGS) -c $< -o $@

# Find extra .o files needed for a given target
extra_objs = $(patsubst %.c,%.o,\
				$(filter-out source/$(1)/main.c,\
					$(wildcard source/$(1)/*.c)))

TARGETS := infinite_loop password exit hello_world echo pc_test sha256 aes_ecb pc_test_complex constraints

define TARGET_RULES
$(1).elf: $(1).s stubs.s startup.s pwned.s $(call extra_objs,$(1))
	$$(CC) $$(CFLAGS) $$^ $$(LDFLAGS) -o $$@
endef

$(foreach t,$(TARGETS),$(eval $(call TARGET_RULES,$(t))))

%.bin: %.elf
	$(OBJCOPY) -O binary $< $@

clean:
	rm -f $(addsuffix .bin,$(TARGETS)) \
	      $(addsuffix .elf,$(TARGETS)) \
	      $(addsuffix .s,$(TARGETS)) \
	      stubs.s pwned.s \
	      $(foreach t,$(TARGETS),$(wildcard source/$(t)/*.o))
