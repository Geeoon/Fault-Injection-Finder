CC=arm-none-eabi-gcc
OBJCOPY=arm-none-eabi-objcopy
AR=arm-none-eabi-ar
CARGO=cargo
RUST_TARGET=thumbv6m-none-eabi

ifdef ARCH
	CFLAGS += -march=$(ARCH)
else
	CFLAGS += -march=armv6-m
endif
ifneq ($(NO_THUMB),1)
	CFLAGS += -mthumb
endif
CFLAGS += -O2
CFLAGS += -ffunction-sections
CFLAGS += -fdata-sections
LDFLAGS += -Wl,--gc-sections
LDFLAGS += -nostartfiles
LDFLAGS += -T linkerfile.ld
CFLAGS += -ffreestanding

.PRECIOUS: %.s %.elf

all: hello.bin

stubs.s: stubs/src/lib.rs
	$(CARGO) rustc -p stubs --target $(RUST_TARGET) --release -- --emit=asm=$(CURDIR)/$@

pwned.s: shellcode/src/lib.rs
	$(CARGO) rustc -p shellcode --target $(RUST_TARGET) --release -- --emit=asm=$(CURDIR)/$@

%.s: source/%/src/main.rs stubs.s
	$(CARGO) rustc -p $* --target $(RUST_TARGET) --release -- --emit=asm=$(CURDIR)/$@

# Compile extra (non-main) .c files in a target's directory to .o
source/%/%.o: source/%/%.c
	$(CC) $(CFLAGS) -c $< -o $@

extra_objs = $(patsubst %.c,%.o,\
				$(filter-out source/$(1)/main.c,\
					$(wildcard source/$(1)/*.c)))

TARGETS := hello

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