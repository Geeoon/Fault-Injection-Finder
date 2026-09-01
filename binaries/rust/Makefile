CC=arm-none-eabi-gcc
OBJCOPY=arm-none-eabi-objcopy
AR=arm-none-eabi-ar
CARGO=cargo

ifdef ARCH
	CFLAGS += -march=$(ARCH)
else
	CFLAGS += -march=armv6-m
endif
ifneq ($(NO_THUMB),1)
	CFLAGS += -mthumb
endif

ifdef TARGET
	RUST_TARGET=$(TARGET)
else
	RUST_TARGET=thumbv6m-none-eabi
endif
CFLAGS += -O2
CFLAGS += -ffunction-sections
CFLAGS += -fdata-sections
LDFLAGS += -Wl,--gc-sections
LDFLAGS += -nostartfiles
LDFLAGS += -T linkerfile.ld
CFLAGS += -ffreestanding

.PRECIOUS: %.s %.elf

all: hello.bin echo.bin password.bin rustcrypto_aes_ecb_decrypt.bin
STATICLIB_TARGETS := rustcrypto_aes_ecb_decrypt

stubs.s: stubs/src/lib.rs
	$(CARGO) clean -p stubs --target $(RUST_TARGET) --release
	$(CARGO) rustc -p stubs --target $(RUST_TARGET) --release -- --emit=asm=$(CURDIR)/$@

pwned.s: shellcode/src/lib.rs
	$(CARGO) clean -p shellcode --target $(RUST_TARGET) --release
	$(CARGO) rustc -p shellcode --target $(RUST_TARGET) --release -- --emit=asm=$(CURDIR)/$@

%.s: source/%/src/main.rs stubs.s
	$(CARGO) clean -p $* --target $(RUST_TARGET) --release
	$(CARGO) rustc -p $* --target $(RUST_TARGET) --release -- --emit=asm=$(CURDIR)/$@

# External libraries have to compiled statically
librustcrypto_aes_ecb_decrypt.a: source/rustcrypto_aes_ecb_decrypt/src/lib.rs
	$(CARGO) clean -p rustcrypto_aes_ecb_decrypt --target $(RUST_TARGET) --release
	$(CARGO) build -p rustcrypto_aes_ecb_decrypt --target $(RUST_TARGET) --release
	cp target/$(RUST_TARGET)/release/librustcrypto_aes_ecb_decrypt.a $@

rustcrypto_aes_ecb_decrypt.elf: librustcrypto_aes_ecb_decrypt.a startup.s pwned.s
	$(CC) $(CFLAGS) startup.s pwned.s $< $(LDFLAGS) -o $@


# Compile extra (non-main) .c files in a target's directory to .o
source/%/%.o: source/%/%.c
	$(CC) $(CFLAGS) -c $< -o $@

extra_objs = $(patsubst %.c,%.o,\
				$(filter-out source/$(1)/main.c,\
					$(wildcard source/$(1)/*.c)))

TARGETS := hello echo password

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

clean:
	rm -f $(addsuffix .bin,$(TARGETS) $(STATICLIB_TARGETS)) \
	      $(addsuffix .elf,$(TARGETS) $(STATICLIB_TARGETS)) \
	      $(addsuffix .s,$(TARGETS) $(STATICLIB_TARGETS)) \
	      $(addprefix lib,$(addsuffix .a,$(STATICLIB_TARGETS))) \
	      stubs.s pwned.s \
	      $(foreach t,$(TARGETS) $(STATICLIB_TARGETS),$(wildcard source/$(t)/*.o))