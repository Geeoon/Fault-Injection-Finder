CC=arm-none-eabi-gcc
OBJCOPY=arm-none-eabi-objcopy
AR=arm-none-eabi-ar

# wolfSSL source tree lives here (full clone of https://github.com/wolfSSL/wolfssl)
# Layout: $(WOLFSSL_DIR)/wolfcrypt/src/*.c    <- sources
#         $(WOLFSSL_DIR)/wolfssl/wolfcrypt/*.h <- headers
WOLFSSL_DIR := wolfssl

ifdef ARCH
	CFLAGS += -march=$(ARCH)
else
	CFLAGS += -march=armv6-m
endif
ifneq ($(NO_THUMB),1)
	CFLAGS += -mthumb  # specific to ARM-Cortex-M0+, comment line for ARM32
endif
CFLAGS += -O2
CFLAGS += -ffunction-sections
CFLAGS += -fdata-sections
LDFLAGS += -Wl,--gc-sections
LDFLAGS += -nostartfiles
LDFLAGS += -T linkerfile.ld
CFLAGS += -ffreestanding
CFLAGS += -I./stubs
CFLAGS += -I.                      # resolves "user_settings.h" at repo root
CFLAGS += -I$(WOLFSSL_DIR)         # resolves "wolfssl/wolfcrypt/..." -> wolfssl/wolfssl/wolfcrypt/...
CFLAGS += -DWOLFSSL_USER_SETTINGS

.PRECIOUS: %.s %.elf

all: infinite_loop.bin password.bin exit.bin hello_world.bin echo.bin pc_test.bin sha256.bin aes_ecb.bin pc_test_complex.bin constraints.bin md5.bin chacha20.bin wolfssl_blake2b.bin wolfssl_ed25519_round.bin wolfssl_ed25519_sign.bin wolfssl_ed25519_verify.bin wolfssl_aes_ecb.bin

# --- wolfSSL library build ---
# Add source files here as you enable more wolfssl features
WOLFSSL_SRCS := \
	$(WOLFSSL_DIR)/wolfcrypt/src/blake2b.c \
	$(WOLFSSL_DIR)/wolfcrypt/src/aes.c \
	$(WOLFSSL_DIR)/wolfcrypt/src/ed25519.c \
	$(WOLFSSL_DIR)/wolfcrypt/src/sha512.c \
	$(WOLFSSL_DIR)/wolfcrypt/src/ge_operations.c \
	$(WOLFSSL_DIR)/wolfcrypt/src/fe_operations.c
WOLFSSL_OBJS := $(WOLFSSL_SRCS:.c=.o)

$(WOLFSSL_DIR)/wolfcrypt/src/%.o: $(WOLFSSL_DIR)/wolfcrypt/src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

libwolfssl.a: $(WOLFSSL_OBJS)
	$(AR) rcs $@ $^

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

TARGETS := infinite_loop password exit hello_world echo pc_test sha256 aes_ecb pc_test_complex constraints md5 chacha20 wolfssl_blake2b wolfssl_ed25519_round wolfssl_ed25519_sign wolfssl_ed25519_verify wolfssl_aes_ecb

define TARGET_RULES
$(1).elf: $(1).s stubs.s startup.s pwned.s $(call extra_objs,$(1)) libwolfssl.a
	$$(CC) $$(CFLAGS) $$^ $$(LDFLAGS) -o $$@
endef

$(foreach t,$(TARGETS),$(eval $(call TARGET_RULES,$(t))))

%.bin: %.elf
	$(OBJCOPY) -O binary $< $@

clean:
	rm -f $(addsuffix .bin,$(TARGETS)) \
	      $(addsuffix .elf,$(TARGETS)) \
	      $(addsuffix .s,$(TARGETS)) \
	      stubs.s pwned.s libwolfssl.a $(WOLFSSL_OBJS) \
	      $(foreach t,$(TARGETS),$(wildcard source/$(t)/*.o))