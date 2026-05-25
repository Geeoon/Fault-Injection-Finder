MSPM0_SDK_INSTALL_DIR ?= /opt/mspm0-sdk-mspm0_sdk_2_06_00_05
TICLANG_ARMCOMPILER ?= /opt/ti-cgt-armllvm_4.0.3.LTS

include $(MSPM0_SDK_INSTALL_DIR)/tools/imports_mak/imports.mak.linux

CC      = $(TICLANG_ARMCOMPILER)/bin/tiarmclang
LNK     = $(TICLANG_ARMCOMPILER)/bin/tiarmclang
OBJCOPY = $(TICLANG_ARMCOMPILER)/bin/tiarmobjcopy
BUILDDIR   ?= build
SRCDIR      = .
LINKERFILE  = linker.ld

CFLAGS += -I.. \
    -D__MSPM0L2228__ \
    -O2 \
    -I$(MSPM0_SDK_INSTALL_DIR)/source/third_party/CMSIS/Core/Include \
    -I$(MSPM0_SDK_INSTALL_DIR)/source \
    -gdwarf-3 \
    -mcpu=cortex-m0plus \
    -march=thumbv6m \
    -mfloat-abi=soft \
    -mthumb

LFLAGS += \
    -l$(MSPM0_SDK_INSTALL_DIR)/source/ti/drivers/lib/ticlang/m0p/drivers_mspm0l122x_l222x.a \
    -l$(MSPM0_SDK_INSTALL_DIR)/kernel/nortos/lib/ticlang/m0p/nortos_mspm0l122x_l222x.a \
    -l$(MSPM0_SDK_INSTALL_DIR)/source/ti/driverlib/lib/ticlang/m0p/mspm0l122x_l222x/driverlib.a \
    -L$(MSPM0_SDK_INSTALL_DIR)/source \
    -L.. \
    -Wl,$(LINKERFILE) \
    -Wl,--rom_model \
    -Wl,--warn_sections \
    -L$(TICLANG_ARMCOMPILER)/lib \
    -llibc.a

# --- Discovery (strip leading ./ for consistent path matching) ---
MAIN_FILES := $(patsubst ./%,%,$(shell find $(SRCDIR) -mindepth 2 -maxdepth 2 -name 'main.c' \
                  -not -path '*/build/*' \
                  -not -path '*/shellcode/*' \
                  -not -path '*/stubs/*'))
PROJ_DIRS  := $(foreach m,$(MAIN_FILES),$(patsubst %/,%,$(dir $(m))))
PROJ_NAMES := $(foreach d,$(PROJ_DIRS),$(notdir $(d)))

ALL_ELFS := $(foreach n,$(PROJ_NAMES),$(BUILDDIR)/$(n)/$(n).elf)
ALL_BINS := $(foreach n,$(PROJ_NAMES),$(BUILDDIR)/$(n)/$(n).bin)
ALL_ASMS := $(foreach n,$(PROJ_NAMES),$(foreach src,$($(n)_SRCS),$(patsubst $(n)/%.c,$(BUILDDIR)/$(n)/%.s,$(src))))

# MUST be first rule so it is the default goal
.PHONY: all clean
all: $(ALL_ELFS) $(ALL_BINS)

# --- Startup (two-step: .c -> .s -> .o) ---
STARTUP_ASM := $(BUILDDIR)/shared/startup_mspm0l222x_ticlang.s
STARTUP_OBJ := $(BUILDDIR)/shared/startup_mspm0l222x_ticlang.o

$(STARTUP_ASM): startup_mspm0l222x_ticlang.c
	@mkdir -p $(dir $@)
	@echo "  S   $<"
	@$(CC) $(CFLAGS) -S $< -o $@

$(STARTUP_OBJ): $(STARTUP_ASM)
	@echo "  AS  $<"
	@$(CC) $(CFLAGS) -c $< -o $@

# --- Shared objects (two-step: .c -> .s -> .o) ---
STUBS_ASM := $(BUILDDIR)/shared/stubs.s
STUBS_OBJ := $(BUILDDIR)/shared/stubs.o

PWNED_ASM := $(BUILDDIR)/shared/pwned.s
PWNED_OBJ := $(BUILDDIR)/shared/pwned.o

$(STUBS_ASM): stubs/stubs.c
	@mkdir -p $(dir $@)
	@echo "  S   $<"
	@$(CC) $(CFLAGS) -Istubs -S $< -o $@

$(STUBS_OBJ): $(STUBS_ASM)
	@echo "  AS  $<"
	@$(CC) $(CFLAGS) -Istubs -c $< -o $@

$(PWNED_ASM): shellcode/pwned.c
	@mkdir -p $(dir $@)
	@echo "  S  $<"
	@$(CC) $(CFLAGS) -Ipwned -S $< -o $@

$(PWNED_OBJ): $(PWNED_ASM)
	@echo "  AS  $<"
	@$(CC) $(CFLAGS) -Ipwned -c $< -o $@

# --- Per-project rules ---
define COMPILE_RULE
$(2): $(1)
	@mkdir -p $$(dir $(2))
	@echo "  S   $(1)"
	@$(CC) $(CFLAGS) -I$(4) -S $(1) -o $(2)

$(3): $(2)
	@echo "  AS  $(2)"
	@$(CC) $(CFLAGS) -I$(4) -c $(2) -o $(3)
endef

define PROJECT_template
$(1)_SRCS := $$(patsubst ./%,%,$$(shell find $(2) -maxdepth 1 -name '*.c'))
$(1)_ASMS := $$(patsubst $(2)/%.c,$(BUILDDIR)/$(1)/%.s,$$($(1)_SRCS))
$(1)_OBJS := $$(patsubst $(2)/%.c,$(BUILDDIR)/$(1)/%.o,$$($(1)_SRCS))

$$(foreach src,$$($(1)_SRCS),$$(eval $$(call COMPILE_RULE,\
    $$(src),\
    $$(patsubst $(2)/%.c,$(BUILDDIR)/$(1)/%.s,$$(src)),\
    $$(patsubst $(2)/%.c,$(BUILDDIR)/$(1)/%.o,$$(src)),\
    $(2))))

$(BUILDDIR)/$(1)/$(1).elf: $$($(1)_OBJS) $(STARTUP_OBJ) $(STUBS_OBJ) $(PWNED_OBJ)
	@mkdir -p $$(dir $$@)
	@echo "  LD  $$@"
	@$(LNK) -Wl,-u,_c_int00 \
	    $$($(1)_OBJS) \
	    $(STARTUP_OBJ) \
	    $(STUBS_OBJ) \
		$(PWNED_OBJ) \
	    $(LFLAGS) \
	    -Wl,-m,$(BUILDDIR)/$(1)/$(1).map \
	    -o $$@

$(BUILDDIR)/$(1)/$(1).bin: $(BUILDDIR)/$(1)/$(1).elf
	@echo "  BIN $$@"
	@$(OBJCOPY) -O binary $$< $$@

endef

$(foreach m,$(MAIN_FILES),$(eval $(call PROJECT_template,$(notdir $(patsubst %/,%,$(dir $(m)))),$(patsubst %/,%,$(dir $(m))))))

clean:
	@echo Cleaning...
	@$(RM) -r $(BUILDDIR)