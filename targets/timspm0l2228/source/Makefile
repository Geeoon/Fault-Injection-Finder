MSPM0_SDK_INSTALL_DIR ?= /opt/mspm0-sdk-mspm0_sdk_2_06_00_05
TICLANG_ARMCOMPILER ?= /opt/ti-cgt-armllvm_4.0.3.LTS

.PHONY: all clean
all:

include $(MSPM0_SDK_INSTALL_DIR)/tools/imports_mak/imports.mak.linux

CC      = $(TICLANG_ARMCOMPILER)/bin/tiarmclang
LNK     = $(TICLANG_ARMCOMPILER)/bin/tiarmclang
OBJCOPY = $(TICLANG_ARMCOMPILER)/bin/tiarmobjcopy
BUILDDIR   ?= ./build
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
    ./$(LINKERFILE) \
    -Wl,--rom_model \
    -Wl,--warn_sections \
    -L$(TICLANG_ARMCOMPILER)/lib \
    -llibc.a

# --- Startup ---
STARTUP_OBJ := $(BUILDDIR)/shared/startup_mspm0l222x_ticlang.so

$(STARTUP_OBJ): startup_mspm0l222x_ticlang.c
	@mkdir -p $(dir $@)
	@echo "  CC  $<"
	@$(CC) $(CFLAGS) -c $< -o $@

# --- Shared objects ---
STUBS_OBJ     := $(BUILDDIR)/shared/stubs.so
SHELLCODE_OBJ := $(BUILDDIR)/shared/shellcode.so

$(STUBS_OBJ): stubs/stubs.c
	@mkdir -p $(dir $@)
	@echo "  CC  $<"
	@$(CC) $(CFLAGS) -Istubs -c $< -o $@

$(SHELLCODE_OBJ): shellcode/pwned.c
	@mkdir -p $(dir $@)
	@echo "  CC  $<"
	@$(CC) $(CFLAGS) -Ishellcode -c $< -o $@

# --- Discovery ---
MAIN_FILES := $(shell find $(SRCDIR) -mindepth 2 -name 'main.c')
PROJ_DIRS  := $(foreach m,$(MAIN_FILES),$(patsubst %/,%,$(dir $(m))))
PROJ_NAMES := $(foreach d,$(PROJ_DIRS),$(notdir $(d)))

ALL_ELFS := $(foreach n,$(PROJ_NAMES),$(BUILDDIR)/$(n)/$(n).elf)
ALL_BINS := $(foreach n,$(PROJ_NAMES),$(BUILDDIR)/$(n)/$(n).bin)

all: $(ALL_ELFS) $(ALL_BINS)

# --- Per-project rules ---
define COMPILE_RULE
$(2): $(1)
	@mkdir -p $$(dir $(2))
	@echo "  CC  $(1)"
	@$(CC) $(CFLAGS) -I$(3) -c $(1) -o $(2)
endef

define PROJECT_template
$(1)_SRCS := $$(shell find $(2) -maxdepth 1 -name '*.c')
$(1)_OBJS := $$(patsubst $(2)/%.c,$(BUILDDIR)/$(1)/%.so,$$($(1)_SRCS))

$$(foreach src,$$($(1)_SRCS),$$(eval $$(call COMPILE_RULE,$$(src),$$(patsubst $(2)/%.c,$(BUILDDIR)/$(1)/%.so,$$(src)),$(2))))

$(BUILDDIR)/$(1)/$(1).elf: $$($(1)_OBJS) $(STARTUP_OBJ) $(STUBS_OBJ) $(SHELLCODE_OBJ)
	@mkdir -p $$(dir $$@)
	@echo "  LD  $$@"
	@$(LNK) -Wl,-u,_c_int00 \
	    $$($(1)_OBJS) \
	    $(STARTUP_OBJ) \
	    $(STUBS_OBJ) \
	    $(SHELLCODE_OBJ) \
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