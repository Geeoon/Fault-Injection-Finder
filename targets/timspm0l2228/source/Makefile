MSPM0_SDK_INSTALL_DIR ?= /opt/mspm0-sdk-mspm0_sdk_2_06_00_05
TICLANG_ARMCOMPILER ?= /opt/ti-cgt-armllvm_4.0.3.LTS
include $(MSPM0_SDK_INSTALL_DIR)/tools/imports_mak/imports.mak.linux

STARTUP = startup_mspm0l222x_ticlang.c
STARTUP_OBJ = $(BUILDDIR)/startup_mspm0l122x_l222x_ticlang.so

STUBS = stubs/stubs.c
STUBS_OBJ = $(BUILDDIR)/stubs.so

CC = "$(TICLANG_ARMCOMPILER)/bin/tiarmclang"
LNK = "$(TICLANG_ARMCOMPILER)/bin/tiarmclang"
OBJCOPY = "$(TICLANG_ARMCOMPILER)/bin/tiarmobjcopy"
BUILDDIR ?= ./build
SRCDIR = ./hello_world
LINKERFILE = "linker.ld"

SOURCES = $(shell find $(SRCDIR) -name '*.c')
OBJECTS = $(patsubst $(SRCDIR)/%.c,$(BUILDDIR)/%.so,$(SOURCES)) $(STARTUP_OBJ) $(STUBS_OBJ)

NAME = mspm0l2228

CFLAGS += -I.. \
    -D__MSPM0L2228__ \
    -O2 \
    "-I$(MSPM0_SDK_INSTALL_DIR)/source/third_party/CMSIS/Core/Include" \
    "-I$(MSPM0_SDK_INSTALL_DIR)/source" \
    -gdwarf-3 \
    -mcpu=cortex-m0plus \
    -march=thumbv6m \
    -mfloat-abi=soft \
    -mthumb

LFLAGS += "-l$(MSPM0_SDK_INSTALL_DIR)/source/ti/drivers/lib/ticlang/m0p/drivers_mspm0l122x_l222x.a" \
    "-l$(MSPM0_SDK_INSTALL_DIR)/kernel/nortos/lib/ticlang/m0p/nortos_mspm0l122x_l222x.a" \
    "-l$(MSPM0_SDK_INSTALL_DIR)/source/ti/driverlib/lib/ticlang/m0p/mspm0l122x_l222x/driverlib.a" \
    "-L$(MSPM0_SDK_INSTALL_DIR)/source" \
    -L.. \
    ./$(LINKERFILE) \
    "-Wl,-m,$(BUILDDIR)/$(NAME).map" \
    -Wl,--rom_model \
    -Wl,--warn_sections \
    "-L$(TICLANG_ARMCOMPILER)/lib" \
    -llibc.a

all: $(BUILDDIR)/$(NAME).elf $(BUILDDIR)/$(NAME).bin

$(BUILDDIR)/%.so: $(SRCDIR)/%.c
	@ mkdir -p $(dir $@)
	@ echo Building $@
	@ $(CC) $(CFLAGS) -c $< -o $@

# Explicit rule for startup file
$(STARTUP_OBJ): $(STARTUP)
	@ mkdir -p $(dir $@)
	@ echo Building $@
	@ $(CC) $(CFLAGS) -c $< -o $@

# Explicit rule for stubs file
$(STUBS_OBJ): $(STUBS)
	@ mkdir -p $(dir $@)
	@ echo Building $@
	@ $(CC) $(CFLAGS) -c $< -o $@

$(BUILDDIR)/$(NAME).elf: $(OBJECTS)
	@ echo linking $@
	@ $(LNK) -Wl,-u,_c_int00 $(OBJECTS)  $(LFLAGS) -o $(BUILDDIR)/$(NAME).elf

$(BUILDDIR)/$(NAME).bin: $(BUILDDIR)/$(NAME).elf
	@ $(OBJCOPY) -O binary $(BUILDDIR)/$(NAME).elf $(BUILDDIR)/$(NAME).bin

clean:
	@ echo Cleaning...
	@ $(RM) $(OBJECTS) > $(DEVNULL) 2>&1
	@ $(RM) $(NAME).elf > $(DEVNULL) 2>&1
	@ $(RM) $(NAME).map > $(DEVNULL) 2>&1