# TIMSPM0L2228 Compilation
This directory contains scripts to compile for the TIMSPM0L2228.  The main difference between the compilation here and the compilation in the `binaries` directory is the addition of the target specific startup scripts, sdk, and stubs.

## Usage for the Tool
### Compilation
1) Compile the binaries like normal by navigating to `sources` and running `make`.
2) Within each source directory, there is a binary and elf which can be flashed onto the boards.

### Conversion
To create binaries which can be run using our tool, we need to examine the assembly.  In a real-world scenario, you may only have access to the raw binary, in which case you will need to reverse engineer the binary using something like Ghidra and any information you have about your target device.
1) Find the entry point to the section of code you want to test
2) Examine the section and any subroutines it calls for peripheral usage (like UART or GPIO)
3) Replace the calls to peripherals with functions in `stubs` or remove them entirely.
4) Link with the tool startup assembly.

### Infinite Loop Example
Since the infinite loop binary is simple, we can just emulate the entire `main` function.

For the sake of simplicity, we're just going to use the compiled `.s` files (you will need to reverse engineer your binary in cases you don't have assembly source files which is out of the scope for this example).

Take all the assembly files you need, and link them with `startup.s`.  You will also probably need to link it with the `binaries/stubs.s` file (the one in the `binaries` directory not this directory).

We are also missing the `init_device` function, but luckily, the function is only used for setting up the embedded system, so we can create our own function that just immediately returns:

2) We notice that `init_device` is just setting up the peripherals, so we can create a function which just returns immediately as a replacement.
3) We notice that `_write` makes calls to the UART peripheral, so it can be replaced with the `_write` stub
4) Ordinarily, we would need to rename the symbol for the entry point, but since it's already named `main` we can just keep it.

```
    .text
    .thumb_func
    .globl  init_device
init_device:
    bx lr  @ immediately exit
```

Here's the command we used: `arm-none-eabi-gcc main.s init_device.s stubs.s startup.s pwned.s -Wl,--gc-sections -nostartfiles -T linkerfile.ld -march=armv6-m -mthumb -o infinite_loop.elf`

We get the following errors:
```
main.s: Assembler messages:
main.s:24: Error: junk at end of line, first unrecognized character is `"'
main.s:25: Error: junk at end of line, first unrecognized character is `"'
main.s:354: Error: unknown pseudo-op: `.addrsig'
main.s:356: Error: unknown pseudo-op: `.ti_attribute'
```

You can also use this command to remove errors related to `.loc`: `grep -v "^\s*.loc" main.s`

These errors are a result of the TI clang compiler having conflicts with our GCC compiler.  Just delete the lines where they appear and relink until the errors disappear.

Then once we have the ELF, we can turn it into a binary: `arm-none-eabi-objcopy -O binary ininite_loop.elf infinite_loop.bin`

You can now run the program using the tool.

### Reference
System Reset: `dslite -c MSPM0L2228.ccxml -r 1`
Flash Binary: `dslite -c MSPM0L2228.ccxml -f ./source/build/hello_world/hello_world.elf`



<!-- 100027c 100031a -->