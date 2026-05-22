# TIMSPM0L2228 Compilation
This directory contains scripts to compile for the TIMSPM0L2228.  The main difference between the compilation here and the compilation in the `binaries` directory is the addition of the target specific startup scripts, sdk, and stubs.

## Usage for the Tool
### Compilation
1) Compile the binaries like normal by navigating to `sources` and running `make`.
2) Within each source directory, there is a binary and elf which can be flashed onto the boards.

### Conversion
To create binaries which can be run using our tool, we need to examine the ELF that was generated.  In a real-world scenario, you may only have access to the raw binary, in which case you will need to reverse engineer the binary using something like Ghidra and any information you have about your target device.
1) Find the entry point to the section of code you want to test
2) Examine the section and any subroutines it calls for peripheral usage (like UART or GPIO)
3) Replace the calls to peripherals with functions in `stubs` or remove them entirely.
4) Link with the tool startup assembly.

### Infinite Loop Example
1) Since the infinite loop binary is simple, we can just emulate the entire `main` function.

Disassembly:
```
000002d0 <main>:
 2d0:   b510            push    {r4, lr}
 2d2:   b082            sub     sp, #8
 2d4:   f7ff ff78       bl      1c8 <init_device>
 2d8:   2001            movs    r0, #1
 2da:   9001            str     r0, [sp, #4]
 2dc:   9801            ldr     r0, [sp, #4]
 2de:   2800            cmp     r0, #0
 2e0:   d005            beq.n   2ee <main+0x1e>
 2e2:   9801            ldr     r0, [sp, #4]
 2e4:   2800            cmp     r0, #0
 2e6:   d002            beq.n   2ee <main+0x1e>
 2e8:   9801            ldr     r0, [sp, #4]
 2ea:   2800            cmp     r0, #0
 2ec:   d1f6            bne.n   2dc <main+0xc>
 2ee:   4904            ldr     r1, [pc, #16]   @ (300 <main+0x30>)
 2f0:   2400            movs    r4, #0
 2f2:   2210            movs    r2, #16
 2f4:   4620            mov     r0, r4
 2f6:   f7ff fee3       bl      c0 <_write>
 2fa:   4620            mov     r0, r4
 2fc:   b002            add     sp, #8
 2fe:   bd10            pop     {r4, pc}
 300:   0388            lsls    r0, r1, #14
```

2) We notice that `init_device` is just setting up the peripherals, so we can create a function which just returns immediately as a replacement.
3) We notice that `_write` makes calls to the UART peripheral, so it can be replaced with the `_write` stub
4) Ordinarily, we would need to rename the symbol for the entry point, but since it's already named `main` we can just keep it.

In order to achieve these goals, I created a seperate assembly file for init_device which immediately returns.
```
.init_device:
    bx lr  @ immediately exit
```

Compiled with "arm-none-eabi-gcc -c -march=armv6-m -mthumb init_device.s -o init_device.o", then got the raw opcodes with "arm-none-eabi-objcopy -O binary --only-section=.text init_device.o init_device.bin"

I then asked Claude to create a script to replace the old function with the new one.  That script is located in the `example` folder.
`python3 elf_patch.py ./infinite_loop.elf init_device ./init_device.bin -o ./ifinite_loop_patched.elf

This process was then done for the `_write` function.  Since the `stubs.s` file already contains assembly, I just reused that 
