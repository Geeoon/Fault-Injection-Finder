# Fault Injection Finder
## Geeoon Chung and Nate Snyder
This project is being developed for our EE 470 project.

The goals of this project are two part:
1. Develop a program that can find instructions that can be skipped to cause security issues.
2. Run the program on a CPU (likely from an FPGA) and perform the faults

We search for security issues by doing one or more of the following:
1. Checking the IO output of the program
2. Checking the exit code of the program
3. Checking the state of the registers at the end of the program
4. Manually adding fault triggers into the "unreachable" parts of the code
5. Performing taint checking to see if the program counter (PC) is able to be modified
6. Using angr to solve for inputs that result user specified PC values

To inject faults, we could do following:
1. Perform reset glitches
2. Perform voltage glitches
3. Perform EMI glitches
4. Perform clock glitching

For triggers, we could do the following:
1. Power analysis
2. IO accesses
3. Count clock cycles

# Notes
`arm-none-eabi-objdump -D -b binary -m arm <binary> | less` to examine the raw binary as assembly

`arm-none-eabi-objdump -D -b binary -m arm -M force-thumb --architecture=armv6 sha256.bin | less` for ARMv6 Thumb

`arm-none-eabi-objdump -D -m arm -M force-thumb --architecture=armv6 aes_ecb.bin | less` for ARMv6 Thumb ELFs

## Running Binaries
The code included in `binaries/sources` are simply for testing.  They do not target any real hardware and are strictly for testing the tool.

To run a specific binary targeting a device, you need to extract the relevant part of the binary in a way that does not make any calls to peripherals outside of simple IO.  For example, if your binary uses UART, you can patch the binary by replacing calls to UART with calls to the `_read` and `_write` stubs found in `binaries/stubs`.  Additionally, GPIO can be replaced with calls to `_trigger` if desired.  To run your code though the tool, you will create a `main` symbol which contains your patched binary, then link it with the `binaries/startup.s` code.  This way, the tool will be able to start up and run your binary.  

For a specific example, check out the targets directory where we show this process on the TIMSPM0L2228.

### Compiling From Source
You must have the same version compiler and the same compilation flags/steps to create a binary that reflects the binary running on the target.  If you are creating your own programs and testing them, this is fine.  But if you only have the source code for the target which you are attacking, it is not likely you will be able to compile down to the exact binary that is running.  So it is recommended to use the exact binary running on your target whenever possible.
