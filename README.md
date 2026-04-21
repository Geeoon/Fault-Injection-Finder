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
