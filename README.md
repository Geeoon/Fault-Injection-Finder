# Fault Injection Finder
## Geeoon Chung and Nate Snyder
This project is being developed for our EE 470 project.

The goals of this project are two part:
1. Develop a program that can find instructions that can be skipped to cause security issues
2. Run the program on a CPU (likely from an FPGA) and perform the faults

To inject faults, we could do following:
1. Perform reset glitches
2. Perform voltage glitches
3. Perform EMI glitches
4. Perform clock glitching

For triggers, we could do the following:
1. Power analysis
2. IO accesses
3. Count clock cycles
