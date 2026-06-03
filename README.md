# Fault Injection Finder
```
▄▖    ▜ ▗   ▄▖   ▘    ▗ ▘      ▄▖▘   ▌     
▙▖▀▌▌▌▐ ▜▘  ▐ ▛▌ ▌█▌▛▘▜▘▌▛▌▛▌  ▙▖▌▛▌▛▌█▌▛▘ 
▌ █▌▙▌▐▖▐▖  ▟▖▌▌ ▌▙▖▙▖▐▖▌▙▌▌▌  ▌ ▌▌▌▙▌▙▖▌  
                ▙▌                         
```
### Geeoon Chung and Nate Snyder
This repository is the software side of our fault injection attack project.  For the hardware side, check out [this repo](https://github.com/Ice-Skates/voltage_glitch).

## Overall Project
The goal of this project is to find instructions in a program's execution that, when skipped/NOP'd, cause security issues.
1. Pre-processing
    1. Load the binary
    2. Identify instructions that are more likely to cause security issues when NOP'd.
2. Unicorn Emulation
    1. Run the program, NOP'ing the nth instruction issued.
    2. Check the output of the program to see if a security fault occured.
        1. If an invalid fetch occured, flip all the bits of the input to the program.
        2. Re-run the program.
        3. If an invalid fetch at a different address occured, take note.  This means that the input to the program is capable of influencing the program counter (i.e., control of the PC).
3. Angr SMT Solving
    1. If the Unicorn emulation indicated control of the PC, run the program with symbolic inputs and skip the instruction issue from the Unicorn step.
    2. See if we eventually get a symbolic variable into the PC register.
    3. Solve for a custom PC value to see what input we need to get our PC to a specific address.
    4. If it can be solved for, take note of the input that resulted in to specified PC.
4. Export interesting instructions
5. Test the instructions on the target using the `targets/tooling.py` script and an FPGA.

[Flow chart for the software](https://raw.githubusercontent.com/Geeoon/Fault-Injection-Finder/refs/heads/main/470_FlowChart.png)

[A presentation we gave for this project](https://github.com/Geeoon/Fault-Injection-Finder/blob/main/EE%20470%20Project%20Presentation.pdf)

## Details
We search for security issues by doing one or more of the following:
1. Checking the IO output of the program
2. Checking the exit code of the program
4. Manually adding fault triggers into the "unreachable" parts of the code
5. Performing taint checking to see if the program counter (PC) is able to be modified
6. Using angr (SMT solver) to solve for inputs that result user specified PC values

## Glitching
To inject faults, we chose to do crowbar glitching.  This was achieved using an FGPA with an SI 2302 N-channel MOSFET.  [Here's a link to our FPGA tooling.](https://github.com/Ice-Skates/voltage_glitch)  More information can be found in `targets`.

## Triggers
For triggers, we chose to use a GPIO input to an FPGA.  In the test code, we toggle an LED, though you could perform power analysis to for your triggers

## Usage
### Dependencies
The dependencies are listed in the `requirements.txt`.  Install them with `pip install -r requirements.txt`.
```
usage: main.py [-h] [-s INDEX] [-i MAX_ITERATIONS] [-o EXPECTED_OUTPUT] [-e EXPECTED_EXIT] [-d DESIRED_PC] [-v] [-n] [-t TYPES] [-b BINARY_ADDR]
               [-u OUTPUT_DIR] [-f BEGIN_ADDR] [-g END_ADDR]
               binary_path input_path

Automatically finds hardware security vulnerabilities in binaries. Only support ARM.

positional arguments:
  binary_path           The binary to examine
  input_path            The path to the input to the program

options:
  -h, --help            show this help message and exit
  -s, --simulate INDEX  Runs a Unicorn simulation with the fault at an nth instruction issue. Ignores all other flags besides --max_iterations and
                        --verbose.
  -i, --max-iterations MAX_ITERATIONS
                        The maximum number of instructions to run in the binary before ending early
  -o, --expected-output EXPECTED_OUTPUT
                        The expected output of the program on a successful security incident
  -e, --expected-exit EXPECTED_EXIT
                        The expected exit of the program on a successful security incident
  -d, --desired-pc DESIRED_PC
                        The program counter we desire to achieve if possible. In hex or decimal. Keep in mind that this is the absolute address,
                        not relative to the binary.
  -v, --verbose         Verbosity: warning, info, debug
  -n, --no-thumb        Whether or not to run in thumb mode
  -t, --types TYPES     Which types of instructions to focus on. 0) Brute force: every issue. 1) Recommended defaults. 2) Only conditional
                        branches. 3) Only compare/tests. 4) Only returns. 5) Only branches, calls, returns, and compares
  -b, --binary-addr BINARY_ADDR
                        The address to flash the binary to. Defaults to 0x1000000. Can be in hex or decimal.
  -u, --output-dir OUTPUT_DIR
                        The directory to store faults that were found.
  -f, --begin-addr BEGIN_ADDR
                        The starting address of the instructions that should be considered for skipping. (inclusive.) If set, -g must also be set.
  -g, --end-addr END_ADDR
                        The ending address of the instructions that should be considered for skipping. (inclusive.) If set, -f must also be set.
```

### Example Usage
#### Output Checking
`python3 main.py ./binaries/sha256.bin ./inputs/sha256.bin -o ./expecteds/sha256.bin -v`

Checks the output to see if we achieved our attack goals.
#### Program Counter Control
`python3 main.py ./binaries/aes_ecb.bin ./inputs/aes_ecb.bin -d 0x100045c -v -u outputs/aes_ecb`

Tests the aes_ecb binary to jump to a custom "unreachable" function and store the inputs inputs into a directory.
#### Testing a Glitch in Simulation
`python3 main.py ./binaries/aes_ecb.bin ./outputs/aes_ecb/solved_pc_188.bin -s 188`

Run Unicorn simulation for this specific glitch cycle and input.  In this case, the output from the program counter control.

## Limitations
1. For now, this program only supports the ARM instruction set.  It supports both thumb and non-thumb modes.
2. Some binaries perform very complex operations on the input (like hashing), which make the SMT solver slow down.

# Notes
## Running Binaries
The code included in `binaries/sources` are simply for testing.  They do not target any real hardware and are strictly for testing the tool.

To run a specific binary targeting a device, you need to extract the relevant part of the binary in a way that does not make any calls to peripherals outside of simple IO.  For example, if your binary uses UART, you can patch the binary by replacing calls to UART with calls to the `_read` and `_write` stubs found in `binaries/stubs`.  Additionally, GPIO can be replaced with calls to `_trigger` if desired.  To run your code though the tool, you will create a `main` symbol which contains your patched binary, then link it with the `binaries/startup.s` code.  This way, the tool will be able to start up and run your binary.  

For a specific example, check out the targets directory where we show this process on the TIMSPM0L2228.

## Compiling From Source
You must have the same version compiler and the same compilation flags/steps to create a binary that reflects the binary running on the target.  If you are creating your own programs and testing them, this is fine.  But if you only have the source code for the target which you are attacking, it is not likely you will be able to compile down to the exact binary that is running.  So it is recommended to use the exact binary running on your target whenever possible.

<!-- 
`arm-none-eabi-objdump -D -b binary -m arm <binary> | less` to examine the raw binary as assembly

`arm-none-eabi-objdump -D -b binary -m arm -M force-thumb --architecture=armv6 sha256.bin | less` for ARMv6 Thumb

`arm-none-eabi-objdump -D -m arm -M force-thumb --architecture=armv6 aes_ecb.elf | less` for ARMv6 Thumb ELFs
-->
