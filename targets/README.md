# Tooling
The tooling will allow you to try the output of the Fault Injection Finder on real hardware.  It relies on an FGPA that implements a simple UART protocol:

`0xAA` signals the FPGA to reset it's trigger detection.  Use after you reset your target.

`0xFF` is the header used to send the delay after a trigger.  The next 4 bytes should be the delay (in FPGA clock cycles) in big-endian order.

`0x00` is the header used to send the glitch length.  The next byte should be the length (in FPGA clock cycles).

After each byte send to the FPGA, it will echo back the byte sent.  Additionally, while running, the FPGA will send `0xCC` when the trigger is detected.

Our implementation is hosted at [this repository](https://github.com/Ice-Skates/voltage_glitch).
