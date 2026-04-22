import logging
logging.basicConfig(
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.INFO
)

from FaultInjectionFinder import FaultInjectionFinder
from FaultInjectionFinder.Engine import PCSolver

# finder = FaultInjectionFinder('./binaries/infinite_loop.bin', input=b'whatever', expected_output=b'escaped the loop')
# finder = FaultInjectionFinder('./binaries/password.bin', input=b'a' * 99, expected_output=b'access granted.', expected_exit=0)
# finder = FaultInjectionFinder('./binaries/pc_test.bin', input=b'0' * 4, desired_pc=0x12345678)
# finder = FaultInjectionFinder('./binaries/sha256.bin', input=b'1' * 16)
finder = FaultInjectionFinder('./binaries/aes_ecb.bin', input=b'a' * 16, desired_pc=0x200FFE0)

print(
"▄▖    ▜ ▗   ▄▖   ▘    ▗ ▘      ▄▖▘   ▌   \n" +
"▙▖▀▌▌▌▐ ▜▘  ▐ ▛▌ ▌█▌▛▘▜▘▌▛▌▛▌  ▙▖▌▛▌▛▌█▌▛▘ \n" +
"▌ █▌▙▌▐▖▐▖  ▟▖▌▌ ▌▙▖▙▖▐▖▌▙▌▌▌  ▌ ▌▌▌▙▌▙▖▌ \n" +
"                ▙▌                        \n"
)

for fault in finder.find_faults():
    i, insns, output, exit_code, regs, pc_control, trigger, input_to_pc = fault

    print("=" * 50)
    print(f"Fault @ instruction index: {i}")

    print("\nInstruction(s):")
    for insn in insns:
        print(f"  0x{insn.address:x}: {insn.mnemonic} {insn.op_str}")

    print("\nExit Code:")
    print(f"  {exit_code}")

    print("\nOutput:")
    print(f"  {output!r}")

    print("\nRegisters:")
    for reg in regs.keys():
        val = regs[reg]
        print(f"  {reg:>8}: 0x{val:08x} ({val})")

    if trigger:
        print("Fault was manually triggered")

    if pc_control:
        print("!" * 10)
        print("Got control of the PC")
        if input_to_pc:
            print(f"By giving an input of {input_to_pc}, we get the desired PC value of {finder.desired_pc}")
        elif finder.desired_pc:
            print(f"Unable to find a suitable input to get the desired PC value")
        print("!" * 10)

    print()