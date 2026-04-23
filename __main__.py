import logging

from FaultInjectionFinder import FaultInjectionFinder
from FaultInjectionFinder.Engine.FIEngine import DEFAULT_BINARY_ADDRESS
logging.basicConfig(
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.INFO
)

logger = logging.getLogger("FaultInjectionFinder")
logger.setLevel(logging.DEBUG)
# finder = FaultInjectionFinder('./binaries/infinite_loop.bin', input=b'whatever', expected_output=b'escaped the loop')
# finder = FaultInjectionFinder('./binaries/password.bin', input=b'a' * 99, expected_output=b'access granted.', expected_exit=0)
# finder = FaultInjectionFinder('./binaries/pc_test.bin', input=b'0' * 4, desired_pc=DEFAULT_BINARY_ADDRESS + 0x7c)
# finder = FaultInjectionFinder('./binaries/pc_test_complex.bin', input=b'0' * 4, desired_pc=DEFAULT_BINARY_ADDRESS + 0xb0)
# finder = FaultInjectionFinder('./binaries/sha256.bin', input=b'1' * 16, desired_pc=DEFAULT_BINARY_ADDRESS + 0x2b8)
finder = FaultInjectionFinder('./binaries/aes_ecb.bin', input=b'a' * 16, desired_pc=DEFAULT_BINARY_ADDRESS + 0x2358)
# finder = FaultInjectionFinder('./binaries/constraints.bin', input=b'a', desired_pc=DEFAULT_BINARY_ADDRESS + 0xb0)

# simulate faults
# pc_test.bin
# res = finder.simulate_fault(b'}\x00\x00\x01', index=36)
# pc_test_complex.bin
# res = finder.simulate_fault(b'.\xf4e\x10', index=61)
# sha256.bin
# :(
# aes_ecb.bin
# res = finder.simulate_fault(b'Y#\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00', index=104)
# res = finder.simulate_fault(b'\x00\x00\x00\x00\x00\x00\x00\x00Y#\x00\x01\x00\x00\x00\x00', index=193)
# res = finder.simulate_fault(b'\x00\x00\x00\x00Y#\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00', index=198)
# res = finder.simulate_fault(b'Y#\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00', index=204)
# constrains.bin
# res = finder.simulate_fault(, index=)
# print(res)
# quit()

print(
"▄▖    ▜ ▗   ▄▖   ▘    ▗ ▘      ▄▖▘   ▌   \n" +
"▙▖▀▌▌▌▐ ▜▘  ▐ ▛▌ ▌█▌▛▘▜▘▌▛▌▛▌  ▙▖▌▛▌▛▌█▌▛▘ \n" +
"▌ █▌▙▌▐▖▐▖  ▟▖▌▌ ▌▙▖▙▖▐▖▌▙▌▌▌  ▌ ▌▌▌▙▌▙▖▌ \n" +
"                ▙▌                        \n"
)

for fault in finder.find_faults():
    i, insns, output, exit_code, regs, pc_control, trigger, input_to_pc = fault

    print("=" * 50)
    print(f"Fault @ cycle {i}")

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
        if input_to_pc is not None:
            print(f"By giving an input of {input_to_pc}, we get the desired PC value of {finder.desired_pc}")
        elif finder.desired_pc is not None:
            print(f"Unable to find a suitable input to get the desired PC value")
        print("!" * 10)

    print()