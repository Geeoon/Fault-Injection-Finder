import logging
logging.basicConfig(
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.INFO
)

from FaultInjectionFinder import FaultInjectionFinder

# finder = FaultInjectionFinder('./binaries/infinite_loop.bin', input=b'whatever', expected_output=b'escaped the loop')
# finder = FaultInjectionFinder('./binaries/password.bin', input=b'wrong\n', expected_output=b'access granted.', expected_exit=0)
finder = FaultInjectionFinder('./binaries/pc_test.bin', input=b'12345678')


print(
"▄▖    ▜ ▗   ▄▖   ▘    ▗ ▘      ▄▖▘   ▌   \n" +
"▙▖▀▌▌▌▐ ▜▘  ▐ ▛▌ ▌█▌▛▘▜▘▌▛▌▛▌  ▙▖▌▛▌▛▌█▌▛▘ \n" +
"▌ █▌▙▌▐▖▐▖  ▟▖▌▌ ▌▙▖▙▖▐▖▌▙▌▌▌  ▌ ▌▌▌▙▌▙▖▌ \n" +
"                ▙▌                        \n"
)

for fault in finder.find_faults():
    i, insns, output, exit_code, regs, pc_control = fault

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
    for reg in sorted(regs.keys(), key=lambda x: int(x[1:])):
        val = regs[reg]
        print(f"  {reg:>4}: 0x{val:08x} ({val})")

    if pc_control:
        print("!" * 10)
        print("Got control of the PC")
        print("!" * 10)

    print()