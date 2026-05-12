import logging
import argparse
from pathlib import Path

from FaultInjectionFinder import FaultInjectionFinder
from FaultInjectionFinder.Engine.FIEngine import DEFAULT_BINARY_ADDRESS

def nonnegative_int(value):
    n = int(value)  # raises ValueError if not an int
    if n < 0:
        raise argparse.ArgumentTypeError(f"must be a non-negative integer, got {value}")
    return n

def existing_path(value):
    p = Path(value)
    if not p.exists():
        raise argparse.ArgumentTypeError(f"path does not exist: {value}")
    return p

def hex_or_dec(value):
    try:
        out = int(value, 0)
        if out < 0:
            argparse.ArgumentTypeError(f"must not be negative, got: {out}")
        return out  # 0 means auto-detect: 0x prefix = hex, otherwise decimal
    except ValueError:
        raise argparse.ArgumentTypeError(f"must be a hex (0x...) or decimal integer, got: {value}")


parser = argparse.ArgumentParser(description="Automatically finds hardware security vulnerabilities in binaries.  Only support ARM.")
parser.add_argument("binary_path", type=existing_path, help="The binary to examine")
parser.add_argument("input_path", type=existing_path, help="The path to the input to the program")
parser.add_argument("-s", "--simulate", type=nonnegative_int, metavar="INDEX", default=None, help="Runs a Unicorn simulation with the fault at a clock cycle.  Ignores all other flags besides --max_iterations and --verbose.")
parser.add_argument("-i", "--max-iterations", type=nonnegative_int, default=10000, help="The maximum number of instructions to run in the binary before ending early")
parser.add_argument("-o", "--expected-output", type=existing_path, default=None, help="The expected output of the program on a successful security incident")
parser.add_argument("-e", "--expected-exit", type=existing_path, default=None, help="The expected exit of the program on a successful security incident")
parser.add_argument("-d", "--desired-pc", type=hex_or_dec, default=None, help="The program counter we desire to achieve if possible.  In hex or decimal.  Keep in mind that this is the absolute address, not relative to the binary.")
parser.add_argument("-v", "--verbose", action="count", default=0, help="Verbosity: warning, info, debug")
parser.add_argument("-n", "--no-thumb", action="store_true", default=False, help="Whether or not to run in thumb mode")
parser.add_argument("-t", "--types", type=int, default=1, help="Which types of instructions to focus on.  0) Brute force: every clock cycle.  1) Recommended defaults.  2) Only conditional branches.  3) Only compare/tests.  4) Only returns.  5) Only branches, calls, returns, and compares")
parser.add_argument("-b", "--binary-addr", type=hex_or_dec, default=DEFAULT_BINARY_ADDRESS, help=f"The address to flash the binary to.  Defaults to {hex(DEFAULT_BINARY_ADDRESS)}.  Can be in hex or decimal.")
args = parser.parse_args()

print(
"▄▖    ▜ ▗   ▄▖   ▘    ▗ ▘      ▄▖▘   ▌     \n" +
"▙▖▀▌▌▌▐ ▜▘  ▐ ▛▌ ▌█▌▛▘▜▘▌▛▌▛▌  ▙▖▌▛▌▛▌█▌▛▘ \n" +
"▌ █▌▙▌▐▖▐▖  ▟▖▌▌ ▌▙▖▙▖▐▖▌▙▌▌▌  ▌ ▌▌▌▙▌▙▖▌  \n" +
"                ▙▌                         \n"
)

logging.basicConfig(
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.WARNING
)

logger = logging.getLogger("FaultInjectionFinder")
logger.setLevel(max(logging.WARNING - 10 * args.verbose, logging.DEBUG))

# read input
bin_in = b''
expected_output = None
with open(args.input_path, "rb") as file:
    bin_in = file.read()

if args.expected_output is not None:
    with open(args.expected_output, "rb") as file:
        expected_output = file.read()

finder = FaultInjectionFinder(binary_path=args.binary_path,
                              input=bin_in,
                              expected_output=expected_output,
                              expected_exit=args.expected_exit,
                              desired_pc=args.desired_pc,
                              enable_thumb=(not args.no_thumb),
                              max_iter=args.max_iterations,
                              user_sel=args.types,
                              binary_addr=args.binary_addr)

if args.simulate is not None:
    # only simulate
    finder.simulate_fault(bin_in, index=args.simulate)
    quit()

for fault in finder.find_faults():
    i, fault_cycle, insns, output, exit_code, regs, pc_control, trigger, input_to_pc = fault

    print("=" * 50)
    print(f"Fault target address: 0x{i:x}")
    print(f"Fault cycle estimate: {fault_cycle}")
    print("\nInstruction(s):")
    for insn in insns:
        print(f"  0x{insn.address:x}: {insn.mnemonic} {insn.op_str}")
    if trigger:
        print("Fault was manually triggered")

    print("\nExit Code:")
    print(f"  {exit_code}")

    print("\nOutput:")
    print(f"  {output!r}")

    # print("\nRegisters:")
    # for reg in regs.keys():
    #     val = regs[reg]
    #     print(f"  {reg:>8}: 0x{val:08x} ({val})")

    if pc_control:
        print("Got control of the PC")
        if input_to_pc is not None:
            print("!" * 10)
            print(f"By giving an input of {input_to_pc}, we get the desired PC value of {finder.desired_pc}")
            print("!" * 10)
        elif finder.desired_pc is not None:
            print(f"Unable to find a suitable input to get the desired PC value")

    print()

# ./binaries/infinite_loop.bin ./inputs/infinite_loop.bin -o ./expecteds/infinite_loop.bin
# finder = FaultInjectionFinder('./binaries/infinite_loop.bin', input=b'whatever', expected_output=b'escaped the loop')

# ./binaries/password.bin ./inputs/password.bin -o ./expecteds/password.bin -e 0
# finder = FaultInjectionFinder('./binaries/password.bin', input=b'a' * 99, expected_output=b'access granted.', expected_exit=0)

# ./binaries/pc_test.bin ./inputs/pc_test.bin -d 0x100007C
# finder = FaultInjectionFinder('./binaries/pc_test.bin', input=b'0' * 4, desired_pc=DEFAULT_BINARY_ADDRESS + 0x7c)

# ./binaries/pc_test_complex.bin ./inputs/pc_test_complex.bin -d 0x100007C
# finder = FaultInjectionFinder('./binaries/pc_test_complex.bin', input=b'0' * 4, desired_pc=DEFAULT_BINARY_ADDRESS + 0xb0)

# ./binaries/sha256.bin ./inputs/sha256.bin -d 0x10002B8
# finder = FaultInjectionFinder('./binaries/sha256.bin', input=b'1' * 16, desired_pc=DEFAULT_BINARY_ADDRESS + 0x2b8)

# ./binaries/aes_ecb.bin ./inputs/aes_ecb.bin -d 0x1002358
# finder = FaultInjectionFinder('./binaries/aes_ecb.bin', input=b'a' * 16, desired_pc=DEFAULT_BINARY_ADDRESS + 0x2358)

# ./binaries/constraints.bin ./inputs/constraints.bin -d 0x10000b0
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
