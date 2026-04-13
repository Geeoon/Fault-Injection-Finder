import logging
logging.basicConfig(
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.INFO
)

from FaultInjectionFinder import FaultInjectionFinder

# finder = FaultInjectionFinder('./binaries/infinite_loop.bin', input=b'whatever', expected_output=b'escaped the loop')
finder = FaultInjectionFinder('./binaries/password.bin', input=b'wrong\n', expected_exit=0)

for fault in finder.find_faults():
    print(fault)
