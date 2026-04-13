import logging
logging.basicConfig(
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.INFO
)

from FaultInjectionFinder import FaultInjectionFinder

finder = FaultInjectionFinder('./binaries/infinite_loop.bin', b'whatever', b'escaped the loop')

for fault in finder.find_faults():
    print(fault)
