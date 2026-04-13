import logging
logging.basicConfig(
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.DEBUG
)

from FaultInjectionFinder import FaultInjectionFinder

finder = FaultInjectionFinder('./binaries/exit.bin')

finder.find_faults()
