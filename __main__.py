import logging
logging.basicConfig(
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.DEBUG
)

from FaultInjectionFinder import FaultInjectionFinder

finder = FaultInjectionFinder('./binaries/hello_world.bin')

finder.find_faults()
