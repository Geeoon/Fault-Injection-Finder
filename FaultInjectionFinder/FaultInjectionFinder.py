import logging

from FaultInjectionFinder.Engine import FIEngine

class FaultInjectionFinder():
    def __init__(self, binary_path: str):
        """
        Initializer for the FaultInjetionFinder
        :param binary_path: the path to the binary to examine
        """
        try:
            with open(binary_path, 'rb') as file:
                self.engine = FIEngine(binary=file.read())
        except Exception as e:
            logging.critical(f"Failed to load the binary into the FIEngine: {str(e)}")
            raise e

    def find_faults(self):
        self.engine.run(max_iter=100000)  # test run with no faults
