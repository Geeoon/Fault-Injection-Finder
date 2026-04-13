import logging

from FaultInjectionFinder.Engine import FIEngine

class FaultInjectionFinder():
    def __init__(self, binary_path: str, input: bytes, expected_output: bytes=None, expected_exit: int=None, expected_regs: dict=None):
        """
        Initializer for the FaultInjetionFinder
        :param binary_path: the path to the binary to examine
        :param input: the input to give the binary, every time it does an IO read
        :param expected_output: the expected output of the program for a successful fault
        :param expected_exit: the expected exit code of the program for a successful fault
        :param expected_regs: the expected registers of the program for a successful fault
        
        If any of the expected value match, it is considered a success.  For expected_regs, only give the registers that are expected.
        Example:
        {
            'R0': 500,
            'R4': 350
        }
        If the end of the program has both R0 set to 500 AND R4 set to 350, then it will be considered a successful fault.
        The values in the other registers will be ignored.
        """
        if not expected_output and expected_exit is None and not expected_regs:
            raise Exception("At least one of the expected values needs to be set")
        self.expected_output = expected_output
        self.expected_exit = expected_exit
        self.expected_regs = expected_regs
        try:
            with open(binary_path, 'rb') as file:
                self.engine = FIEngine(binary=file.read(), input=input)
        except Exception as e:
            logging.critical(f"Failed to load the binary into the FIEngine: {str(e)}")
            raise e

    def find_faults(self):
        logging.info("Searching for faults...")
        successes = []
        for i in range(len(self.engine.binary) // 4):
            skipped_instruction, res_output, res_exit, res_regs, pc_control = self.engine.run(i, max_iter=1000000)
            if pc_control:
                successes.append((i, skipped_instruction, res_output, res_exit, res_regs, pc_control))
            elif self.expected_output and self.expected_output == res_output: 
                successes.append((i, skipped_instruction, res_output, res_exit, res_regs, pc_control))
            elif self.expected_exit is not None and self.expected_exit == res_exit: 
                successes.append((i, skipped_instruction, res_output, res_exit, res_regs, pc_control))
            elif self.expected_regs:  # todo: finish this
                pass
                # successes.append((skipped_instruction, res_output, res_exit, res_regs))
            
        logging.info("Done searching for faults.")
        return successes
                
