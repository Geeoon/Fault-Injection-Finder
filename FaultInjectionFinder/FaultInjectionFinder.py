import logging

from FaultInjectionFinder.Engine import FIEngine, PCSolver
from FaultInjectionFinder.Engine.FIEngine import INSTRUCTION_SIZE

class FaultInjectionFinder():
    def __init__(self, binary_path: str, input: bytes, expected_output: bytes=None, expected_exit: int=None, expected_regs: dict=None, desired_pc: int=None):
        """
        Initializer for the FaultInjetionFinder
        :param binary_path: the path to the binary to examine
        :param input: the input to give the binary, every time it does an IO read
        :param expected_output: the expected output of the program for a successful fault
        :param expected_exit: the expected exit code of the program for a successful fault
        :param expected_regs: the expected registers of the program for a successful fault
        :param desired_pc: the program counter we should try to set, if we have control
        
        If any of the expected value match, it is considered a success.  For expected_regs, only give the registers that are expected.
        Example:
        {
            'R0': 500,
            'R4': 350
        }
        If the end of the program has both R0 set to 500 AND R4 set to 350, then it will be considered a successful fault.
        The values in the other registers will be ignored.
        """
        self.expected_output = expected_output
        self.expected_exit = expected_exit
        self.expected_regs = expected_regs
        try:
            with open(binary_path, 'rb') as file:
                self.engine = FIEngine(binary=file.read(), input=input)
        except Exception as e:
            logging.critical(f"Failed to load the binary into the FIEngine: {str(e)}")
            raise e
        self.desired_pc = desired_pc
        self.input_len = len(input)

    def find_faults(self) -> list:
        logging.info("Searching for faults...")
        successes = []
        for i in range(len(self.engine.binary) // INSTRUCTION_SIZE):
            res = self.engine.run(i, max_iter=100000)
            if not res:  # skip if it didn't even run
                continue
            skipped_instruction, res_output, res_exit, res_regs, pc_control, trigger = res
            if trigger:
                successes.append((i, skipped_instruction, res_output, res_exit, res_regs, pc_control, trigger, None))
            elif pc_control:
                # solve for PC to see if we can
                binary, _ = self.engine.skip_instruction(bytearray(self.engine.binary), i)
                good_input = None
                if self.desired_pc is not None:
                    solver = PCSolver(binary, self.input_len, self.desired_pc)
                    good_input = solver.run()
                successes.append((i, skipped_instruction, res_output, res_exit, res_regs, pc_control, trigger, good_input))
            elif self.expected_output and self.expected_output in res_output: 
                successes.append((i, skipped_instruction, res_output, res_exit, res_regs, pc_control, trigger, None))
            elif self.expected_exit is not None and self.expected_exit == res_exit: 
                successes.append((i, skipped_instruction, res_output, res_exit, res_regs, pc_control, trigger, None))
            elif self.expected_regs:  # todo: finish this
                pass
                # successes.append((skipped_instruction, res_output, res_exit, res_regs))
            
        logging.info("Done searching for faults.")
        return successes
                
