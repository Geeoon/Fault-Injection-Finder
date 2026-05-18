import logging

from FaultInjectionFinder.Engine import FIEngine, PCSolver, DEFAULT_BINARY_ADDRESS
from FaultInjectionFinder.PreProcessing import PreProcessing

class FaultInjectionFinder():
    def __init__(
            self, 
            binary_path: str, 
            input: bytes, 
            expected_output: bytes=None, 
            expected_exit: int=None, 
            expected_regs: dict=None, 
            desired_pc: int=None, 
            enable_thumb: bool=True, 
            max_iter=20000, 
            user_sel: int = 1,
            binary_addr: int=DEFAULT_BINARY_ADDRESS,
            addr_range: tuple[int, int]=None
        ):
        """
        Initializer for the FaultInjetionFinder
        :param binary_path: the path to the binary to examine
        :param input: the input to give the binary, every time it does an IO read
        :param expected_output: the expected output of the program for a successful fault
        :param expected_exit: the expected exit code of the program for a successful fault
        :param expected_regs: the expected registers of the program for a successful fault
        :param desired_pc: the program counter we should try to set, if we have control
        :param enable_thumb: run the binary as thumb
        :param user_sel: options that th euser can specify
        :param binary_addr: the address where the start of the binary should be flashed to
        :param addr_range: the range of instructions to be searched
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
        self.thumb = enable_thumb
        self.desired_pc = desired_pc
        self.input = input
        self.max_iter = max_iter
        self.user_sel = user_sel
        self.binary_addr = binary_addr
        self.addr_range = addr_range

        try:
            with open(binary_path, 'rb') as file:
                self.binary = file.read()
        except Exception as e:
            logging.critical(f"Failed to load the binary into the FIEngine: {str(e)}")
            raise e

    def find_faults(self) -> list:
        skip_targets = None
        if self.user_sel:
            logging.info("Performing pre-processing...")
            # PreProcessing returns vulnerable instruction addresses.
            skip_targets = PreProcessing(
                binary=self.binary,
                user_sel=self.user_sel,
                start_addr=self.binary_addr,
                thumb=self.thumb
            ).instructions
            logging.info(f"Found {len(skip_targets)} vulnerable instructions to try.")

        self.engine = FIEngine(
            binary=self.binary,
            input=self.input,
            enable_thumb=self.thumb,
            BINARY_ADDRESS=self.binary_addr,
            skip_addrs=list(map(lambda target: target["address"] & ~1, skip_targets)) if skip_targets else None,
            addr_range=self.addr_range
        )
        logging.info("Searching for faults...")
        successes = []

        index = 0
        while not self.engine.is_done and index < self.max_iter:  # set hard limit in-case it goes forever
            res = self.engine.run(fault_index=index, max_iter=self.max_iter)
            if not res:
                break  # continue?
            skipped_instruction, skipped_addr, res_output, res_exit, res_regs, pc_control, manual, fault_cycle, next_index, triggers = res
            index = next_index

            # check if we got any actual results
            nothing_set = self.expected_exit is None and self.expected_output is None
            conditions_pass = (
                (self.expected_exit is None or self.expected_exit == res_exit) and
                (self.expected_output is None or self.expected_output in res_output)
            )

            if (nothing_set or not conditions_pass) and not pc_control and not manual:
                continue
            good_input = None
            if pc_control:
                if self.desired_pc is not None:
                    solver = PCSolver(
                        self.engine.binary,
                        fault_cycle,
                        len(self.input),
                        self.desired_pc,
                        enable_thumb=self.thumb,
                        BINARY_ADDRESS=self.binary_addr
                    )
                    good_input = solver.run(max_iter=self.max_iter)
            successes.append((
                skipped_addr,
                fault_cycle,
                skipped_instruction,
                res_output,
                res_exit,
                res_regs,
                pc_control,
                manual,
                good_input,
                triggers
            ))
        logging.info("Done searching for faults.")
        return successes

    def simulate_fault(self, real_input: bytes, index: int) -> tuple[bytes, int, bool]:
        """
        :param real_input: the input to actually give the program
        :param index: the clock cycle of the fault
        :return: the output of the program, exit code, manual?
        """
        self.engine = FIEngine(binary=self.binary, input=real_input, enable_thumb=self.thumb, BINARY_ADDRESS=self.binary_addr)
        logging.info("Simulating the fault...")
        skipped_instruction, skipped_addr, res_output, res_exit, res_regs, pc_control, manual, fault_cycle, next_index, triggers = self.engine.run(index, max_iter=self.max_iter)        
        logging.info("Simulation finished")
        return res_output, res_exit, manual
