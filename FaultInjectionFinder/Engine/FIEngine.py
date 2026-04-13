import logging

from unicorn import *
from capstone import *


R = [getattr(arm_const, f"UC_ARM_REG_R{i}") for i in range(13)]
PC = arm_const.UC_ARM_REG_PC
LR = arm_const.UC_ARM_REG_LR
SP = arm_const.UC_ARM_REG_SP
NOP = b"\x00\xf0\x20\xe3"

BINARY_ADDRESS = 0x1000000  # start address of the binary in our emulator's memory
BINARY_MAX_SIZE = 0x10000  # allow binaries up to 64KiB

RAM_ADDRESS = 0x2000000  # start address of the RAM avaible to the program
RAM_SIZE = 0x10000  # allocate 64KiB for RAM

EXIT_ADDRESS = 0x10000  # special address for hooking into exits
RW_ADDRESS = 0x11000  # special address for hooking into IO read and write operations

class FIEngine():
    """
    The main driver for running binaries with faults.
    Only supports ARM64 (AArch64) binaries.
    """
    def __init__(self, binary: bytes):
        """
        :param binary: the binary to examine
        """
        logging.debug("init!")
        # initalize emulator and capstone disassembler 
        self.md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
        self.mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        self.mu.mem_map(BINARY_ADDRESS, BINARY_MAX_SIZE, UC_PROT_READ | UC_PROT_EXEC)  # map the binary as read and execute only
        self.mu.mem_map(RAM_ADDRESS, RAM_SIZE, UC_PROT_READ | UC_PROT_WRITE)  # map RAM as read and write only  (maybe add execute for fun?)
        self.mu.mem_map(EXIT_ADDRESS, 0x1000, UC_PROT_WRITE)  # add exit hook to memory map
        self.mu.mem_map(RW_ADDRESS, 0x1000, UC_PROT_READ | UC_PROT_WRITE)  # add IO hook to memory map
        self.mu.hook_add(UC_HOOK_MEM_WRITE, self._exit_hook, begin=EXIT_ADDRESS, end=EXIT_ADDRESS + 0x4)  # add hook for exit
        self.mu.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, self._rw_hook, begin=RW_ADDRESS, end=RW_ADDRESS)  # add hook for IO read/write
        self.mu.hook_add(UC_HOOK_MEM_INVALID, self._mem_invalid_hook)
        self.binary = binary
    
    def _exit_hook(self, mu, access, address, size, value, user_data) -> bool:
        logging.info(f"Emulation stopped with exit code {value}")
        self.exit_code = value
        mu.emu_stop()
        return True

    def _rw_hook(self, mu, access, address, size, value, user_data) -> bool:
        if access == UC_MEM_WRITE:
            logging.info(f"IO write: {chr(value)}")
        elif access == UC_MEM_READ:
            data = b'A'
            logging.info(f"IO read, sending {data}")
            mu.mem_write(RW_ADDRESS, data)
        return True
    
    def _mem_invalid_hook(self, mu, access, address, size, value, user_data) -> bool:
        if access == UC_MEM_FETCH_UNMAPPED:
            logging.critical(f"Fetch from unmapped address: {hex(address)}")
        elif access == UC_MEM_READ_UNMAPPED:
            logging.critical(f"Read from unmapped address: {hex(address)}")
        elif access == UC_MEM_WRITE_UNMAPPED:
            logging.critical(f"Write to unmapped address: {hex(address)}")
        return False
    
    def run(self, fault_index: int=None, max_iter: int=1000):
        """
        Runs the binary with an optional fault index
        :param fault_index: the instruction to fault (0 being the first instruction in the binary)
        :param max_iter: the max number of iterations to run the program for.  Set to 0 to run until exit
        """
        # convert to byte array so we can mutate it
        code_arr = bytearray(self.binary)

        # add a NOP fault, if given
        if fault_index is not None:
            byte_offset = fault_index * 4
            code_arr[byte_offset:byte_offset + 4] = NOP

        # write the binary to memory
        self.mu.mem_write(BINARY_ADDRESS, bytes(code_arr))  # write our binary to memory
        self.mu.reg_write(SP, RAM_ADDRESS + RAM_SIZE) # set the stack pointer to the top of our RAM

        logging.info("Starting the emulation")
        self.mu.emu_start(BINARY_ADDRESS, 0xFFFFFFFF, count=max_iter) # stops after 100 instructions, `until` set to non existant address

        # print registers
        logging.info("Emulation done. Below is the CPU context")
        for i in range(4): logging.info(f">>> R{i} = 0x{self.mu.reg_read(R[i]):x}")
        
