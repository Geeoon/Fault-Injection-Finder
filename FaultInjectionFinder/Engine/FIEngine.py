import logging

from unicorn import *
from capstone import *


R = [getattr(arm_const, f"UC_ARM_REG_R{i}") for i in range(13)]
PC = arm_const.UC_ARM_REG_PC
LR = arm_const.UC_ARM_REG_LR
SP = arm_const.UC_ARM_REG_SP
NOP = b"\x00\xf0\x20\xe3"

BINARY_ADDRESS = 0x0  # start address of the binary in our emulator's memory
BINARY_MAX_SIZE = 0x10000  # allow binaries up to 64KiB

RAM_ADDRESS = 0x2000000  # start address of the RAM avaible to the program
RAM_SIZE = 0x10000  # allocate 64KiB for RAM

EXIT_ADDRESS = 0x3000000  # special address for hooking into exits
RW_ADDRESS = 0x3001000  # special address for hooking into IO read and write operations

class FIEngine():
    """
    The main driver for running binaries with faults.
    Only supports ARM64 (AArch64) binaries.
    """
    def __init__(self, binary: bytes, input: bytes):
        """
        :param binary: the binary to examine
        """
        self.md = Cs(CS_ARCH_ARM, CS_MODE_ARM)  # initialize capstone disassembler
        self.binary = binary
        self.input = input

    def _create_unicorn(self):
        # initalize emulator
        self.mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        self.mu.mem_map(BINARY_ADDRESS, BINARY_MAX_SIZE, UC_PROT_READ | UC_PROT_EXEC)  # map the binary as read and execute only
        self.mu.mem_map(RAM_ADDRESS, RAM_SIZE, UC_PROT_READ | UC_PROT_WRITE)  # map RAM as read and write only  (maybe add execute for fun?)
        self.mu.mem_map(EXIT_ADDRESS, 0x1000, UC_PROT_WRITE)  # add exit hook to memory map
        self.mu.mem_map(RW_ADDRESS, 0x1000, UC_PROT_READ | UC_PROT_WRITE)  # add IO hook to memory map
        self.mu.hook_add(UC_HOOK_MEM_WRITE, self._exit_hook, begin=EXIT_ADDRESS, end=EXIT_ADDRESS + 0x4)  # add hook for exit
        self.mu.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, self._rw_hook, begin=RW_ADDRESS, end=RW_ADDRESS)  # add hook for IO read/write
        self.mu.hook_add(UC_HOOK_MEM_INVALID, self._mem_invalid_hook)
        self.mu.reg_write(SP, RAM_ADDRESS + RAM_SIZE)  # set the stack pointer to the top of our RAM

    def _to_signed_32(self, unsigned_val):
        # If the value is greater than or equal to 2^31, it's negative in 2's complement
        if unsigned_val >= 0x80000000:
            return unsigned_val - 0x100000000
        return unsigned_val
    
    def _exit_hook(self, mu, access, address, size, value, user_data) -> bool:
        value = self._to_signed_32(value)
        logging.debug(f"Emulation stopped with exit code {value}")
        self.exit_code = value
        mu.emu_stop()
        return True

    def _rw_hook(self, mu, access, address, size, value, user_data) -> bool:
        if access == UC_MEM_WRITE:
            logging.debug(f"IO write: {value.to_bytes(1)}")
            self.output += value.to_bytes(1)
        elif access == UC_MEM_READ:
            if self.input:
                data = (self.input[0]).to_bytes(1)
                self.input = self.input[1:]
            else:
                data = b'\0'
            logging.debug(f"IO read, sending {data}")
            mu.mem_write(RW_ADDRESS, data)
        return True
    
    def _mem_invalid_hook(self, mu, access, address, size, value, user_data) -> bool:
        if access == UC_MEM_FETCH_UNMAPPED:
            logging.warning(f"Fetch from unmapped address: {hex(address)}")
        elif access == UC_MEM_READ_UNMAPPED:
            logging.warning(f"Read from unmapped address: {hex(address)}")
        elif access == UC_MEM_WRITE_UNMAPPED:
            logging.warning(f"Write to unmapped address: {hex(address)}")
    
    def run(self, fault_index: int=None, max_iter: int=1000):
        """
        Runs the binary with an optional fault index
        :param fault_index: the instruction to fault (0 being the first instruction in the binary)
        :param max_iter: the max number of iterations to run the program for.  Set to 0 to run until exit
        """
        logging.debug("Starting the emulation")
        # reset emulator
        self.output = b''
        self.exit_code = None
        self._create_unicorn()

        # convert to byte array so we can mutate it
        code_arr = bytearray(self.binary)
        # add a NOP fault, if given
        if fault_index is not None:
            byte_offset = fault_index * 4
            decoded = list(self.md.disasm(code_arr[byte_offset:byte_offset + 4], 0x0))
            if not decoded:
                logging.error("Could not decode the instruction to be skipped")
            else:
                skipped_instruction = decoded[0]
                logging.debug(f"Injecting a fault at {fault_index}, replacing {skipped_instruction.mnemonic} {skipped_instruction.op_str} with NOP")
            code_arr[byte_offset:byte_offset + 4] = NOP
            # logging.debug(f"Injected fault, below is the new code with a NOP as the fault at index {fault_index}:")
            # for i in self.md.disasm(code_arr, 0x0):
            #     logging.debug("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))

        # write the binary to memory
        self.mu.mem_write(BINARY_ADDRESS, bytes(code_arr))  # write our binary to memory

        try:
            self.mu.emu_start(BINARY_ADDRESS, 0xFFFFFFFF, count=max_iter) # `until` set to non existant address to run until exit or max_iter
        except UcError as e:
            logging.error(f"Emulator crashed (likely just due to the binary being corrupted): {str(e)}")

        if self.exit_code is None:
            logging.debug("Emulation reached max iterations instead (i.e., the program did not exit in time)")

        # get registers
        final_registers = {}
        for i in range(len(R)):
            final_registers[f'R{i}'] = self.mu.reg_read(R[i])
        return decoded, self.output, self.exit_code, final_registers

        # print registers
        # logging.info("Emulation done. Below is the CPU context")
        # for i in range(4): logging.info(f">>> R{i} = 0x{self.mu.reg_read(R[i]):x}")
        
