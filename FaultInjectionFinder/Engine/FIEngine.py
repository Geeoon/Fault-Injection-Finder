import logging

from unicorn import *
from capstone import *

R = [getattr(arm_const, f"UC_ARM_REG_R{i}") for i in range(13)]
PC = arm_const.UC_ARM_REG_PC
LR = arm_const.UC_ARM_REG_LR
SP = arm_const.UC_ARM_REG_SP
NOP = b"\x00\xf0\x20\xe3"

class InvalidFetch(Exception):
    """
    Exception raised for invalid fetches
    """
    pass

class FIEngine():
    """
    The main driver for running binaries with faults.
    Only supports ARM64 (AArch64) binaries.
    """
    def __init__(self, binary: bytes, input: bytes, BINARY_ADDRESS: int=0x0, BINARY_MAX_SIZE: int=0x10000, RAM_ADDRESS: int=0x2000000, RAM_SIZE: int=0x10000, EXIT_ADDRESS: int=0x3000000, RW_ADDRESS: int=0x3001000):
        """
        :param binary: the binary to examine
        """
        self.md = Cs(CS_ARCH_ARM, CS_MODE_ARM)  # initialize capstone disassembler
        self.binary = binary
        self.input = input
        self._mutated_input = input
        self.BINARY_ADDRESS = BINARY_ADDRESS
        self.BINARY_MAX_SIZE = BINARY_MAX_SIZE
        self.RAM_ADDRESS = RAM_ADDRESS
        self.RAM_SIZE = RAM_SIZE
        self.EXIT_ADDRESS = EXIT_ADDRESS
        self.RW_ADDRESS = RW_ADDRESS

    def _init_emulator(self):
        # reset emulator
        self.output = b''
        self.exit_code = None
        self._mutated_input = self.input
        self._invalid_fetch = None
        self._create_unicorn()
        self.mu.reg_write(SP, self.RAM_ADDRESS + self.RAM_SIZE)  # set the stack pointer to the top of our RAM
        self.mu.reg_write(PC, 0x0)  # reset PC to start of binary
        self.mu.reg_write(LR, 0x0)  # reset LR
        # reset all general purpose registers
        for reg in R:
            self.mu.reg_write(reg, 0x0)

    def _create_unicorn(self):
        # initalize emulator
        self.mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        self.mu.mem_map(self.BINARY_ADDRESS, self.BINARY_MAX_SIZE, UC_PROT_READ | UC_PROT_EXEC)  # map the binary as read and execute only
        self.mu.mem_map(self.RAM_ADDRESS, self.RAM_SIZE, UC_PROT_READ | UC_PROT_WRITE)  # map RAM as read and write only  (maybe add execute for fun?)
        self.mu.mem_map(self.EXIT_ADDRESS, 0x1000, UC_PROT_WRITE)  # add exit hook to memory map
        self.mu.mem_map(self.RW_ADDRESS, 0x1000, UC_PROT_READ | UC_PROT_WRITE)  # add IO hook to memory map
        self.mu.hook_add(UC_HOOK_MEM_WRITE, self._exit_hook, begin=self.EXIT_ADDRESS, end=self.EXIT_ADDRESS + 0x4)  # add hook for exit
        self.mu.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, self._rw_hook, begin=self.RW_ADDRESS, end=self.RW_ADDRESS)  # add hook for IO read/write
        self.mu.hook_add(UC_HOOK_MEM_INVALID, self._mem_invalid_hook)

    def _to_signed_32(self, unsigned_val) -> int:
        # If the value is greater than or equal to 2^31, it's negative in 2's complement
        if unsigned_val >= 0x80000000:
            return unsigned_val - 0x100000000
        return unsigned_val
    
    def _flip_bits(self, input: bytes) -> bytes:
        out = b''
        for byte in input:
            out += bytes(byte ^ 0xFF)
        return out
    
    def _exit_hook(self, mu, access, address, size, value, user_data) -> bool:
        value = self._to_signed_32(value)
        logging.info(f"Emulation stopped with exit code {value}")
        self.exit_code = value
        mu.emu_stop()
        return True

    def _rw_hook(self, mu, access, address, size, value, user_data) -> bool:
        if access == UC_MEM_WRITE:
            logging.debug(f"IO write: {value.to_bytes(1)}")
            self.output += value.to_bytes(1)
        elif access == UC_MEM_READ:
            if self._mutated_input:
                data = (self._mutated_input[0]).to_bytes(1)
                self._mutated_input = self._mutated_input[1:]
            else:
                logging.debug("Ran out of input, sending null bytes")
                data = b'\0'
            logging.debug(f"IO read, sending {data}")
            mu.mem_write(self.RW_ADDRESS, data)
        return True
    
    def _mem_invalid_hook(self, mu, access, address, size, value, user_data) -> bool:
        if access == UC_MEM_FETCH_UNMAPPED:
            logging.warning(f"Fetch from unmapped address: {hex(address)}")
            if self._invalid_fetch is None:
                self._invalid_fetch = address  # store the invalid access
                # we will re-run this case with a different input and see if 
                # we are able to influence the program counter
            else:
                # has our input influenced the PC?
                self._pc_control = self._invalid_fetch == address
            self.mu.emu_stop()
            return False
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
        self._init_emulator()

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

        # write the binary to memory
        self.mu.mem_write(self.BINARY_ADDRESS, bytes(code_arr))  # write our binary to memory

        # used for keeping track of whether our input influences the PC
        self._pc_control = False
        try:
            try:
                self.mu.emu_start(self.BINARY_ADDRESS, 0xFFFFFFFF, count=max_iter) # `until` set to non existant address to run until exit or max_iter
            except UcError as e:
                if e.errno == UC_ERR_FETCH_UNMAPPED:
                    raise InvalidFetch
                logging.error(f"Emulator crashed (likely just due to the binary being corrupted): {str(e)}")
        except InvalidFetch as e:
            logging.info(f"Emulator fetched invalid instruction.  Trying again with a different input.")
            self._init_emulator()
            # flip all bits for normal input
            self._mutated_input = self._flip_bits(self.input)
            self._pc_control = True
            try:
                self.mu.emu_start(self.BINARY_ADDRESS, 0xFFFFFFFF, count=max_iter) # `until` set to non existant address to run until exit or max_iter
            except UcError as e:
                if e.errno == UC_ERR_FETCH_UNMAPPED:
                    pass
                logging.error(f"Emulator crashed (likely just due to the binary being corrupted): {str(e)}")
                
        if self.exit_code is None:
            logging.debug("Emulation reached max iterations instead (i.e., the program did not exit in time)")

        # get registers
        final_registers = {}
        for i in range(len(R)):
            final_registers[f'R{i}'] = self.mu.reg_read(R[i])
        return decoded, self.output, self.exit_code, final_registers, self._pc_control

        # print registers
        # logging.info("Emulation done. Below is the CPU context")
        # for i in range(4): logging.info(f">>> R{i} = 0x{self.mu.reg_read(R[i]):x}")
        
