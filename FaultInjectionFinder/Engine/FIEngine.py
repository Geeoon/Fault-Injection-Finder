import logging

from unicorn import *
from capstone import *

R = [getattr(arm_const, f"UC_ARM_REG_R{i}") for i in range(13)]
PC = arm_const.UC_ARM_REG_PC
LR = arm_const.UC_ARM_REG_LR
SP = arm_const.UC_ARM_REG_SP
NOP = b"\x00\xf0\x20\xe3"
THUMB_NOP = b"\x00\xbf"  # ARMv6 Thumb

DEFAULT_BINARY_ADDRESS = 0x1000000
DEFAULT_BINARY_MAX_SIZE = 0x10000
DEFAULT_RAM_ADDRESS = 0x2000000
DEFAULT_RAM_SIZE = 0x10000
DEFAULT_EXIT_ADDRESS = 0x3000000
DEFAULT_RW_ADDRESS = 0x3001000
DEFAULT_FAULT_ADDRESS = 0x3002000

class InvalidFetch(Exception):
    """
    Exception raised for invalid fetches
    """
    pass

class FaultDetected(Exception):
    """
    Exception raised when the fault detection is tripped
    """
    pass

class FIEngine():
    """
    The main driver for running binaries with faults.
    Only supports ARM64 (AArch64) binaries.
    """
    def __init__(self,
                 binary: bytes,
                 input: bytes,
                 BINARY_ADDRESS: int=DEFAULT_BINARY_ADDRESS,
                 BINARY_MAX_SIZE: int=DEFAULT_BINARY_MAX_SIZE,
                 RAM_ADDRESS: int=DEFAULT_RAM_ADDRESS,
                 RAM_SIZE: int=DEFAULT_RAM_SIZE,
                 EXIT_ADDRESS: int=DEFAULT_EXIT_ADDRESS,
                 RW_ADDRESS: int=DEFAULT_RW_ADDRESS,
                 FAULT_ADDRESS: int=DEFAULT_FAULT_ADDRESS,
                 enable_thumb: bool=True):
        """
        :param binary: the binary to examine
        :param BINARY_ADDRESS: the address where the binary should be loaded
        :param BINARY_MAX_SIZE: the size of flash allocated for the binary
        :param RAM_ADDRESS: the starting address of the RAM
        :param RAM_SIZE: the size of available RAM for emulation
        :param EXIT_ADDRESS: the address that should be written for an exit
        :param RW_ADDRESS: the IO address
        :param FAULT_ADDRESS: the address that should be written to in the event of a successful fault
        :param enable_thumb: whether or not to run as ARMv6 Thumb
        """
        self.thumb = enable_thumb
        if self.thumb:
            self.nop = THUMB_NOP
            self.md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)  # initialize capstone disassembler for ARMv6 Thumb
            self.INSTRUCTION_SIZE = 2
        else:
            self.nop = NOP
            self.md = Cs(CS_ARCH_ARM, CS_MODE_ARM)  # initialize capstone disassembler
            self.INSTRUCTION_SIZE = 4
        self.binary = binary
        self.input = input
        self._mutated_input = input
        self.BINARY_ADDRESS = BINARY_ADDRESS
        self.BINARY_MAX_SIZE = BINARY_MAX_SIZE
        self.RAM_ADDRESS = RAM_ADDRESS
        self.RAM_SIZE = RAM_SIZE
        self.EXIT_ADDRESS = EXIT_ADDRESS
        self.RW_ADDRESS = RW_ADDRESS
        self.FAULT_ADDRESS = FAULT_ADDRESS

    def _init_emulator(self, index):
        # reset emulator
        self.output = b''
        self.exit_code = None
        self._mutated_input = self.input
        self._invalid_fetch = None
        self._create_unicorn()
        self.mu.reg_write(SP, self.RAM_ADDRESS + self.RAM_SIZE)  # set the stack pointer to the top of our RAM
        self.mu.reg_write(PC, self.BINARY_ADDRESS | 1 if self.thumb else self.BINARY_ADDRESS)  # reset PC to start of binary
        self.mu.reg_write(LR, 0x0)  # reset LR
        # reset all general purpose registers
        for reg in R:
            self.mu.reg_write(reg, 0x0)
        self._skip_index = index
        self._instruction_count = 0
        self.trigger = False

    def _create_unicorn(self):
        # initalize emulator
        if self.thumb:
            self.mu = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS)  # ARMv6 Thumb
        else:
            self.mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        self.mu.mem_map(self.BINARY_ADDRESS, self.BINARY_MAX_SIZE, UC_PROT_READ | UC_PROT_EXEC)  # map the binary as read and execute only
        self.mu.mem_map(self.RAM_ADDRESS, self.RAM_SIZE, UC_PROT_READ | UC_PROT_WRITE)  # map RAM as read and write only  (maybe add execute for fun?)
        self.mu.mem_map(self.EXIT_ADDRESS, 0x1000, UC_PROT_WRITE)  # add exit hook to memory map
        self.mu.mem_map(self.RW_ADDRESS, 0x1000, UC_PROT_READ | UC_PROT_WRITE)  # add IO hook to memory map
        self.mu.mem_map(self.FAULT_ADDRESS, 0x1000, UC_PROT_WRITE)  # fault hook to memory map
        self.mu.hook_add(UC_HOOK_MEM_WRITE, self._exit_hook, begin=self.EXIT_ADDRESS, end=self.EXIT_ADDRESS + 0x4)  # add hook for exit
        self.mu.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, self._rw_hook, begin=self.RW_ADDRESS, end=self.RW_ADDRESS)  # add hook for IO read/write
        self.mu.hook_add(UC_HOOK_MEM_WRITE, self._fault_hook, begin=self.FAULT_ADDRESS, end=self.FAULT_ADDRESS + 0x4)  # add hook for fault detection
        self.mu.hook_add(UC_HOOK_MEM_INVALID, self._mem_invalid_hook)
        self.mu.hook_add(UC_HOOK_CODE, self._instr_hook)  # hook for every instruction, this is the bottleneck for speed

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

    def _instr_hook(self, mu, address, size, user_data):
        self._instruction_count += 1
        if self._instruction_count == self._skip_index:
            decoded = list(self.md.disasm(mu.mem_read(address, size), 0x0))
            if not decoded:
                logging.error("Could not decode the instruction to be skipped")
                mu.emu_stop()
            else:
                self._decoded = decoded
                logging.debug(f"Skipping 0x{address:x}: {self._decoded[0].mnemonic} {self._decoded[0].op_str} at \"clock cycle\" number {self._instruction_count}.")
                mu.reg_write(PC, (address+size) | (1 if self.thumb else 0))

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
    
    def _fault_hook(self, mu, access, address, size, value, user_data) -> bool:
        self.trigger = True
        mu.emu_stop()
    
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

    def skip_instruction(self, binary: bytearray, index: int) -> tuple[bytes, list]:
        """
        Not used anymore
        """
        byte_offset = index * self.INSTRUCTION_SIZE
        decoded = list(self.md.disasm(binary[byte_offset:byte_offset + self.INSTRUCTION_SIZE], 0x0))
        if not decoded:
            logging.error("Could not decode the instruction to be skipped")
        else:
            skipped_instruction = decoded[0]
            logging.debug(f"Injecting a fault at {index}, replacing {skipped_instruction.mnemonic} {skipped_instruction.op_str} with NOP")
        binary[byte_offset:byte_offset + self.INSTRUCTION_SIZE] = self.nop
        return bytes(binary), decoded
    
    def run(self, fault_index: int=None, max_iter: int=1000):
        """
        Runs the binary with an optional fault index
        :param fault_index: the instruction to fault (0 being the first instruction in the binary)
        :param max_iter: the max number of iterations to run the program for.  Set to 0 to run until exit
        """
        logging.debug("Starting the emulation")
        self._init_emulator(fault_index)

        self._decoded = None  # gets set by the instruction hook

        # write the binary to memory
        self.mu.mem_write(self.BINARY_ADDRESS, self.binary)  # write our binary to memory

        # used for keeping track of whether our input influences the PC
        self._pc_control = False
        self._old_pc = None
        try:
            try:
                self.mu.emu_start(self.BINARY_ADDRESS | 1 if self.thumb else self.BINARY_ADDRESS, 0xFFFFFFFF, count=max_iter) # `until` set to non existant address to run until exit or max_iter
            except UcError as e:
                if e.errno == UC_ERR_FETCH_UNMAPPED:
                    raise InvalidFetch
                logging.error(f"Emulator crashed (likely just due to the binary being corrupted): {str(e)}")
        except InvalidFetch as e:
            logging.info(f"Emulator fetched invalid instruction.  Trying again with a different input.")
            self._old_pc = self.mu.reg_read(PC)
            self._init_emulator(fault_index)
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
            logging.debug("Program did not exit (emulation stopped before program exit).")

        # get registers
        final_registers = {}
        for i in range(len(R)):
            final_registers[f'R{i}'] = self.mu.reg_read(R[i])
        final_registers['PC'] = self.mu.reg_read(PC)
        if self._pc_control:
            final_registers['Old PC'] = self._old_pc
        return self._decoded, self.output, self.exit_code, final_registers, self._pc_control, self.trigger

        # print registers
        # logging.info("Emulation done. Below is the CPU context")
        # for i in range(4): logging.info(f">>> R{i} = 0x{self.mu.reg_read(R[i]):x}")
        
