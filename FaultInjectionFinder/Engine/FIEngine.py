import logging
from unicorn import *
from capstone import *

R = [getattr(arm_const, f"UC_ARM_REG_R{i}") for i in range(13)]
PC = arm_const.UC_ARM_REG_PC
LR = arm_const.UC_ARM_REG_LR
SP = arm_const.UC_ARM_REG_SP

DEFAULT_BINARY_ADDRESS = 0x1000000
DEFAULT_BINARY_MAX_SIZE = 0x10000
DEFAULT_RAM_ADDRESS = 0x2000000
DEFAULT_RAM_SIZE = 0x10000
DEFAULT_EXIT_ADDRESS = 0x3000000
DEFAULT_RW_ADDRESS = 0x3001000
DEFAULT_FAULT_ADDRESS = 0x3002000
DEFAULT_TRIGGER_ADDRESS = 0x3003000

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
                 TRIGGER_ADDRESS: int=DEFAULT_TRIGGER_ADDRESS,
                 start_thumb: bool=True,
                 skip_addrs: list[int]=None,
                 addr_range: tuple[int, int]=None):
        """
        :param binary: the binary to examine
        :param BINARY_ADDRESS: the address where the binary should be loaded
        :param BINARY_MAX_SIZE: the size of flash allocated for the binary
        :param RAM_ADDRESS: the starting address of the RAM
        :param RAM_SIZE: the size of available RAM for emulation
        :param EXIT_ADDRESS: the address that should be written for an exit
        :param RW_ADDRESS: the IO address
        :param FAULT_ADDRESS: the address that should be written to in the event of a successful fault
        :param TRIGGER_ADDRESS: the address that should be written to to signify a trigger
        :param start_thumb: whether or not to start in thumb mode
        :param skip_addrs: a list of addresses to skip, if ran into at or after fault_index.  None to do skip at the exact address
        """
        self.start_thumb = start_thumb
        self.md = Cs(CS_ARCH_ARM, CS_MODE_THUMB if self.start_thumb else CS_MODE_ARM)  # initialize capstone, NOTE: thumb selection doesn't matter since we change it per instruction
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
        self.TRIGGER_ADDRESS = TRIGGER_ADDRESS
        self.is_done = False
        self.logger = logging.getLogger(__name__)
        self.skip_addrs = skip_addrs
        self.addr_range = addr_range

    def _init_emulator(self, index):
        # reset emulator
        self._input = b''
        self.output = b''
        self.exit_code = None
        self._mutated_input = self.input
        self._invalid_fetch = None
        self._create_unicorn()
        self.mu.reg_write(SP, self.RAM_ADDRESS + self.RAM_SIZE)  # set the stack pointer to the top of our RAM
        self.mu.reg_write(PC, self.BINARY_ADDRESS | (1 if self.start_thumb else 0))  # reset PC to start of binary
        self.mu.reg_write(LR, 0x0)  # reset LR
        # reset all general purpose registers
        for reg in R:
            self.mu.reg_write(reg, 0x0)
        self._skip_index = index
        self._skip_cycle = None           # runtime cycle when address was hit
        self._instruction_count = 0
        self.manual = False
        self.triggers = []


        # write the binary to memory
        self.mu.mem_write(self.BINARY_ADDRESS, self.binary)  # write our binary to memory
        self._decoded = None  # gets set by the instruction hook
        # used for keeping track of whether our input influences the PC
        self._pc_control = False

    def _create_unicorn(self):
        # initalize emulator
        self.mu = Uc(UC_ARCH_ARM, (UC_MODE_THUMB | UC_MODE_MCLASS) if self.start_thumb else UC_MODE_ARM)

        self.mu.mem_map(self.BINARY_ADDRESS, self.BINARY_MAX_SIZE, UC_PROT_READ | UC_PROT_EXEC)  # map the binary as read and execute only
        self.mu.mem_map(self.RAM_ADDRESS, self.RAM_SIZE, UC_PROT_READ | UC_PROT_WRITE)  # map RAM as read and write only  (maybe add execute for fun?)
        self.mu.mem_map(self.EXIT_ADDRESS, 0x1000, UC_PROT_WRITE)  # add exit hook to memory map
        self.mu.mem_map(self.RW_ADDRESS, 0x1000, UC_PROT_READ | UC_PROT_WRITE)  # add IO hook to memory map
        self.mu.mem_map(self.FAULT_ADDRESS, 0x1000, UC_PROT_WRITE)  # fault hook to memory map
        self.mu.mem_map(self.TRIGGER_ADDRESS, 0x1000, UC_PROT_WRITE)  # trigger hook to memory map
        self.mu.hook_add(UC_HOOK_MEM_WRITE, self._exit_hook, begin=self.EXIT_ADDRESS, end=self.EXIT_ADDRESS + 0x4)  # add hook for exit
        self.mu.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, self._rw_hook, begin=self.RW_ADDRESS, end=self.RW_ADDRESS)  # add hook for IO read/write
        self.mu.hook_add(UC_HOOK_MEM_WRITE, self._fault_hook, begin=self.FAULT_ADDRESS, end=self.FAULT_ADDRESS + 0x4)  # add hook for fault detection
        self.mu.hook_add(UC_HOOK_MEM_WRITE, self._trigger_hook, begin=self.TRIGGER_ADDRESS, end=self.TRIGGER_ADDRESS + 0x4)  # add hook for trigger
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
            out += (byte ^ 0xFF).to_bytes(1)
        return out

    def _instr_hook(self, mu, address, size, user_data):
        # NOTE: address's last bit does not correspond to "thumb" bit
        self._instruction_count += 1
        decoded = None
        is_thumb = mu.reg_read(arm_const.UC_ARM_REG_CPSR) & 0x20
        self.md.mode = CS_MODE_THUMB if is_thumb else CS_MODE_ARM
        if self.triggers and not self._skip_cycle:
            # decoding is a slow operation, only do it if necessary
            decoded = list(self.md.disasm(mu.mem_read(address, size), address))
            if not decoded:
                self.logger.error("Could not decode the instruction to be skipped")
                # shouldn't happen with our configuration
                mu.emu_stop()
                return False
            self.triggers[-1][2].append(decoded)
        # check _skip_cycle to prevent skipping multiple times
        if (self._skip_cycle is None) and (self._instruction_count >= self._skip_index) and ((self.addr_range is None) or ((address >= self.addr_range[0]) and (address <= self.addr_range[1]))):
            # we can now start skipping instructions, if they fit the criteria
            if self.skip_addrs is None or address in self.skip_addrs:
                # brute force or at the index we should skip
                self._skip_cycle = self._instruction_count
                self._skip_addr = address
                if not decoded:
                    decoded = list(self.md.disasm(mu.mem_read(address, size), address))
                    if not decoded:
                        self.logger.error("Could not decode the instruction to be skipped")
                        # shouldn't happen with our configuration
                        mu.emu_stop()
                        return False
                self._decoded = decoded
                self.logger.info(
                    f"Skipping 0x{address:x}: {self._decoded[0].mnemonic} "
                    f"{self._decoded[0].op_str} at runtime cycle {self._skip_cycle}."
                )
                mu.reg_write(PC, (address + size) | (1 if is_thumb else 0))


    def _exit_hook(self, mu, access, address, size, value, user_data) -> bool:
        value = self._to_signed_32(value)
        self.logger.debug(f"Emulation stopped with exit code {value}")
        self.exit_code = value
        mu.emu_stop()
        return True

    def _rw_hook(self, mu, access, address, size, value, user_data) -> bool:
        if access == UC_MEM_WRITE:
            self.logger.debug(f"IO write: {value.to_bytes(1)}")
            self.output += value.to_bytes(1)
        elif access == UC_MEM_READ:
            if self._mutated_input:
                data = (self._mutated_input[0]).to_bytes(1)
                self._mutated_input = self._mutated_input[1:]
            else:
                data = b'\xFF' if self._invalid_fetch is not None else b'\0'
                self.logger.debug(f"Ran out of input, sending {data}")
            self.logger.debug(f"IO read, sending {data}")
            self._input += data
            mu.mem_write(self.RW_ADDRESS, data)
        return True
    
    def _fault_hook(self, mu, access, address, size, value, user_data) -> bool:
        logging.debug("Hit manual fault.")
        self.manual = True
        mu.emu_stop()

    def _trigger_hook(self, mu, access, address, size, value, user_data) -> bool:
        self.triggers.append((self._instruction_count, self.mu.reg_read(PC), []))
        logging.debug("Hit trigger.")

    def _mem_invalid_hook(self, mu, access, address, size, value, user_data) -> bool:
        if access == UC_MEM_FETCH_UNMAPPED:
            self.logger.debug(f"Fetch from unmapped address: {hex(address)}")
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
            self.logger.debug(f"Read from unmapped address: {hex(address)}")
        elif access == UC_MEM_WRITE_UNMAPPED:
            self.logger.debug(f"Write to unmapped address: {hex(address)}")

    def run(self, fault_index: int=None, max_iter: int=100) -> tuple:
        """
        Runs the binary with an optional fault index
        :param fault_index: the instruction to fault (0 being the first instruction in the binary)
        :param max_iter: the max number of iterations to run the program for.  Set to 0 to run until exit
        """
        self.logger.info("Starting the emulation")
        self._init_emulator(fault_index)
        try:
            try:
                self.mu.emu_start((self.BINARY_ADDRESS) | (1 if self.start_thumb else 0), 0xFFFFFFFF, count=max_iter) # `until` set to non existant address to run until exit or max_iter
            except UcError as e:
                if e.errno == UC_ERR_FETCH_UNMAPPED:
                    raise InvalidFetch
                self.logger.debug(f"Emulator crashed (likely just due an invalid CPU state): {str(e)}")
        except InvalidFetch as e:
            self.logger.debug(f"Emulator fetched invalid instruction.  Trying again with a different input.")
            temp = self._invalid_fetch  # temporarily store, since _init_emulator will set it to None
            self._init_emulator(fault_index)
            self._invalid_fetch = temp
            # flip all bits for normal input
            self._mutated_input = self._flip_bits(self.input)
            self._pc_control = True
            try:
                self.mu.emu_start(self.BINARY_ADDRESS | (1 if self.start_thumb else 0), 0xFFFFFFFF, count=max_iter) # `until` set to non existant address to run until exit or max_iter
            except UcError as e:
                if e.errno == UC_ERR_FETCH_UNMAPPED:
                    pass
                self.logger.debug(f"Emulator crashed (likely just due an invalid CPU state): {str(e)}")                
        # if we exit without hittinig the glitch index, then there is no more to do
        self.is_done = (self._skip_cycle is None) or (self._skip_index > self._instruction_count)
        if self.is_done:
            self.logger.info("Ran without encountering an instruction to fault, this indicates the end of the search.")
            return None
        if self.exit_code is None:
            self.logger.debug("Program did not exit (emulation stopped before program exit).")
        if not self._decoded:
            self.logger.warning("Could not decode instruction, not attempting to find faults")
            return None
        
        # get registers
        final_registers = {}
        for i in range(len(R)):
            final_registers[f'R{i}'] = self.mu.reg_read(R[i])
        final_registers['PC'] = self.mu.reg_read(PC)
        return (
            self._decoded,
            self._skip_addr,
            self._input,
            self.output,
            self.exit_code,
            final_registers,
            self._pc_control,
            self.manual,
            self._skip_cycle,
            (self._skip_cycle + 1) if self._skip_cycle else None,
            self.triggers
        )
        # print registers
        # self.logger.info("Emulation done. Below is the CPU context")
        # for i in range(4): self.logger.info(f">>> R{i} = 0x{self.mu.reg_read(R[i]):x}")
        
