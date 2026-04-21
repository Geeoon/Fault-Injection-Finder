"""
Constraint solver for finding inputs that set the PC equal to some value
"""
import logging

import angr
import claripy

from FaultInjectionFinder.Engine.FIEngine import DEFAULT_BINARY_ADDRESS, DEFAULT_BINARY_MAX_SIZE, DEFAULT_EXIT_ADDRESS, DEFAULT_FAULT_ADDRESS, DEFAULT_RAM_ADDRESS, DEFAULT_RAM_SIZE, DEFAULT_RW_ADDRESS

class PCSolver():
    """
    Given a binary, solve for what inputs could cause the PC equal to some value
    This is slower, so prefer using FIEngine until a proper instruction skip has been found
    """
    def __init__(self,
                 binary: bytes,
                 input_size: int,
                 desired_pc: int,
                 BINARY_ADDRESS: int=DEFAULT_BINARY_ADDRESS,
                 BINARY_MAX_SIZE: int=DEFAULT_BINARY_MAX_SIZE,
                 RAM_ADDRESS: int=DEFAULT_RAM_ADDRESS,
                 RAM_SIZE: int=DEFAULT_RAM_SIZE,
                 EXIT_ADDRESS: int=DEFAULT_EXIT_ADDRESS,
                 RW_ADDRESS: int=DEFAULT_RW_ADDRESS,
                 FAULT_ADDRESS: int=DEFAULT_FAULT_ADDRESS):
        """
        :param binary: the binary to solve for
        :param input_size: the size of the input
        :param desired_pc: the program counter we want to solve for
        :param BINARY_ADDRESS: the address where the binary should be loaded
        :param BINARY_MAX_SIZE: the size of flash allocated for the binary
        :param RAM_ADDRESS: the starting address of the RAM
        :param RAM_SIZE: the size of available RAM for emulation
        :param EXIT_ADDRESS: the address that should be written for an exit
        :param RW_ADDRESS: the IO address
        :param FAULT_ADDRESS: the address that should be written to in the event of a successful fault
        """
        self.desired_pc = desired_pc
        self.project = angr.load_shellcode(
            binary,
            arch='arm',
            start_offset=0,
            load_address=BINARY_ADDRESS
        )
        self.state = self.project.factory.blank_state(addr=BINARY_ADDRESS)
        self.state.regs.sp = RAM_ADDRESS + RAM_SIZE
        self.state.memory.store(RAM_ADDRESS, b'\x00' * RAM_SIZE)  # zero out RAM
        self.input_size = input_size
        # set up IO read hook
        self.RW_ADDRESS = RW_ADDRESS
        self.state.inspect.b(
            'mem_read',
            when=angr.BP_BEFORE,
            mem_read_address=RW_ADDRESS,
            mem_read_length=1,
            action=self._io_read_hook
        )
        # set up exit hook
        self.state.inspect.b(
            'mem_write',
            when=angr.BP_BEFORE,
            mem_write_address=EXIT_ADDRESS,
            action=self._exit_hook
        )
        # for IO write and fault hook, we can just ignore it since it's not useful for us
        self.symbolic_inputs = []

    def _io_read_hook(self, state):
        if self.input_size:
            # give a symbollic byte
            sym_inp = self.state.solver.BVS('io_read', 8)  # single symbolic input
            self.symbolic_inputs.append(sym_inp)
            state.memory.store(
                self.RW_ADDRESS,
                sym_inp,
                endness=self.project.arch.memory_endness
            )
            self.input_size -= 1
        else:
            # send a null byte
            state.memory.store(
                self.RW_ADDRESS,
                self.state.solver.BVV(0x0, 8),  # single null byte
                endness=self.project.arch.memory_endness
            )

    def _exit_hook(self, state):
        # stop angr
        state.add_constraints(state.solver.false)  # unsatisfyable constraint

    def _pc_is_target(self, state):
        ip = state.ip
        if ip.symbolic:
            return state.solver.satisfiable(
                extra_constraints=[ip == self.desired_pc]
            )
        else:
            return state.solver.eval(ip) == self.desired_pc

    def run(self) -> bytes | None:
        """
        Run the solver.
        """
        simgr = self.project.factory.simgr(self.state)

        simgr.explore(find=self._pc_is_target)
        
        if simgr.found:
            found_state = simgr.found[0]
            if found_state.ip.symbolic:
                found_state.add_constraints(found_state.ip == self.desired_pc)
            result = []
            for sym_byte in self.symbolic_inputs:
                result.append(found_state.solver.eval(sym_byte))
            return bytes(result)
        else:
            return None
