"""
Constraint solver for finding inputs that set the PC equal to some value
"""
import logging

import angr
import claripy
import archinfo

from FaultInjectionFinder.Engine.FIEngine import DEFAULT_BINARY_ADDRESS, DEFAULT_BINARY_MAX_SIZE, DEFAULT_EXIT_ADDRESS, DEFAULT_FAULT_ADDRESS, DEFAULT_RAM_ADDRESS, DEFAULT_RAM_SIZE, DEFAULT_RW_ADDRESS, INSTRUCTION_SIZE

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
        self.desired_pc = desired_pc | 1  # THUMB
        self.project = angr.load_shellcode(
            binary,
            # arch='arm',  # NOT THUMB
            arch=archinfo.ArchARMEL(),  # THUMB
            start_offset=0,
            load_address=BINARY_ADDRESS,
            thumb=True  # THUMB
        )
        self.state = self.project.factory.blank_state(
            addr=BINARY_ADDRESS | 1,  # `| 1` FOR THUMB
            add_options={
                angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
                angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
            }
        )
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
            sym_inp = claripy.BVS('io_read', 8)  # single symbolic input
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
                claripy.BVV(0x0, 8),  # single null byte
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

    def _step_func(self, simgr):
        if simgr.active:
            logging.info(f"Step {self._steps}, active: {len(simgr.active)}, constraints: {len(simgr.active[0].solver.constraints)}")
        self._steps += 1
        return simgr

    def run(self, max_iter: int=1000) -> bytes | None:
        """
        Run the solver.
        """
        simgr = self.project.factory.simgr(
            self.state,
            save_unconstrained=True,
            save_unsat=True
        )
        # veritesting, does not work with our setup due to internal angr weirdness
        # simgr.use_technique(angr.exploration_techniques.veritesting.Veritesting())
        # simple max iterations
        simgr.use_technique(angr.exploration_techniques.LengthLimiter(max_length=max_iter))
        # this severely limits the number of states that will be explored
        simgr.use_technique(angr.exploration_techniques.LoopSeer(bound=32))
        self._steps = 0
        self._max_iter = max_iter
        simgr.explore(find=self._pc_is_target, num_find=1, step_func=self._step_func)
        
        if simgr.found:
            candidates = simgr.found
        elif simgr.unconstrained:
            candidates = simgr.unconstrained
        else:
            return None
        for state in candidates:
            if state.ip.symbolic:
                state.add_constraints(state.ip == self.desired_pc)
            if state.solver.satisfiable():
                result = []
                for sym_byte in self.symbolic_inputs:
                    result.append(state.solver.eval(sym_byte))
                return bytes(result)
        return None
