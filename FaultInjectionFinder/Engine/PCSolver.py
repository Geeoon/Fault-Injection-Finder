"""
Constraint solver for finding inputs that set the PC equal to some value
"""
import logging

import angr
import claripy
import archinfo

from FaultInjectionFinder.Engine.FIEngine import DEFAULT_BINARY_ADDRESS, DEFAULT_BINARY_MAX_SIZE, DEFAULT_EXIT_ADDRESS, DEFAULT_FAULT_ADDRESS, DEFAULT_RAM_ADDRESS, DEFAULT_RAM_SIZE, DEFAULT_RW_ADDRESS

class PCSolver():
    """
    Given a binary, solve for what inputs could cause the PC equal to some value
    This is slower, so prefer using FIEngine until a proper instruction skip has been found
    """
    def __init__(self,
                 binary: bytes,
                 fault_index: int,
                 input_size: int,
                 desired_pc: int,
                 BINARY_ADDRESS: int=DEFAULT_BINARY_ADDRESS,
                 RAM_ADDRESS: int=DEFAULT_RAM_ADDRESS,
                 RAM_SIZE: int=DEFAULT_RAM_SIZE,
                 EXIT_ADDRESS: int=DEFAULT_EXIT_ADDRESS,
                 RW_ADDRESS: int=DEFAULT_RW_ADDRESS,
                 start_thumb: bool=True,
                 z3_timeout: int=1000):
        """
        :param binary: the binary to solve for
        :param input_size: the size of the input
        :param fault_index: the "clock cycle" for the fault to occur on
        :param cycle_insn_map: the cycles to instruction called map
        :param desired_pc: the program counter we want to solve for, make sure to set the thumb bit if desired
        :param BINARY_ADDRESS: the address where the binary should be loaded
        :param BINARY_MAX_SIZE: the size of flash allocated for the binary
        :param RAM_ADDRESS: the starting address of the RAM
        :param RAM_SIZE: the size of available RAM for emulation
        :param EXIT_ADDRESS: the address that should be written for an exit
        :param RW_ADDRESS: the IO address
        :param FAULT_ADDRESS: the address that should be written to in the event of a successful fault
        :param start_thumb: whether or not to start running in thumb mode (common in M architectures)
        :param z3_timeout: the timeout period for each equation in the z3 solver in ms. it will give up after this period
        """
        self.start_thumb = start_thumb
        self.desired_pc = desired_pc
        self.fault_index = fault_index
        arch = archinfo.ArchARMEL()
        
        self.project = angr.load_shellcode(
            binary,
            arch=arch,
            start_offset=0,
            load_address=BINARY_ADDRESS,
            # thumb=self.thumb  # let angr do it dynamically
        )

        self.state = self.project.factory.blank_state(
            addr=BINARY_ADDRESS | (1 if self.start_thumb else 0),
            add_options={  # NOTE: in the future, we may want to just make it crash when it pulls unconstrained values to make it more deterministic
                angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
                angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                angr.options.LAZY_SOLVES,
            }
        )
        
        self.state.regs.sp = RAM_ADDRESS + RAM_SIZE
        self.state.memory.store(RAM_ADDRESS, b'\x00' * RAM_SIZE)  # zero out RAM, NOTE: also maybe crash to make it deterministic
        self.input_size = input_size
        # set up IO read hook
        self.RW_ADDRESS = RW_ADDRESS
        self.state.inspect.b(
            'mem_read',
            when=angr.BP_BEFORE,
            mem_read_address=RW_ADDRESS,
            action=self._io_read_hook
        )
        # set up exit hook
        self.state.inspect.b(
            'mem_write',
            when=angr.BP_BEFORE,
            mem_write_address=EXIT_ADDRESS,
            action=self._exit_hook
        )
        self.state.solver._solver.timeout = z3_timeout  # 1 second timeout for solving a single formula
        # for IO write and fault hook, we can just ignore it since it's not useful for us
        self.logger = logging.getLogger(__name__)
    
    def _io_read_hook(self, state):
        consumed = state.globals.get('inputs_consumed', 0)
        # if consumed < self.input_size:  # removed so we always send symbollic inputs
        if True:
            # give a symbollic byte
            sym_inp = claripy.BVS('io_read', 8)  # single symbolic input
            symbolic_inputs = state.globals.get('symbolic_inputs', [])
            symbolic_inputs = symbolic_inputs + [sym_inp]  # create new list, don't mutate the existing one
            state.globals['symbolic_inputs'] = symbolic_inputs
            state.memory.store(
                self.RW_ADDRESS,
                sym_inp,
                endness=self.project.arch.memory_endness
            )
            state.globals['inputs_consumed'] = consumed + 1
        else:
            # send a null byte
            state.memory.store(
                self.RW_ADDRESS,
                claripy.BVV(0x0, 8),  # single null byte
                endness=self.project.arch.memory_endness
            )

    def _exit_hook(self, state):
        # stop angr
        state.add_constraints(claripy.BVV(0, 1))  # unsatisfyable constraint
        state._satisfiable = False

    def _pc_is_target(self, state):
        ip = state.ip
        if ip.symbolic:
            self.logger.info("PC is symbolic")
            return state.solver.satisfiable(
                extra_constraints=[ip == self.desired_pc]
            )
        else:
            return state.solver.eval(ip) == self.desired_pc

    def _find_solution(self, state):
        # we chose to implement this in a kind of convoluted way.  Instead of having the constraint added to the simgr, we apply it once the 
        # IP is symbolic.  This way, in the future, we can save these states and solve for different PC values
        if state.ip.symbolic:
            state.add_constraints(state.ip == self.desired_pc)
        if state.solver.satisfiable():
            result = []
            for sym_byte in state.globals.get('symbolic_inputs', []):
                result.append(state.solver.eval(sym_byte))
            return bytes(result)
        return None

    def run(self, max_iter: int=2000) -> bytes | None:
        """
        Run the solver.
        """
        simgr = self.project.factory.simgr(
            self.state,
            save_unconstrained=True,
            save_unsat=False,
            stashes={
                'active': [],
                'deadended': [],
                'unsat': [],
                'unconstrained': [],
                'found': [],
            },
            
        )
        # veritesting, does not work with our setup due to internal angr weirdness
        # simgr.use_technique(angr.exploration_techniques.veritesting.Veritesting())
        # simple max iterations
        simgr.use_technique(angr.exploration_techniques.LengthLimiter(max_length=max_iter))
        simgr.use_technique(angr.exploration_techniques.LoopSeer(bound=32))
        # simgr.use_technique(angr.exploration_techniques.DFS())
        self._steps = 0
        while simgr.active:
            simgr.step(num_inst=1)
            if simgr.active:
                self.logger.debug(f"Step {self._steps}, active: {len(simgr.active)}, constraints: {len(simgr.active[0].solver.constraints)}")
            self._steps += 1
            for state in simgr.active:
                state.globals['cycle_count'] = state.globals.get('cycle_count', 0) + 1
                # Check find condition
                if state.globals['cycle_count'] == self.fault_index - 1:  # cycle_count stores the last executed cycle, so check against index - 1
                    old_ip = state.addr
                    block = self.project.factory.block(state.addr)
                    if block.capstone.insns:
                        insn = block.capstone.insns[0]
                        self.logger.debug(f"Cycle to be skipped: {state.globals.get('cycle_count', 0)}, addr: {hex(insn.address)}, insn: {insn.mnemonic} {insn.op_str}")
                    state.ip = state.addr + (2 if (state.addr & 1) else 4)
                    self.logger.info(f"Skipping at cycle {state.globals['cycle_count'] + 1}.  Skipped from: {hex(old_ip & -2)} to: {hex(state.solver.eval(state.ip) & -2)}")
                    block = self.project.factory.block(state.addr)
                    if block.capstone.insns:
                        insn = block.capstone.insns[0]
                        self.logger.debug(f"Cycle to run now {state.globals.get('cycle_count', 0)}, addr: {hex(insn.address)}, insn: {insn.mnemonic} {insn.op_str}")


            simgr.unsat.clear()  # save memory
            simgr.move(from_stash='active', to_stash='found', filter_func=self._pc_is_target)
            simgr.move(from_stash='unconstrained', to_stash='found', filter_func=self._pc_is_target)
            simgr.unconstrained.clear()  # save memory
            simgr.move(from_stash='deadended', to_stash='found', filter_func=self._pc_is_target)
            simgr.deadended.clear()  # save memory
            if simgr.found:
                break
        for state in simgr.found:  # for each found state, try to find a solution
            soln = self._find_solution(state)
            if soln is not None:
                return soln
        return None
