"""
Constraint solver for finding inputs that set the PC equal to some value
"""
import logging

import angr

from FIEngine import R, PC, LR, SP, NOP, FIEngine

class PCSolver(FIEngine):
    """
    Given a binary, solve for what inputs could cause the PC equal to some value
    This is slower, so prefer using FIEngine until a proper instruction skip has been found
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.project = angr.load_shellcode(
            self.binary,
            arch='arm',
            start_offset=0,
            load_address=self.BINARY_ADDRESS
        )


