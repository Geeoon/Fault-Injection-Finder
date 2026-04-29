from unicorn import *
from capstone import * 


# call on line 30 of FaultInjectionFinder.py


md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
md.detail = True

BRANCH_MNEMONICS = {
    "b", "bl", "br", "blr",
    "b.eq", "b.ne", "b.lt", "b.le", "b.gt", "b.ge",
    "b.lo", "b.ls", "b.hi", "b.hs",
    "b.mi", "b.pl", "b.vs", "b.vc",
    "cbz", "cbnz", "tbz", "tbnz"
}

RETURN_MNEMONICS = {
    "ret",    # standard return
    "eret",   # exception return
}

COMPARE_MNEMONICS = {
    "cmp",    # compare (sets flags)
    "cmn",    # compare negative
    "tst",    # test bits (AND, sets flags)
    "fcmp",   # floating point compare
    "ccmp",   # conditional compare
    "ccmn",   # conditional compare negative
}

ALL_SPECIAL = BRANCH_MNEMONICS | RETURN_MNEMONICS | COMPARE_MNEMONICS



class Pre_Processing():
    def __init__(binary: bytes, user_sel: str):
        """
        Initializer for the PreProcessor
        :param binary: binary to examine
        :param user_sel: user chooses instructions to examine

        - user inputs numbers 1-4 (for now)
        - can choose to find branch statements, comparison, return values or all
        - analyze binary for all statements
        """

        # if the user enters numbers not in range 1-4
        if (~(user_sel > 0 & user_sel < 5)):
            return instructions
        
        code_arr = bytearray(binary)
        instructions = [] 

        start_addr = 0x1000             # change to input later
        for i in md.disasm(code_arr, start_addr):
            instructions.append({
            "address": i.address,
            "mnemonic": i.mnemonic,
            "op_str": i.op_str
        })
            
        return find_inst(instructions, user_sel)


    def find_inst(instructions, user_sel):

        special_inst = []

        mnemonic_map = {
            1: ALL_SPECIAL,
            2: BRANCH_MNEMONICS,
            3: COMPARE_MNEMONICS,
            4: RETURN_MNEMONICS,
        }

        target = mnemonic_map.get(user_sel, set())

        for insn in instructions:
            if insn["mnemonic"] in target:
                special_inst.append(insn)

  

        return special_inst
    

