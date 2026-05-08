from capstone import *

# BRANCH_MNEMONICS = {
#     # unconditional/control-transfer branches
#     "b", "bl", "bx", "blx",

#     # conditional branches
#     "beq", "bne", "blt", "ble", "bgt", "bge",
#     "blo", "bls", "bhi", "bhs",
#     "bmi", "bpl", "bvs", "bvc",

#     # ARM/AArch64-style names, useful for future binaries
#     "b.eq", "b.ne", "b.lt", "b.le", "b.gt", "b.ge",
#     "b.lo", "b.ls", "b.hi", "b.hs",
#     "b.mi", "b.pl", "b.vs", "b.vc",

#     "cbz", "cbnz", "tbz", "tbnz",
#     "br", "blr",
# }

# CONDITIONAL_BRANCH_MNEMONICS = {
#     "beq", "bne", "blt", "ble", "bgt", "bge",
#     "blo", "bls", "bhi", "bhs",
#     "bmi", "bpl", "bvs", "bvc",
#     "b.eq", "b.ne", "b.lt", "b.le", "b.gt", "b.ge",
#     "b.lo", "b.ls", "b.hi", "b.hs",
#     "b.mi", "b.pl", "b.vs", "b.vc",
#     "cbz", "cbnz", "tbz", "tbnz",
# }

# RETURN_MNEMONICS = {
#     "ret",
#     "eret",
#     "bx",   # common ARM/Thumb return: bx lr
# }

# COMPARE_MNEMONICS = {
#     "cmp",
#     "cmn",
#     "tst",
#     "fcmp",
#     "ccmp",
#     "ccmn",
# }

COND_SUFFIXES = {
    "eq", "ne",
    "cs", "hs",
    "cc", "lo",
    "mi", "pl",
    "vs", "vc",
    "hi", "ls",
    "ge", "lt",
    "gt", "le",
}

CONDITIONAL_BRANCH_MNEMONICS = {
    # AArch32 / Thumb
    "beq", "bne",
    "bcs", "bhs",
    "bcc", "blo",
    "bmi", "bpl",
    "bvs", "bvc",
    "bhi", "bls",
    "bge", "blt",
    "bgt", "ble",
    "cbz", "cbnz",

    # A64
    "b.eq", "b.ne",
    "b.cs", "b.hs",
    "b.cc", "b.lo",
    "b.mi", "b.pl",
    "b.vs", "b.vc",
    "b.hi", "b.ls",
    "b.ge", "b.lt",
    "b.gt", "b.le",

    "bc.eq", "bc.ne",
    "bc.cs", "bc.hs",
    "bc.cc", "bc.lo",
    "bc.mi", "bc.pl",
    "bc.vs", "bc.vc",
    "bc.hi", "bc.ls",
    "bc.ge", "bc.lt",
    "bc.gt", "bc.le",

    "tbz", "tbnz",

    # Newer A64 compare-and-branch forms, depending on Capstone support
    "cbge", "cble", "cblt", "cbgt",
    "cbhs", "cblo", "cbls", "cbhi",
    "cbbge", "cbble", "cbblt", "cbbgt",
    "cbbhs", "cbblo", "cbbls", "cbbhi",
    "cbhge", "cbhle", "cbhlt", "cbhgt",
    "cbhhs", "cbhlo", "cbhls", "cbhhi",
}

UNCONDITIONAL_BRANCH_MNEMONICS = {
    # AArch32 / Thumb
    "b", "bl", "bx", "blx", "bxj",

    # A64
    "br", "blr",
    "braa", "braaz", "brab", "brabz",
    "blraa", "blraaz", "blrab", "blrabz",
}

RETURN_MNEMONICS = {
    # A64
    "ret", "eret", "eretaa", "eretab",

    # AArch32 common returns
    "bx",       # bx lr
    "pop",      # pop {..., pc}
    "ldm", "ldmia", "ldmfd", "ldmda", "ldmfa", "ldmdb", "ldmea", "ldmib", "ldmed",
}

COMPARE_MNEMONICS = {
    # AArch32 / A64
    "cmp", "cmn", "tst", "teq",

    # A64
    "ccmp", "ccmn",
    "fcmp", "fcmpe",
}

FLAG_SETTING_MNEMONICS = {
    # AArch32 and many A64
    "adds", "adcs",
    "subs", "sbcs",
    "ands",

    # Mostly AArch32
    "rsbs", "rscs",
    "bics",
    "eors", "orrs", "orns",
    "movs", "mvns",
    "lsls", "lsrs", "asrs", "rors", "rrxs",
    "muls", "mlas",
}

CONDITIONAL_SELECT_MNEMONICS = {
    # A64
    "csel",
    "csinc",
    "csinv",
    "csneg",
    "cset",
    "csetm",
    "cinc",
    "cinv",
    "cneg",
}

IT_MNEMONICS = {
    "it", "itt", "ite", "itte", "itet", "ittt", "itttt",
}

SECURITY_CHECK_MNEMONICS = {
    # Optional, mostly useful for hardened A64 binaries
    "autia", "autiaz", "autiasp", "autiza",
    "autib", "autibz", "autibsp", "autizb",
    "autda", "autdza", "autdb", "autdzb",
    "pacibsp", "paciasp",
    "bti",
    "brk", "bkpt", "hlt",
}

OTHER_MNEMONICS = {
    "push", "pop", "ldr", "str"
}

BRANCH_MNEMONICS = CONDITIONAL_BRANCH_MNEMONICS | UNCONDITIONAL_BRANCH_MNEMONICS

VULNERABLE_MNEMONICS = (
    CONDITIONAL_BRANCH_MNEMONICS
    | COMPARE_MNEMONICS
    | FLAG_SETTING_MNEMONICS
    | CONDITIONAL_SELECT_MNEMONICS
    | RETURN_MNEMONICS
    | IT_MNEMONICS
    | OTHER_MNEMONICS
)

ALL_SPECIAL = (
    BRANCH_MNEMONICS
    | RETURN_MNEMONICS
    | COMPARE_MNEMONICS
    | FLAG_SETTING_MNEMONICS
    | CONDITIONAL_SELECT_MNEMONICS
    | IT_MNEMONICS
    | SECURITY_CHECK_MNEMONICS
)



class PreProcessing:
    def __init__(self, binary: bytes, user_sel: int, start_addr: int, thumb: bool):
        if thumb:
            self.md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
        else:
            self.md = Cs(CS_ARCH_ARM, CS_MODE_ARM)

        self.instructions = []


        all_instructions = []

        for insn in self.md.disasm(bytearray(binary), start_addr):
            all_instructions.append({
                "address": insn.address,
                "mnemonic": insn.mnemonic,
                "op_str": insn.op_str,
            })



        self.instructions = self.find_inst(all_instructions, user_sel)

    def find_inst(self, instructions, user_sel):
        mnemonic_map = {
            1: VULNERABLE_MNEMONICS,          # recommended default
            2: CONDITIONAL_BRANCH_MNEMONICS,  # only conditional branches
            3: COMPARE_MNEMONICS,             # only compares/tests
            4: RETURN_MNEMONICS,              # returns
            5: ALL_SPECIAL,                   # branches/calls/returns/compares
        }

            

        target = mnemonic_map.get(user_sel, set())

        special_inst = []

        for insn in instructions:
            if not (1 <= user_sel <= 5):
                special_inst.append(insn)
            elif insn["mnemonic"] in target:
                special_inst.append(insn)

        return special_inst