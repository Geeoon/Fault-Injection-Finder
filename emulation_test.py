import unicorn
import capstone
from unicorn import *
from capstone import * 

# R0  = arm_const.UC_ARM_REG_R0
# R1  = arm_const.UC_ARM_REG_R1
# R2  = arm_const.UC_ARM_REG_R2
# R3  = arm_const.UC_ARM_REG_R3
# R4  = arm_const.UC_ARM_REG_R4
# R5  = arm_const.UC_ARM_REG_R5
# R6  = arm_const.UC_ARM_REG_R6
# R7  = arm_const.UC_ARM_REG_R7
# R8  = arm_const.UC_ARM_REG_R8
# R9  = arm_const.UC_ARM_REG_R9
# R10 = arm_const.UC_ARM_REG_R10
# R11 = arm_const.UC_ARM_REG_R11
# R12 = arm_const.UC_ARM_REG_R12

R = [getattr(arm_const, f"UC_ARM_REG_R{i}") for i in range(13)]

PC = arm_const.UC_ARM_REG_PC
LR = arm_const.UC_ARM_REG_LR
SP = arm_const.UC_ARM_REG_SP
NOP = b"\x00\xf0\x20\xe3"

# will be our binary code
CODE = (
    b"\x2a\x00\xa0\xe3"
    b"\x04\x00\x2d\xe5"
    b"\x00\x00\xa0\xe3"
    b"\x04\x00\x9d\xe4"
)

ADDRESS = 0x1000000
num_instructions = len(CODE)


def run_emulation(fault_index):

    # initalize emulator and capstone disassembler 
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    mu.mem_map(ADDRESS, 0x1000)

    # print disas of unmodified code
    # if (fault_index == -1):
    #     for i in md.disasm(CODE, 0x1000):
    #         print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))

    code_arr = bytearray(CODE)

    if (fault_index > -1): 
        byte_offset = fault_index * 4
        code_arr[byte_offset:byte_offset + 4] = NOP

    for i in md.disasm(code_arr, 0x1000):
        print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))


    # 0x1000 is one page of memory allocated
    mu.mem_write(ADDRESS, bytes(code_arr))
    mu.reg_write(SP, ADDRESS + 0x800) # initialize machine registers
    mu.emu_start(ADDRESS, ADDRESS + len(code_arr), count=100) # stops after 100 instructions

    # print registers
    print("Emulation done. Below is the CPU context")
    for i in range(4): print(f">>> R{i} = 0x{mu.reg_read(R[i]):x}")


run_emulation(-1)

for i in range(len(CODE) // 4): run_emulation(i)