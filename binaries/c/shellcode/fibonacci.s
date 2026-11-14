@ fibonacci.s
@ test program to compute fibonacci sequence
@ our UART loader payload already has the I/O address stored in R1
.syntax unified
.thumb
.arch armv6-m
.text
    MOVS R2, #0         @ start condition for t-2
    MOVS R3, #1         @ start condition for t-1
    STRB R2, [R1]       @ print t-2
    STRB R3, [R1]       @ print t-1
    ADDS R4, R3, R2     @ compute next fibonacci, t0
    STRB R4, [R1]       @ print it
    MOV R2, R3          @ t-2 = t-1
    MOV R3, R4          @ t-1 = t0
    B . -8              @ go back to the ADDS instruction
