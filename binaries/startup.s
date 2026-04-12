@ startup.s
.global _start
_start:
    ldr sp, =0x20001000   @ set up stack
    bl  main
.hang:
    b   .hang
