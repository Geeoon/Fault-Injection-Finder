@ startup.s
.section .startup, "ax"
.global _start
_start:
    bl  main
    bl  _exit
