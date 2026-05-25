	.arch armv6-m
	.fpu softvfp
	.eabi_attribute 20, 1
	.eabi_attribute 21, 1
	.eabi_attribute 23, 3
	.eabi_attribute 24, 1
	.eabi_attribute 25, 1
	.eabi_attribute 26, 1
	.eabi_attribute 30, 2
	.eabi_attribute 34, 0
	.eabi_attribute 18, 4
	.file	"pwned.c"
	.text
	.section	.rodata.pwned.str1.4,"aMS",%progbits,1
	.align	2
.LC0:
	.ascii	"pwned!\000"
	.section	.text.pwned,"ax",%progbits
	.align	1
	.p2align 2,,3
	.global	pwned
	.syntax unified
	.code	16
	.thumb_func
	.type	pwned, %function
pwned:
	@ Volatile: function does not return.
	@ args = 0, pretend = 0, frame = 0
	@ frame_needed = 0, uses_anonymous_args = 0
	movs	r2, #6
	movs	r0, #0
	push	{r4, lr}
	ldr	r1, .L4
	bl	_write
.L2:
	b	.L2
.L5:
	.align	2
.L4:
	.word	.LC0
	.size	pwned, .-pwned
	.ident	"GCC: (15:14.2.rel1-1) 14.2.1 20241119"
