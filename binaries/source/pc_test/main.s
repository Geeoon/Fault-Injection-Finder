	.cpu arm7tdmi
	.arch armv4t
	.fpu softvfp
	.eabi_attribute 20, 1
	.eabi_attribute 21, 1
	.eabi_attribute 23, 3
	.eabi_attribute 24, 1
	.eabi_attribute 25, 1
	.eabi_attribute 26, 1
	.eabi_attribute 30, 6
	.eabi_attribute 34, 0
	.eabi_attribute 18, 4
	.file	"main.c"
	.text
	.section	.text.main,"ax",%progbits
	.align	2
	.global	main
	.syntax unified
	.arm
	.type	main, %function
main:
	@ Function supports interworking.
	@ args = 0, pretend = 0, frame = 8
	@ frame_needed = 1, uses_anonymous_args = 0
	push	{fp, lr}
	add	fp, sp, #4
	sub	sp, sp, #8
	@ allocate at least 8 bytes for input
	sub	r3, fp, #12  	@ r3 = 12 byte buffer
	mov	r2, #8  		@ r2 = 8, read 8 bytes
	mov	r1, r3			@ r1 = r3, but pass to function
	mov	r0, #0  		@ r0 = 0, fd (unused)
	bl	_read			@ call read
	nop					@ fault injection finder should have at least one where it runs the original program
	ldr r4, [r3]		@ load from buffer to register
	bx r4				@ jump to address from buffer
	.size	main, .-main
	.ident	"GCC: (15:14.2.rel1-1) 14.2.1 20241119"
