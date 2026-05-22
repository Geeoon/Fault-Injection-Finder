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
	.file	"stubs.c"
	.text
	.section	.text._exit,"ax",%progbits
	.align	1
	.p2align 2,,3
	.global	_exit
	.syntax unified
	.code	16
	.thumb_func
	.type	_exit, %function
_write:
	@ args = 0, pretend = 0, frame = 0
	@ frame_needed = 0, uses_anonymous_args = 0
	movs	r0, r2
	push	{r4, r5, lr}
	cmp	r2, #0
	ble	.L11
	ldr	r4, .L14
	adds	r5, r1, r2
.L12:
	ldrb	r3, [r1]
	adds	r1, r1, #1
	strb	r3, [r4]
	cmp	r1, r5
	bne	.L12
.L11:
	@ sp needed
	pop	{r4, r5, pc}
.L15:
	.align	2
.L14:
	.word	50335744
	.size	_write, .-_write
	.section	.text._fini,"ax",%progbits
	.align	1
	.p2align 2,,3
	.global	_fini
	.syntax unified
	.code	16
	.thumb_func
	.type	_fini, %function

