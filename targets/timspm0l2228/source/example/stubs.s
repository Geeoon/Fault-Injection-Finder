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
_exit:
	@ Volatile: function does not return.
	@ args = 0, pretend = 0, frame = 0
	@ frame_needed = 0, uses_anonymous_args = 0
	@ link register save eliminated.
	movs	r3, #192
	lsls	r3, r3, #18
	str	r0, [r3]
.L2:
	b	.L2
	.size	_exit, .-_exit
	.section	.text._read,"ax",%progbits
	.align	1
	.p2align 2,,3
	.global	_read
	.syntax unified
	.code	16
	.thumb_func
	.type	_read, %function
_read:
	@ args = 0, pretend = 0, frame = 0
	@ frame_needed = 0, uses_anonymous_args = 0
	movs	r0, r2
	push	{r4, r5, lr}
	cmp	r2, #0
	ble	.L5
	ldr	r4, .L8
	adds	r5, r1, r2
.L6:
	ldrb	r3, [r4]
	strb	r3, [r1]
	adds	r1, r1, #1
	cmp	r1, r5
	bne	.L6
.L5:
	@ sp needed
	pop	{r4, r5, pc}
.L9:
	.align	2
.L8:
	.word	50335744
	.size	_read, .-_read
	.section	.text._write,"ax",%progbits
	.align	1
	.p2align 2,,3
	.global	_write
	.syntax unified
	.code	16
	.thumb_func
	.type	_write, %function
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
	.section	.text.led_blip,"ax",%progbits
	.align	1
	.p2align 2,,3
	.global	led_blip
	.syntax unified
	.code	16
	.thumb_func
	.type	led_blip, %function
led_blip:
	@ args = 0, pretend = 0, frame = 0
	@ frame_needed = 0, uses_anonymous_args = 0
	@ link register save eliminated.
	movs	r2, #0
	@ sp needed
	ldr	r3, .L17
	str	r2, [r3]
	bx	lr
.L18:
	.align	2
.L17:
	.word	50343936
	.size	led_blip, .-led_blip
	.section	.text._fini,"ax",%progbits
	.align	1
	.p2align 2,,3
	.global	_fini
	.syntax unified
	.code	16
	.thumb_func
	.type	_fini, %function
_fini:
	@ args = 0, pretend = 0, frame = 0
	@ frame_needed = 0, uses_anonymous_args = 0
	@ link register save eliminated.
	@ sp needed
	bx	lr
	.size	_fini, .-_fini
	.section	.text._init,"ax",%progbits
	.align	1
	.p2align 2,,3
	.global	_init
	.syntax unified
	.code	16
	.thumb_func
	.type	_init, %function
_init:
	@ args = 0, pretend = 0, frame = 0
	@ frame_needed = 0, uses_anonymous_args = 0
	@ link register save eliminated.
	@ sp needed
	bx	lr
	.size	_init, .-_init
	.section	.text._lseek,"ax",%progbits
	.align	1
	.p2align 2,,3
	.global	_lseek
	.syntax unified
	.code	16
	.thumb_func
	.type	_lseek, %function
_lseek:
	@ args = 0, pretend = 0, frame = 0
	@ frame_needed = 0, uses_anonymous_args = 0
	@ link register save eliminated.
	movs	r0, #1
	@ sp needed
	rsbs	r0, r0, #0
	bx	lr
	.size	_lseek, .-_lseek
	.section	.text._close,"ax",%progbits
	.align	1
	.p2align 2,,3
	.global	_close
	.syntax unified
	.code	16
	.thumb_func
	.type	_close, %function
_close:
	@ args = 0, pretend = 0, frame = 0
	@ frame_needed = 0, uses_anonymous_args = 0
	@ link register save eliminated.
	movs	r0, #1
	@ sp needed
	rsbs	r0, r0, #0
	bx	lr
	.size	_close, .-_close
	.section	.text._sbrk,"ax",%progbits
	.align	1
	.p2align 2,,3
	.global	_sbrk
	.syntax unified
	.code	16
	.thumb_func
	.type	_sbrk, %function
_sbrk:
	@ args = 0, pretend = 0, frame = 0
	@ frame_needed = 0, uses_anonymous_args = 0
	@ link register save eliminated.
	movs	r0, #1
	@ sp needed
	rsbs	r0, r0, #0
	bx	lr
	.size	_sbrk, .-_sbrk
	.section	.text._isatty,"ax",%progbits
	.align	1
	.p2align 2,,3
	.global	_isatty
	.syntax unified
	.code	16
	.thumb_func
	.type	_isatty, %function
_isatty:
	@ args = 0, pretend = 0, frame = 0
	@ frame_needed = 0, uses_anonymous_args = 0
	@ link register save eliminated.
	movs	r0, #1
	@ sp needed
	rsbs	r0, r0, #0
	bx	lr
	.size	_isatty, .-_isatty
	.section	.text._kill,"ax",%progbits
	.align	1
	.p2align 2,,3
	.global	_kill
	.syntax unified
	.code	16
	.thumb_func
	.type	_kill, %function
_kill:
	@ args = 0, pretend = 0, frame = 0
	@ frame_needed = 0, uses_anonymous_args = 0
	@ link register save eliminated.
	movs	r0, #1
	@ sp needed
	rsbs	r0, r0, #0
	bx	lr
	.size	_kill, .-_kill
	.section	.text._getpid,"ax",%progbits
	.align	1
	.p2align 2,,3
	.global	_getpid
	.syntax unified
	.code	16
	.thumb_func
	.type	_getpid, %function
_getpid:
	@ args = 0, pretend = 0, frame = 0
	@ frame_needed = 0, uses_anonymous_args = 0
	@ link register save eliminated.
	movs	r0, #1
	@ sp needed
	rsbs	r0, r0, #0
	bx	lr
	.size	_getpid, .-_getpid
	.section	.text._fstat,"ax",%progbits
	.align	1
	.p2align 2,,3
	.global	_fstat
	.syntax unified
	.code	16
	.thumb_func
	.type	_fstat, %function
_fstat:
	@ args = 0, pretend = 0, frame = 0
	@ frame_needed = 0, uses_anonymous_args = 0
	@ link register save eliminated.
	movs	r0, #1
	@ sp needed
	rsbs	r0, r0, #0
	bx	lr
	.size	_fstat, .-_fstat
	.ident	"GCC: (15:14.2.rel1-1) 14.2.1 20241119"
