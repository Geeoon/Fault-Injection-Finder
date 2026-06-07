	.text
	.syntax unified
	.eabi_attribute	67, "2.09"	@ Tag_conformance
	.eabi_attribute	28, 0	@ Tag_ABI_VFP_args
	.eabi_attribute	72, 0	@ Tag_execute_only
	.cpu	cortex-m0plus
	.eabi_attribute	6, 12	@ Tag_CPU_arch
	.eabi_attribute	7, 77	@ Tag_CPU_arch_profile
	.eabi_attribute	8, 0	@ Tag_ARM_ISA_use
	.eabi_attribute	9, 1	@ Tag_THUMB_ISA_use
	.eabi_attribute	34, 0	@ Tag_CPU_unaligned_access
	.eabi_attribute	17, 1	@ Tag_ABI_PCS_GOT_use
	.eabi_attribute	20, 1	@ Tag_ABI_FP_denormal
	.eabi_attribute	21, 0	@ Tag_ABI_FP_exceptions
	.eabi_attribute	23, 3	@ Tag_ABI_FP_number_model
	.eabi_attribute	24, 1	@ Tag_ABI_align_needed
	.eabi_attribute	25, 1	@ Tag_ABI_align_preserved
	.eabi_attribute	72, 0	@ Tag_execute_only
	.eabi_attribute	38, 1	@ Tag_ABI_FP_16bit_format
	.eabi_attribute	18, 4	@ Tag_ABI_PCS_wchar_t
	.eabi_attribute	26, 1	@ Tag_ABI_enum_size
	.eabi_attribute	14, 0	@ Tag_ABI_PCS_R9_use
	.file	"main.c"
	.file	1 "/home/main/Documents/school/Fault-Injection-Finder/targets/timspm0l2228/source" "password/main.c"
	.file	2 "/opt/ti-cgt-armllvm_4.0.3.LTS/include/c" "string.h"
	.section	.text.main,"ax",%progbits
	.hidden	main                            @ -- Begin function main
	.globl	main
	.p2align	2
	.type	main,%function
	.code	16                              @ @main
	.thumb_func
main:
.Lfunc_begin0:
	.loc	1 11 0                          @ password/main.c:11:0
	.fnstart
	.cfi_sections .debug_frame
	.cfi_startproc
@ %bb.0:
	.pad	#24
	sub	sp, #24
	.cfi_def_cfa_offset 24
.Ltmp0:
	.loc	1 12 5 prologue_end             @ password/main.c:12:5
	bl	init_device
.Ltmp1:
	.loc	1 0 5 is_stmt 0                 @ password/main.c:0:5
	movs	r0, #0
	.loc	1 13 18 is_stmt 1               @ password/main.c:13:18
	str	r0, [sp, #20]
.Ltmp2:
	.loc	1 14 9                          @ password/main.c:14:9
	ldr	r0, [sp, #20]
.Ltmp3:
	.loc	1 14 9 is_stmt 0                @ password/main.c:14:9
	cmp	r0, #0
	beq	.LBB0_2
@ %bb.1:
.Ltmp4:
	.loc	1 14 14                         @ password/main.c:14:14
	bl	pwned
.Ltmp5:
.LBB0_2:
	.loc	1 0 14                          @ password/main.c:0:14
	movs	r0, #114
	mvns	r7, r0
	ldr	r4, .LCPI0_0
.LBB0_3:                                @ =>This Inner Loop Header: Depth=1
	movs	r5, #0
	movs	r2, #18
.Ltmp6:
	.loc	1 18 9 is_stmt 1                @ password/main.c:18:9
	mov	r0, r5
	mov	r1, r4
	bl	_write
.Ltmp7:
	.loc	1 0 9 is_stmt 0                 @ password/main.c:0:9
	add	r6, sp, #8
	movs	r2, #11
	.loc	1 19 17 is_stmt 1               @ password/main.c:19:17
	mov	r0, r5
	mov	r1, r6
	bl	_read
.Ltmp8:
	@DEBUG_VALUE: s1 <- [DW_OP_plus_uconst 8, DW_OP_plus_uconst 1, DW_OP_stack_value] $sp
	@DEBUG_VALUE: s2 <- undef
	@DEBUG_VALUE: strncmp:n <- undef
	@DEBUG_VALUE: strncmp:string2 <- undef
	@DEBUG_VALUE: strncmp:string1 <- [DW_OP_plus_uconst 8, DW_OP_stack_value] $sp
	@DEBUG_VALUE: n <- undef
	.loc	2 437 35                        @ /opt/ti-cgt-armllvm_4.0.3.LTS/include/c/string.h:437:35
	ldrb	r0, [r6]
.Ltmp9:
	@DEBUG_VALUE: result <- [DW_OP_LLVM_arg 0, DW_OP_LLVM_convert 8 7, DW_OP_LLVM_convert 32 7, DW_OP_LLVM_arg 1, DW_OP_LLVM_convert 8 7, DW_OP_LLVM_convert 32 7, DW_OP_minus, DW_OP_stack_value] $r0, 112
	@DEBUG_VALUE: cp <- 112
	.loc	2 437 10 is_stmt 0              @ /opt/ti-cgt-armllvm_4.0.3.LTS/include/c/string.h:437:10
	cmp	r0, #112
	bne	.LBB0_15
.Ltmp10:
@ %bb.4:                                @   in Loop: Header=BB0_3 Depth=1
	@DEBUG_VALUE: cp <- 112
	@DEBUG_VALUE: result <- [DW_OP_LLVM_arg 0, DW_OP_LLVM_convert 8 7, DW_OP_LLVM_convert 32 7, DW_OP_LLVM_arg 1, DW_OP_LLVM_convert 8 7, DW_OP_LLVM_convert 32 7, DW_OP_minus, DW_OP_stack_value] $r0, 112
	@DEBUG_VALUE: strncmp:string1 <- [DW_OP_plus_uconst 8, DW_OP_stack_value] $sp
	@DEBUG_VALUE: s1 <- [DW_OP_plus_uconst 8, DW_OP_plus_uconst 1, DW_OP_stack_value] $sp
	@DEBUG_VALUE: strncmp:n <- undef
	@DEBUG_VALUE: s2 <- undef
	@DEBUG_VALUE: s1 <- [DW_OP_plus_uconst 8, DW_OP_plus_uconst 1, DW_OP_plus_uconst 1, DW_OP_stack_value] $sp
	.loc	2 0 10                          @ /opt/ti-cgt-armllvm_4.0.3.LTS/include/c/string.h:0:10
	add	r0, sp, #8
.Ltmp11:
	.loc	2 437 35                        @ /opt/ti-cgt-armllvm_4.0.3.LTS/include/c/string.h:437:35
	ldrb	r0, [r0, #1]
.Ltmp12:
	@DEBUG_VALUE: result <- [DW_OP_LLVM_arg 0, DW_OP_LLVM_convert 8 7, DW_OP_LLVM_convert 32 7, DW_OP_LLVM_arg 1, DW_OP_LLVM_convert 8 7, DW_OP_LLVM_convert 32 7, DW_OP_minus, DW_OP_stack_value] $r0, 97
	@DEBUG_VALUE: cp <- 97
	.loc	2 437 10                        @ /opt/ti-cgt-armllvm_4.0.3.LTS/include/c/string.h:437:10
	cmp	r0, #97
	bne	.LBB0_16
.Ltmp13:
@ %bb.5:                                @   in Loop: Header=BB0_3 Depth=1
	@DEBUG_VALUE: cp <- 97
	@DEBUG_VALUE: result <- [DW_OP_LLVM_arg 0, DW_OP_LLVM_convert 8 7, DW_OP_LLVM_convert 32 7, DW_OP_LLVM_arg 1, DW_OP_LLVM_convert 8 7, DW_OP_LLVM_convert 32 7, DW_OP_minus, DW_OP_stack_value] $r0, 97
	@DEBUG_VALUE: s1 <- [DW_OP_plus_uconst 8, DW_OP_plus_uconst 1, DW_OP_plus_uconst 1, DW_OP_stack_value] $sp
	@DEBUG_VALUE: strncmp:string1 <- [DW_OP_plus_uconst 8, DW_OP_stack_value] $sp
	@DEBUG_VALUE: strncmp:n <- undef
	@DEBUG_VALUE: s2 <- undef
	@DEBUG_VALUE: s1 <- [DW_OP_plus_uconst 8, DW_OP_plus_uconst 2, DW_OP_plus_uconst 1, DW_OP_stack_value] $sp
	.loc	2 0 10                          @ /opt/ti-cgt-armllvm_4.0.3.LTS/include/c/string.h:0:10
	add	r0, sp, #8
.Ltmp14:
	.loc	2 437 35                        @ /opt/ti-cgt-armllvm_4.0.3.LTS/include/c/string.h:437:35
	ldrb	r0, [r0, #2]
.Ltmp15:
	@DEBUG_VALUE: result <- [DW_OP_LLVM_arg 0, DW_OP_LLVM_convert 8 7, DW_OP_LLVM_convert 32 7, DW_OP_LLVM_arg 1, DW_OP_LLVM_convert 8 7, DW_OP_LLVM_convert 32 7, DW_OP_minus, DW_OP_stack_value] $r0, 115
	@DEBUG_VALUE: cp <- 115
	.loc	2 437 10                        @ /opt/ti-cgt-armllvm_4.0.3.LTS/include/c/string.h:437:10
	cmp	r0, #115
	mov	r1, r7
	bne	.LBB0_17
.Ltmp16:
@ %bb.6:                                @   in Loop: Header=BB0_3 Depth=1
	@DEBUG_VALUE: cp <- 115
	@DEBUG_VALUE: result <- [DW_OP_LLVM_arg 0, DW_OP_LLVM_convert 8 7, DW_OP_LLVM_convert 32 7, DW_OP_LLVM_arg 1, DW_OP_LLVM_convert 8 7, DW_OP_LLVM_convert 32 7, DW_OP_minus, DW_OP_stack_value] $r0, 115
	@DEBUG_VALUE: s1 <- [DW_OP_plus_uconst 8, DW_OP_plus_uconst 2, DW_OP_plus_uconst 1, DW_OP_stack_value] $sp
	@DEBUG_VALUE: strncmp:string1 <- [DW_OP_plus_uconst 8, DW_OP_stack_value] $sp
	@DEBUG_VALUE: strncmp:n <- undef
	@DEBUG_VALUE: s2 <- undef
	@DEBUG_VALUE: s1 <- [DW_OP_plus_uconst 8, DW_OP_plus_uconst 3, DW_OP_plus_uconst 1, DW_OP_stack_value] $sp
	.loc	2 0 10                          @ /opt/ti-cgt-armllvm_4.0.3.LTS/include/c/string.h:0:10
	add	r0, sp, #8
.Ltmp17:
	.loc	2 437 35                        @ /opt/ti-cgt-armllvm_4.0.3.LTS/include/c/string.h:437:35
	ldrb	r0, [r0, #3]
.Ltmp18:
	@DEBUG_VALUE: result <- [DW_OP_LLVM_arg 0, DW_OP_LLVM_convert 8 7, DW_OP_LLVM_convert 32 7, DW_OP_LLVM_arg 1, DW_OP_LLVM_convert 8 7, DW_OP_LLVM_convert 32 7, DW_OP_minus, DW_OP_stack_value] $r0, 115
	@DEBUG_VALUE: cp <- 115
	.loc	2 437 10                        @ /opt/ti-cgt-armllvm_4.0.3.LTS/include/c/string.h:437:10
	cmp	r0, #115
	mov	r1, r7
	bne	.LBB0_17
.Ltmp19:
@ %bb.7:                                @   in Loop: Header=BB0_3 Depth=1
	@DEBUG_VALUE: s1 <- [DW_OP_plus_uconst 8, DW_OP_plus_uconst 3, DW_OP_plus_uconst 1, DW_OP_stack_value] $sp
	@DEBUG_VALUE: cp <- 115
	@DEBUG_VALUE: result <- [DW_OP_LLVM_arg 0, DW_OP_LLVM_convert 8 7, DW_OP_LLVM_convert 32 7, DW_OP_LLVM_arg 1, DW_OP_LLVM_convert 8 7, DW_OP_LLVM_convert 32 7, DW_OP_minus, DW_OP_stack_value] $r0, 115
	@DEBUG_VALUE: strncmp:string1 <- [DW_OP_plus_uconst 8, DW_OP_stack_value] $sp
	@DEBUG_VALUE: strncmp:n <- undef
	@DEBUG_VALUE: s2 <- undef
	@DEBUG_VALUE: s1 <- [DW_OP_plus_uconst 8, DW_OP_plus_uconst 4, DW_OP_plus_uconst 1, DW_OP_stack_value] $sp
	.loc	2 0 10                          @ /opt/ti-cgt-armllvm_4.0.3.LTS/include/c/string.h:0:10
	add	r0, sp, #8
.Ltmp20:
	.loc	2 437 35                        @ /opt/ti-cgt-armllvm_4.0.3.LTS/include/c/string.h:437:35
	ldrb	r0, [r0, #4]
.Ltmp21:
	@DEBUG_VALUE: result <- [DW_OP_LLVM_arg 0, DW_OP_LLVM_convert 8 7, DW_OP_LLVM_convert 32 7, DW_OP_LLVM_arg 1, DW_OP_LLVM_convert 8 7, DW_OP_LLVM_convert 32 7, DW_OP_minus, DW_OP_stack_value] $r0, 119
	@DEBUG_VALUE: cp <- 119
	.loc	2 437 10                        @ /opt/ti-cgt-armllvm_4.0.3.LTS/include/c/string.h:437:10
	cmp	r0, #119
	bne	.LBB0_19
.Ltmp22:
@ %bb.8:                                @   in Loop: Header=BB0_3 Depth=1
	@DEBUG_VALUE: cp <- 119
	@DEBUG_VALUE: result <- [DW_OP_LLVM_arg 0, DW_OP_LLVM_convert 8 7, DW_OP_LLVM_convert 32 7, DW_OP_LLVM_arg 1, DW_OP_LLVM_convert 8 7, DW_OP_LLVM_convert 32 7, DW_OP_minus, DW_OP_stack_value] $r0, 119
	@DEBUG_VALUE: s1 <- [DW_OP_plus_uconst 8, DW_OP_plus_uconst 4, DW_OP_plus_uconst 1, DW_OP_stack_value] $sp
	@DEBUG_VALUE: strncmp:string1 <- [DW_OP_plus_uconst 8, DW_OP_stack_value] $sp
	@DEBUG_VALUE: strncmp:n <- undef
	@DEBUG_VALUE: s2 <- undef
	@DEBUG_VALUE: s1 <- [DW_OP_plus_uconst 8, DW_OP_plus_uconst 5, DW_OP_plus_uconst 1, DW_OP_stack_value] $sp
	.loc	2 0 10                          @ /opt/ti-cgt-armllvm_4.0.3.LTS/include/c/string.h:0:10
	add	r0, sp, #8
.Ltmp23:
	.loc	2 437 35                        @ /opt/ti-cgt-armllvm_4.0.3.LTS/include/c/string.h:437:35
	ldrb	r0, [r0, #5]
.Ltmp24:
	@DEBUG_VALUE: result <- [DW_OP_LLVM_arg 0, DW_OP_LLVM_convert 8 7, DW_OP_LLVM_convert 32 7, DW_OP_LLVM_arg 1, DW_OP_LLVM_convert 8 7, DW_OP_LLVM_convert 32 7, DW_OP_minus, DW_OP_stack_value] $r0, 111
	@DEBUG_VALUE: cp <- 111
	.loc	2 437 10                        @ /opt/ti-cgt-armllvm_4.0.3.LTS/include/c/string.h:437:10
	cmp	r0, #111
	bne	.LBB0_20
.Ltmp25:
@ %bb.9:                                @   in Loop: Header=BB0_3 Depth=1
	@DEBUG_VALUE: cp <- 111
	@DEBUG_VALUE: result <- [DW_OP_LLVM_arg 0, DW_OP_LLVM_convert 8 7, DW_OP_LLVM_convert 32 7, DW_OP_LLVM_arg 1, DW_OP_LLVM_convert 8 7, DW_OP_LLVM_convert 32 7, DW_OP_minus, DW_OP_stack_value] $r0, 111
	@DEBUG_VALUE: s1 <- [DW_OP_plus_uconst 8, DW_OP_plus_uconst 5, DW_OP_plus_uconst 1, DW_OP_stack_value] $sp
	@DEBUG_VALUE: strncmp:string1 <- [DW_OP_plus_uconst 8, DW_OP_stack_value] $sp
	@DEBUG_VALUE: strncmp:n <- undef
	@DEBUG_VALUE: s2 <- undef
	@DEBUG_VALUE: s1 <- [DW_OP_plus_uconst 8, DW_OP_plus_uconst 6, DW_OP_plus_uconst 1, DW_OP_stack_value] $sp
	.loc	2 0 10                          @ /opt/ti-cgt-armllvm_4.0.3.LTS/include/c/string.h:0:10
	add	r0, sp, #8
.Ltmp26:
	.loc	2 437 35                        @ /opt/ti-cgt-armllvm_4.0.3.LTS/include/c/string.h:437:35
	ldrb	r0, [r0, #6]
.Ltmp27:
	@DEBUG_VALUE: result <- [DW_OP_LLVM_arg 0, DW_OP_LLVM_convert 8 7, DW_OP_LLVM_convert 32 7, DW_OP_LLVM_arg 1, DW_OP_LLVM_convert 8 7, DW_OP_LLVM_convert 32 7, DW_OP_minus, DW_OP_stack_value] $r0, 114
	@DEBUG_VALUE: cp <- 114
	.loc	2 437 10                        @ /opt/ti-cgt-armllvm_4.0.3.LTS/include/c/string.h:437:10
	cmp	r0, #114
	bne	.LBB0_21
.Ltmp28:
@ %bb.10:                               @   in Loop: Header=BB0_3 Depth=1
	@DEBUG_VALUE: cp <- 114
	@DEBUG_VALUE: result <- [DW_OP_LLVM_arg 0, DW_OP_LLVM_convert 8 7, DW_OP_LLVM_convert 32 7, DW_OP_LLVM_arg 1, DW_OP_LLVM_convert 8 7, DW_OP_LLVM_convert 32 7, DW_OP_minus, DW_OP_stack_value] $r0, 114
	@DEBUG_VALUE: s1 <- [DW_OP_plus_uconst 8, DW_OP_plus_uconst 6, DW_OP_plus_uconst 1, DW_OP_stack_value] $sp
	@DEBUG_VALUE: strncmp:string1 <- [DW_OP_plus_uconst 8, DW_OP_stack_value] $sp
	@DEBUG_VALUE: strncmp:n <- undef
	@DEBUG_VALUE: s2 <- undef
	@DEBUG_VALUE: s1 <- [DW_OP_plus_uconst 8, DW_OP_plus_uconst 7, DW_OP_plus_uconst 1, DW_OP_stack_value] $sp
	.loc	2 0 10                          @ /opt/ti-cgt-armllvm_4.0.3.LTS/include/c/string.h:0:10
	add	r0, sp, #8
.Ltmp29:
	.loc	2 437 35                        @ /opt/ti-cgt-armllvm_4.0.3.LTS/include/c/string.h:437:35
	ldrb	r0, [r0, #7]
.Ltmp30:
	@DEBUG_VALUE: result <- [DW_OP_LLVM_arg 0, DW_OP_LLVM_convert 8 7, DW_OP_LLVM_convert 32 7, DW_OP_LLVM_arg 1, DW_OP_LLVM_convert 8 7, DW_OP_LLVM_convert 32 7, DW_OP_minus, DW_OP_stack_value] $r0, 100
	@DEBUG_VALUE: cp <- 100
	.loc	2 437 10                        @ /opt/ti-cgt-armllvm_4.0.3.LTS/include/c/string.h:437:10
	cmp	r0, #100
	bne	.LBB0_22
.Ltmp31:
@ %bb.11:                               @   in Loop: Header=BB0_3 Depth=1
	@DEBUG_VALUE: cp <- 100
	@DEBUG_VALUE: result <- [DW_OP_LLVM_arg 0, DW_OP_LLVM_convert 8 7, DW_OP_LLVM_convert 32 7, DW_OP_LLVM_arg 1, DW_OP_LLVM_convert 8 7, DW_OP_LLVM_convert 32 7, DW_OP_minus, DW_OP_stack_value] $r0, 100
	@DEBUG_VALUE: s1 <- [DW_OP_plus_uconst 8, DW_OP_plus_uconst 7, DW_OP_plus_uconst 1, DW_OP_stack_value] $sp
	@DEBUG_VALUE: strncmp:string1 <- [DW_OP_plus_uconst 8, DW_OP_stack_value] $sp
	@DEBUG_VALUE: strncmp:n <- undef
	@DEBUG_VALUE: s2 <- undef
	@DEBUG_VALUE: s1 <- [DW_OP_plus_uconst 8, DW_OP_plus_uconst 8, DW_OP_plus_uconst 1, DW_OP_stack_value] $sp
	.loc	2 0 10                          @ /opt/ti-cgt-armllvm_4.0.3.LTS/include/c/string.h:0:10
	add	r0, sp, #8
.Ltmp32:
	.loc	2 437 35                        @ /opt/ti-cgt-armllvm_4.0.3.LTS/include/c/string.h:437:35
	ldrb	r0, [r0, #8]
.Ltmp33:
	@DEBUG_VALUE: result <- [DW_OP_LLVM_arg 0, DW_OP_LLVM_convert 8 7, DW_OP_LLVM_convert 32 7, DW_OP_LLVM_arg 1, DW_OP_LLVM_convert 8 7, DW_OP_LLVM_convert 32 7, DW_OP_minus, DW_OP_stack_value] $r0, 49
	@DEBUG_VALUE: cp <- 49
	.loc	2 437 10                        @ /opt/ti-cgt-armllvm_4.0.3.LTS/include/c/string.h:437:10
	cmp	r0, #49
	bne	.LBB0_23
.Ltmp34:
@ %bb.12:                               @   in Loop: Header=BB0_3 Depth=1
	@DEBUG_VALUE: cp <- 49
	@DEBUG_VALUE: result <- [DW_OP_LLVM_arg 0, DW_OP_LLVM_convert 8 7, DW_OP_LLVM_convert 32 7, DW_OP_LLVM_arg 1, DW_OP_LLVM_convert 8 7, DW_OP_LLVM_convert 32 7, DW_OP_minus, DW_OP_stack_value] $r0, 49
	@DEBUG_VALUE: s1 <- [DW_OP_plus_uconst 8, DW_OP_plus_uconst 8, DW_OP_plus_uconst 1, DW_OP_stack_value] $sp
	@DEBUG_VALUE: strncmp:string1 <- [DW_OP_plus_uconst 8, DW_OP_stack_value] $sp
	@DEBUG_VALUE: strncmp:n <- undef
	@DEBUG_VALUE: s2 <- undef
	@DEBUG_VALUE: s1 <- [DW_OP_plus_uconst 8, DW_OP_plus_uconst 9, DW_OP_plus_uconst 1, DW_OP_stack_value] $sp
	.loc	2 0 10                          @ /opt/ti-cgt-armllvm_4.0.3.LTS/include/c/string.h:0:10
	add	r0, sp, #8
.Ltmp35:
	.loc	2 437 35                        @ /opt/ti-cgt-armllvm_4.0.3.LTS/include/c/string.h:437:35
	ldrb	r0, [r0, #9]
.Ltmp36:
	@DEBUG_VALUE: result <- [DW_OP_LLVM_arg 0, DW_OP_LLVM_convert 8 7, DW_OP_LLVM_convert 32 7, DW_OP_LLVM_arg 1, DW_OP_LLVM_convert 8 7, DW_OP_LLVM_convert 32 7, DW_OP_minus, DW_OP_stack_value] $r0, 50
	@DEBUG_VALUE: cp <- 50
	.loc	2 437 10                        @ /opt/ti-cgt-armllvm_4.0.3.LTS/include/c/string.h:437:10
	cmp	r0, #50
	bne	.LBB0_24
.Ltmp37:
@ %bb.13:                               @   in Loop: Header=BB0_3 Depth=1
	@DEBUG_VALUE: cp <- 50
	@DEBUG_VALUE: result <- [DW_OP_LLVM_arg 0, DW_OP_LLVM_convert 8 7, DW_OP_LLVM_convert 32 7, DW_OP_LLVM_arg 1, DW_OP_LLVM_convert 8 7, DW_OP_LLVM_convert 32 7, DW_OP_minus, DW_OP_stack_value] $r0, 50
	@DEBUG_VALUE: s1 <- [DW_OP_plus_uconst 8, DW_OP_plus_uconst 9, DW_OP_plus_uconst 1, DW_OP_stack_value] $sp
	@DEBUG_VALUE: strncmp:string1 <- [DW_OP_plus_uconst 8, DW_OP_stack_value] $sp
	@DEBUG_VALUE: strncmp:n <- undef
	@DEBUG_VALUE: s2 <- undef
	@DEBUG_VALUE: s1 <- [DW_OP_plus_uconst 8, DW_OP_plus_uconst 10, DW_OP_plus_uconst 1, DW_OP_stack_value] $sp
	.loc	2 0 10                          @ /opt/ti-cgt-armllvm_4.0.3.LTS/include/c/string.h:0:10
	add	r0, sp, #8
.Ltmp38:
	.loc	2 437 35                        @ /opt/ti-cgt-armllvm_4.0.3.LTS/include/c/string.h:437:35
	ldrb	r0, [r0, #10]
.Ltmp39:
	@DEBUG_VALUE: result <- [DW_OP_LLVM_arg 0, DW_OP_LLVM_convert 8 7, DW_OP_LLVM_convert 32 7, DW_OP_LLVM_arg 1, DW_OP_LLVM_convert 8 7, DW_OP_LLVM_convert 32 7, DW_OP_minus, DW_OP_stack_value] $r0, 51
	@DEBUG_VALUE: cp <- 51
	.loc	2 437 10                        @ /opt/ti-cgt-armllvm_4.0.3.LTS/include/c/string.h:437:10
	cmp	r0, #51
	beq	.LBB0_18
.Ltmp40:
@ %bb.14:                               @   in Loop: Header=BB0_3 Depth=1
	@DEBUG_VALUE: cp <- 51
	@DEBUG_VALUE: result <- [DW_OP_LLVM_arg 0, DW_OP_LLVM_convert 8 7, DW_OP_LLVM_convert 32 7, DW_OP_LLVM_arg 1, DW_OP_LLVM_convert 8 7, DW_OP_LLVM_convert 32 7, DW_OP_minus, DW_OP_stack_value] $r0, 51
	@DEBUG_VALUE: s1 <- [DW_OP_plus_uconst 8, DW_OP_plus_uconst 10, DW_OP_plus_uconst 1, DW_OP_stack_value] $sp
	@DEBUG_VALUE: strncmp:string1 <- [DW_OP_plus_uconst 8, DW_OP_stack_value] $sp
	.loc	2 0 10                          @ /opt/ti-cgt-armllvm_4.0.3.LTS/include/c/string.h:0:10
	mov	r1, r7
	adds	r1, #64
	b	.LBB0_17
.Ltmp41:
.LBB0_15:                               @   in Loop: Header=BB0_3 Depth=1
	@DEBUG_VALUE: cp <- 112
	@DEBUG_VALUE: result <- [DW_OP_LLVM_arg 0, DW_OP_LLVM_convert 8 7, DW_OP_LLVM_convert 32 7, DW_OP_LLVM_arg 1, DW_OP_LLVM_convert 8 7, DW_OP_LLVM_convert 32 7, DW_OP_minus, DW_OP_stack_value] $r0, 112
	@DEBUG_VALUE: strncmp:string1 <- [DW_OP_plus_uconst 8, DW_OP_stack_value] $sp
	@DEBUG_VALUE: s1 <- [DW_OP_plus_uconst 8, DW_OP_plus_uconst 1, DW_OP_stack_value] $sp
	adds	r1, r7, #3
	b	.LBB0_17
.Ltmp42:
.LBB0_16:                               @   in Loop: Header=BB0_3 Depth=1
	@DEBUG_VALUE: cp <- 97
	@DEBUG_VALUE: result <- [DW_OP_LLVM_arg 0, DW_OP_LLVM_convert 8 7, DW_OP_LLVM_convert 32 7, DW_OP_LLVM_arg 1, DW_OP_LLVM_convert 8 7, DW_OP_LLVM_convert 32 7, DW_OP_minus, DW_OP_stack_value] $r0, 97
	@DEBUG_VALUE: s1 <- [DW_OP_plus_uconst 8, DW_OP_plus_uconst 1, DW_OP_plus_uconst 1, DW_OP_stack_value] $sp
	@DEBUG_VALUE: strncmp:string1 <- [DW_OP_plus_uconst 8, DW_OP_stack_value] $sp
	mov	r1, r7
	adds	r1, #18
.Ltmp43:
.LBB0_17:                               @   in Loop: Header=BB0_3 Depth=1
	@DEBUG_VALUE: strncmp:string1 <- [DW_OP_plus_uconst 8, DW_OP_stack_value] $sp
	@DEBUG_VALUE: result <- undef
	.loc	2 437 41                        @ /opt/ti-cgt-armllvm_4.0.3.LTS/include/c/string.h:437:41
	adds	r5, r1, r0
.Ltmp44:
	@DEBUG_VALUE: result <- $r5
.LBB0_18:                               @   in Loop: Header=BB0_3 Depth=1
	.loc	1 20 13 is_stmt 1               @ password/main.c:20:13
	str	r5, [sp, #4]
	.loc	1 21 9                          @ password/main.c:21:9
	bl	led_blip
.Ltmp45:
	.loc	1 22 13                         @ password/main.c:22:13
	ldr	r0, [sp, #4]
.Ltmp46:
	.loc	1 22 5 is_stmt 0                @ password/main.c:22:5
	cmp	r0, #0
	bne	.LBB0_3
	b	.LBB0_25
.Ltmp47:
.LBB0_19:                               @   in Loop: Header=BB0_3 Depth=1
	@DEBUG_VALUE: cp <- 119
	@DEBUG_VALUE: result <- [DW_OP_LLVM_arg 0, DW_OP_LLVM_convert 8 7, DW_OP_LLVM_convert 32 7, DW_OP_LLVM_arg 1, DW_OP_LLVM_convert 8 7, DW_OP_LLVM_convert 32 7, DW_OP_minus, DW_OP_stack_value] $r0, 119
	@DEBUG_VALUE: s1 <- [DW_OP_plus_uconst 8, DW_OP_plus_uconst 4, DW_OP_plus_uconst 1, DW_OP_stack_value] $sp
	@DEBUG_VALUE: strncmp:string1 <- [DW_OP_plus_uconst 8, DW_OP_stack_value] $sp
	.loc	1 0 5                           @ password/main.c:0:5
	subs	r1, r7, #4
	b	.LBB0_17
.LBB0_20:                               @   in Loop: Header=BB0_3 Depth=1
	@DEBUG_VALUE: cp <- 111
	@DEBUG_VALUE: result <- [DW_OP_LLVM_arg 0, DW_OP_LLVM_convert 8 7, DW_OP_LLVM_convert 32 7, DW_OP_LLVM_arg 1, DW_OP_LLVM_convert 8 7, DW_OP_LLVM_convert 32 7, DW_OP_minus, DW_OP_stack_value] $r0, 111
	@DEBUG_VALUE: s1 <- [DW_OP_plus_uconst 8, DW_OP_plus_uconst 5, DW_OP_plus_uconst 1, DW_OP_stack_value] $sp
	@DEBUG_VALUE: strncmp:string1 <- [DW_OP_plus_uconst 8, DW_OP_stack_value] $sp
	adds	r1, r7, #4
	b	.LBB0_17
.LBB0_21:                               @   in Loop: Header=BB0_3 Depth=1
	@DEBUG_VALUE: cp <- 114
	@DEBUG_VALUE: result <- [DW_OP_LLVM_arg 0, DW_OP_LLVM_convert 8 7, DW_OP_LLVM_convert 32 7, DW_OP_LLVM_arg 1, DW_OP_LLVM_convert 8 7, DW_OP_LLVM_convert 32 7, DW_OP_minus, DW_OP_stack_value] $r0, 114
	@DEBUG_VALUE: s1 <- [DW_OP_plus_uconst 8, DW_OP_plus_uconst 6, DW_OP_plus_uconst 1, DW_OP_stack_value] $sp
	@DEBUG_VALUE: strncmp:string1 <- [DW_OP_plus_uconst 8, DW_OP_stack_value] $sp
	adds	r1, r7, #1
	b	.LBB0_17
.LBB0_22:                               @   in Loop: Header=BB0_3 Depth=1
	@DEBUG_VALUE: cp <- 100
	@DEBUG_VALUE: result <- [DW_OP_LLVM_arg 0, DW_OP_LLVM_convert 8 7, DW_OP_LLVM_convert 32 7, DW_OP_LLVM_arg 1, DW_OP_LLVM_convert 8 7, DW_OP_LLVM_convert 32 7, DW_OP_minus, DW_OP_stack_value] $r0, 100
	@DEBUG_VALUE: s1 <- [DW_OP_plus_uconst 8, DW_OP_plus_uconst 7, DW_OP_plus_uconst 1, DW_OP_stack_value] $sp
	@DEBUG_VALUE: strncmp:string1 <- [DW_OP_plus_uconst 8, DW_OP_stack_value] $sp
	mov	r1, r7
	adds	r1, #15
	b	.LBB0_17
.LBB0_23:                               @   in Loop: Header=BB0_3 Depth=1
	@DEBUG_VALUE: cp <- 49
	@DEBUG_VALUE: result <- [DW_OP_LLVM_arg 0, DW_OP_LLVM_convert 8 7, DW_OP_LLVM_convert 32 7, DW_OP_LLVM_arg 1, DW_OP_LLVM_convert 8 7, DW_OP_LLVM_convert 32 7, DW_OP_minus, DW_OP_stack_value] $r0, 49
	@DEBUG_VALUE: s1 <- [DW_OP_plus_uconst 8, DW_OP_plus_uconst 8, DW_OP_plus_uconst 1, DW_OP_stack_value] $sp
	@DEBUG_VALUE: strncmp:string1 <- [DW_OP_plus_uconst 8, DW_OP_stack_value] $sp
	mov	r1, r7
	adds	r1, #66
	b	.LBB0_17
.LBB0_24:                               @   in Loop: Header=BB0_3 Depth=1
	@DEBUG_VALUE: cp <- 50
	@DEBUG_VALUE: result <- [DW_OP_LLVM_arg 0, DW_OP_LLVM_convert 8 7, DW_OP_LLVM_convert 32 7, DW_OP_LLVM_arg 1, DW_OP_LLVM_convert 8 7, DW_OP_LLVM_convert 32 7, DW_OP_minus, DW_OP_stack_value] $r0, 50
	@DEBUG_VALUE: s1 <- [DW_OP_plus_uconst 8, DW_OP_plus_uconst 9, DW_OP_plus_uconst 1, DW_OP_stack_value] $sp
	@DEBUG_VALUE: strncmp:string1 <- [DW_OP_plus_uconst 8, DW_OP_stack_value] $sp
	mov	r1, r7
	adds	r1, #65
	b	.LBB0_17
.LBB0_25:
	.loc	1 23 5 is_stmt 1                @ password/main.c:23:5
	ldr	r1, .LCPI0_1
	movs	r0, #0
	movs	r2, #16
	bl	_write
.Ltmp48:
.LBB0_26:                               @ =>This Inner Loop Header: Depth=1
	.loc	1 24 5                          @ password/main.c:24:5
	b	.LBB0_26
.Ltmp49:
	.p2align	2
@ %bb.27:
	.loc	1 0 5 is_stmt 0                 @ password/main.c:0:5
.LCPI0_0:
	.long	.L.str
.LCPI0_1:
	.long	.L.str.2
.Lfunc_end0:
	.size	main, .Lfunc_end0-main
	.cfi_endproc
	.cantunwind
	.fnend
                                        @ -- End function
	.type	.L.str,%object                  @ @.str
	.section	.rodata.str1.15159059442110792349.1,"aMS",%progbits,1
.L.str:
	.asciz	"\nenter a password:"
	.size	.L.str, 19

	.type	.L.str.2,%object                @ @.str.2
	.section	.rodata.str1.17100691992556644108.1,"aMS",%progbits,1
.L.str.2:
	.asciz	"\naccess granted.\n"
	.size	.L.str.2, 18

	.section	.debug_loc,"",%progbits
.Ldebug_loc0:
	.long	.Ltmp9-.Lfunc_begin0
	.long	.Ltmp12-.Lfunc_begin0
	.short	2                               @ Loc expr size
	.byte	16                              @ DW_OP_constu
	.byte	112                             @ 112
	.long	.Ltmp12-.Lfunc_begin0
	.long	.Ltmp15-.Lfunc_begin0
	.short	2                               @ Loc expr size
	.byte	16                              @ DW_OP_constu
	.byte	97                              @ 97
	.long	.Ltmp15-.Lfunc_begin0
	.long	.Ltmp21-.Lfunc_begin0
	.short	2                               @ Loc expr size
	.byte	16                              @ DW_OP_constu
	.byte	115                             @ 115
	.long	.Ltmp21-.Lfunc_begin0
	.long	.Ltmp24-.Lfunc_begin0
	.short	2                               @ Loc expr size
	.byte	16                              @ DW_OP_constu
	.byte	119                             @ 119
	.long	.Ltmp24-.Lfunc_begin0
	.long	.Ltmp27-.Lfunc_begin0
	.short	2                               @ Loc expr size
	.byte	16                              @ DW_OP_constu
	.byte	111                             @ 111
	.long	.Ltmp27-.Lfunc_begin0
	.long	.Ltmp30-.Lfunc_begin0
	.short	2                               @ Loc expr size
	.byte	16                              @ DW_OP_constu
	.byte	114                             @ 114
	.long	.Ltmp30-.Lfunc_begin0
	.long	.Ltmp33-.Lfunc_begin0
	.short	2                               @ Loc expr size
	.byte	16                              @ DW_OP_constu
	.byte	100                             @ 100
	.long	.Ltmp33-.Lfunc_begin0
	.long	.Ltmp36-.Lfunc_begin0
	.short	2                               @ Loc expr size
	.byte	16                              @ DW_OP_constu
	.byte	49                              @ 49
	.long	.Ltmp36-.Lfunc_begin0
	.long	.Ltmp39-.Lfunc_begin0
	.short	2                               @ Loc expr size
	.byte	16                              @ DW_OP_constu
	.byte	50                              @ 50
	.long	.Ltmp39-.Lfunc_begin0
	.long	.Ltmp41-.Lfunc_begin0
	.short	2                               @ Loc expr size
	.byte	16                              @ DW_OP_constu
	.byte	51                              @ 51
	.long	.Ltmp41-.Lfunc_begin0
	.long	.Ltmp42-.Lfunc_begin0
	.short	2                               @ Loc expr size
	.byte	16                              @ DW_OP_constu
	.byte	112                             @ 112
	.long	.Ltmp42-.Lfunc_begin0
	.long	.Ltmp43-.Lfunc_begin0
	.short	2                               @ Loc expr size
	.byte	16                              @ DW_OP_constu
	.byte	97                              @ 97
	.long	0
	.long	0
	.section	.debug_abbrev,"",%progbits
	.byte	1                               @ Abbreviation Code
	.byte	17                              @ DW_TAG_compile_unit
	.byte	1                               @ DW_CHILDREN_yes
	.byte	37                              @ DW_AT_producer
	.byte	14                              @ DW_FORM_strp
	.byte	19                              @ DW_AT_language
	.byte	5                               @ DW_FORM_data2
	.byte	3                               @ DW_AT_name
	.byte	14                              @ DW_FORM_strp
	.byte	16                              @ DW_AT_stmt_list
	.byte	6                               @ DW_FORM_data4
	.byte	27                              @ DW_AT_comp_dir
	.byte	14                              @ DW_FORM_strp
	.byte	17                              @ DW_AT_low_pc
	.byte	1                               @ DW_FORM_addr
	.byte	18                              @ DW_AT_high_pc
	.byte	1                               @ DW_FORM_addr
	.byte	0                               @ EOM(1)
	.byte	0                               @ EOM(2)
	.byte	2                               @ Abbreviation Code
	.byte	52                              @ DW_TAG_variable
	.byte	0                               @ DW_CHILDREN_no
	.byte	73                              @ DW_AT_type
	.byte	19                              @ DW_FORM_ref4
	.byte	58                              @ DW_AT_decl_file
	.byte	11                              @ DW_FORM_data1
	.byte	59                              @ DW_AT_decl_line
	.byte	11                              @ DW_FORM_data1
	.byte	2                               @ DW_AT_location
	.byte	10                              @ DW_FORM_block1
	.byte	0                               @ EOM(1)
	.byte	0                               @ EOM(2)
	.byte	3                               @ Abbreviation Code
	.byte	1                               @ DW_TAG_array_type
	.byte	1                               @ DW_CHILDREN_yes
	.byte	73                              @ DW_AT_type
	.byte	19                              @ DW_FORM_ref4
	.byte	0                               @ EOM(1)
	.byte	0                               @ EOM(2)
	.byte	4                               @ Abbreviation Code
	.byte	33                              @ DW_TAG_subrange_type
	.byte	0                               @ DW_CHILDREN_no
	.byte	73                              @ DW_AT_type
	.byte	19                              @ DW_FORM_ref4
	.byte	55                              @ DW_AT_count
	.byte	11                              @ DW_FORM_data1
	.byte	0                               @ EOM(1)
	.byte	0                               @ EOM(2)
	.byte	5                               @ Abbreviation Code
	.byte	36                              @ DW_TAG_base_type
	.byte	0                               @ DW_CHILDREN_no
	.byte	3                               @ DW_AT_name
	.byte	14                              @ DW_FORM_strp
	.byte	62                              @ DW_AT_encoding
	.byte	11                              @ DW_FORM_data1
	.byte	11                              @ DW_AT_byte_size
	.byte	11                              @ DW_FORM_data1
	.byte	0                               @ EOM(1)
	.byte	0                               @ EOM(2)
	.byte	6                               @ Abbreviation Code
	.byte	36                              @ DW_TAG_base_type
	.byte	0                               @ DW_CHILDREN_no
	.byte	3                               @ DW_AT_name
	.byte	14                              @ DW_FORM_strp
	.byte	11                              @ DW_AT_byte_size
	.byte	11                              @ DW_FORM_data1
	.byte	62                              @ DW_AT_encoding
	.byte	11                              @ DW_FORM_data1
	.byte	0                               @ EOM(1)
	.byte	0                               @ EOM(2)
	.byte	7                               @ Abbreviation Code
	.byte	52                              @ DW_TAG_variable
	.byte	0                               @ DW_CHILDREN_no
	.byte	73                              @ DW_AT_type
	.byte	19                              @ DW_FORM_ref4
	.byte	58                              @ DW_AT_decl_file
	.byte	11                              @ DW_FORM_data1
	.byte	59                              @ DW_AT_decl_line
	.byte	11                              @ DW_FORM_data1
	.byte	0                               @ EOM(1)
	.byte	0                               @ EOM(2)
	.byte	8                               @ Abbreviation Code
	.byte	22                              @ DW_TAG_typedef
	.byte	0                               @ DW_CHILDREN_no
	.byte	73                              @ DW_AT_type
	.byte	19                              @ DW_FORM_ref4
	.byte	3                               @ DW_AT_name
	.byte	14                              @ DW_FORM_strp
	.byte	58                              @ DW_AT_decl_file
	.byte	11                              @ DW_FORM_data1
	.byte	59                              @ DW_AT_decl_line
	.byte	11                              @ DW_FORM_data1
	.byte	0                               @ EOM(1)
	.byte	0                               @ EOM(2)
	.byte	9                               @ Abbreviation Code
	.byte	46                              @ DW_TAG_subprogram
	.byte	1                               @ DW_CHILDREN_yes
	.byte	3                               @ DW_AT_name
	.byte	14                              @ DW_FORM_strp
	.byte	58                              @ DW_AT_decl_file
	.byte	11                              @ DW_FORM_data1
	.byte	59                              @ DW_AT_decl_line
	.byte	5                               @ DW_FORM_data2
	.byte	39                              @ DW_AT_prototyped
	.byte	12                              @ DW_FORM_flag
	.byte	54                              @ DW_AT_calling_convention
	.byte	11                              @ DW_FORM_data1
	.byte	73                              @ DW_AT_type
	.byte	19                              @ DW_FORM_ref4
	.byte	32                              @ DW_AT_inline
	.byte	11                              @ DW_FORM_data1
	.byte	0                               @ EOM(1)
	.byte	0                               @ EOM(2)
	.byte	10                              @ Abbreviation Code
	.byte	5                               @ DW_TAG_formal_parameter
	.byte	0                               @ DW_CHILDREN_no
	.byte	3                               @ DW_AT_name
	.byte	14                              @ DW_FORM_strp
	.byte	58                              @ DW_AT_decl_file
	.byte	11                              @ DW_FORM_data1
	.byte	59                              @ DW_AT_decl_line
	.byte	5                               @ DW_FORM_data2
	.byte	73                              @ DW_AT_type
	.byte	19                              @ DW_FORM_ref4
	.byte	0                               @ EOM(1)
	.byte	0                               @ EOM(2)
	.byte	11                              @ Abbreviation Code
	.byte	11                              @ DW_TAG_lexical_block
	.byte	1                               @ DW_CHILDREN_yes
	.byte	0                               @ EOM(1)
	.byte	0                               @ EOM(2)
	.byte	12                              @ Abbreviation Code
	.byte	52                              @ DW_TAG_variable
	.byte	0                               @ DW_CHILDREN_no
	.byte	3                               @ DW_AT_name
	.byte	14                              @ DW_FORM_strp
	.byte	58                              @ DW_AT_decl_file
	.byte	11                              @ DW_FORM_data1
	.byte	59                              @ DW_AT_decl_line
	.byte	5                               @ DW_FORM_data2
	.byte	73                              @ DW_AT_type
	.byte	19                              @ DW_FORM_ref4
	.byte	0                               @ EOM(1)
	.byte	0                               @ EOM(2)
	.byte	13                              @ Abbreviation Code
	.byte	15                              @ DW_TAG_pointer_type
	.byte	0                               @ DW_CHILDREN_no
	.byte	73                              @ DW_AT_type
	.byte	19                              @ DW_FORM_ref4
	.byte	0                               @ EOM(1)
	.byte	0                               @ EOM(2)
	.byte	14                              @ Abbreviation Code
	.byte	38                              @ DW_TAG_const_type
	.byte	0                               @ DW_CHILDREN_no
	.byte	73                              @ DW_AT_type
	.byte	19                              @ DW_FORM_ref4
	.byte	0                               @ EOM(1)
	.byte	0                               @ EOM(2)
	.byte	15                              @ Abbreviation Code
	.byte	46                              @ DW_TAG_subprogram
	.byte	1                               @ DW_CHILDREN_yes
	.byte	17                              @ DW_AT_low_pc
	.byte	1                               @ DW_FORM_addr
	.byte	18                              @ DW_AT_high_pc
	.byte	1                               @ DW_FORM_addr
	.byte	64                              @ DW_AT_frame_base
	.byte	10                              @ DW_FORM_block1
	.ascii	"\224@"                         @ DW_AT_TI_max_frame_size
	.byte	11                              @ DW_FORM_data1
	.byte	3                               @ DW_AT_name
	.byte	14                              @ DW_FORM_strp
	.byte	58                              @ DW_AT_decl_file
	.byte	11                              @ DW_FORM_data1
	.byte	59                              @ DW_AT_decl_line
	.byte	11                              @ DW_FORM_data1
	.byte	73                              @ DW_AT_type
	.byte	19                              @ DW_FORM_ref4
	.byte	63                              @ DW_AT_external
	.byte	12                              @ DW_FORM_flag
	.byte	0                               @ EOM(1)
	.byte	0                               @ EOM(2)
	.byte	16                              @ Abbreviation Code
	.byte	52                              @ DW_TAG_variable
	.byte	0                               @ DW_CHILDREN_no
	.byte	2                               @ DW_AT_location
	.byte	10                              @ DW_FORM_block1
	.byte	3                               @ DW_AT_name
	.byte	14                              @ DW_FORM_strp
	.byte	58                              @ DW_AT_decl_file
	.byte	11                              @ DW_FORM_data1
	.byte	59                              @ DW_AT_decl_line
	.byte	11                              @ DW_FORM_data1
	.byte	73                              @ DW_AT_type
	.byte	19                              @ DW_FORM_ref4
	.byte	0                               @ EOM(1)
	.byte	0                               @ EOM(2)
	.byte	17                              @ Abbreviation Code
	.byte	11                              @ DW_TAG_lexical_block
	.byte	1                               @ DW_CHILDREN_yes
	.byte	85                              @ DW_AT_ranges
	.byte	6                               @ DW_FORM_data4
	.byte	0                               @ EOM(1)
	.byte	0                               @ EOM(2)
	.byte	18                              @ Abbreviation Code
	.byte	52                              @ DW_TAG_variable
	.byte	0                               @ DW_CHILDREN_no
	.byte	3                               @ DW_AT_name
	.byte	14                              @ DW_FORM_strp
	.byte	58                              @ DW_AT_decl_file
	.byte	11                              @ DW_FORM_data1
	.byte	59                              @ DW_AT_decl_line
	.byte	11                              @ DW_FORM_data1
	.byte	73                              @ DW_AT_type
	.byte	19                              @ DW_FORM_ref4
	.byte	0                               @ EOM(1)
	.byte	0                               @ EOM(2)
	.byte	19                              @ Abbreviation Code
	.byte	29                              @ DW_TAG_inlined_subroutine
	.byte	1                               @ DW_CHILDREN_yes
	.byte	49                              @ DW_AT_abstract_origin
	.byte	19                              @ DW_FORM_ref4
	.byte	17                              @ DW_AT_low_pc
	.byte	1                               @ DW_FORM_addr
	.byte	18                              @ DW_AT_high_pc
	.byte	1                               @ DW_FORM_addr
	.byte	88                              @ DW_AT_call_file
	.byte	11                              @ DW_FORM_data1
	.byte	89                              @ DW_AT_call_line
	.byte	11                              @ DW_FORM_data1
	.byte	87                              @ DW_AT_call_column
	.byte	11                              @ DW_FORM_data1
	.byte	0                               @ EOM(1)
	.byte	0                               @ EOM(2)
	.byte	20                              @ Abbreviation Code
	.byte	5                               @ DW_TAG_formal_parameter
	.byte	0                               @ DW_CHILDREN_no
	.byte	49                              @ DW_AT_abstract_origin
	.byte	19                              @ DW_FORM_ref4
	.byte	0                               @ EOM(1)
	.byte	0                               @ EOM(2)
	.byte	21                              @ Abbreviation Code
	.byte	11                              @ DW_TAG_lexical_block
	.byte	1                               @ DW_CHILDREN_yes
	.byte	17                              @ DW_AT_low_pc
	.byte	1                               @ DW_FORM_addr
	.byte	18                              @ DW_AT_high_pc
	.byte	1                               @ DW_FORM_addr
	.byte	0                               @ EOM(1)
	.byte	0                               @ EOM(2)
	.byte	22                              @ Abbreviation Code
	.byte	52                              @ DW_TAG_variable
	.byte	0                               @ DW_CHILDREN_no
	.byte	49                              @ DW_AT_abstract_origin
	.byte	19                              @ DW_FORM_ref4
	.byte	0                               @ EOM(1)
	.byte	0                               @ EOM(2)
	.byte	23                              @ Abbreviation Code
	.byte	52                              @ DW_TAG_variable
	.byte	0                               @ DW_CHILDREN_no
	.byte	2                               @ DW_AT_location
	.byte	6                               @ DW_FORM_data4
	.byte	49                              @ DW_AT_abstract_origin
	.byte	19                              @ DW_FORM_ref4
	.byte	0                               @ EOM(1)
	.byte	0                               @ EOM(2)
	.byte	24                              @ Abbreviation Code
	.ascii	"\210\201\001"                  @ DW_TAG_TI_reserved_3
	.byte	0                               @ DW_CHILDREN_no
	.byte	17                              @ DW_AT_low_pc
	.byte	1                               @ DW_FORM_addr
	.ascii	"\212@"                         @ DW_AT_TI_reserved_9
	.byte	12                              @ DW_FORM_flag
	.byte	3                               @ DW_AT_name
	.byte	14                              @ DW_FORM_strp
	.byte	0                               @ EOM(1)
	.byte	0                               @ EOM(2)
	.byte	25                              @ Abbreviation Code
	.byte	53                              @ DW_TAG_volatile_type
	.byte	0                               @ DW_CHILDREN_no
	.byte	73                              @ DW_AT_type
	.byte	19                              @ DW_FORM_ref4
	.byte	0                               @ EOM(1)
	.byte	0                               @ EOM(2)
	.byte	0                               @ EOM(3)
	.section	.debug_info,"",%progbits
.Lcu_begin0:
	.long	.Ldebug_info_end0-.Ldebug_info_start0 @ Length of Unit
.Ldebug_info_start0:
	.short	3                               @ DWARF version number
	.long	.debug_abbrev                   @ Offset Into Abbrev. Section
	.byte	4                               @ Address Size (in bytes)
	.byte	1                               @ Abbrev [1] 0xb:0x1e5 DW_TAG_compile_unit
	.long	.Linfo_string0                  @ DW_AT_producer
	.short	29                              @ DW_AT_language
	.long	.Linfo_string1                  @ DW_AT_name
	.long	.Lline_table_start0             @ DW_AT_stmt_list
	.long	.Linfo_string2                  @ DW_AT_comp_dir
	.long	.Lfunc_begin0                   @ DW_AT_low_pc
	.long	.Lfunc_end0                     @ DW_AT_high_pc
	.byte	2                               @ Abbrev [2] 0x26:0xd DW_TAG_variable
	.long	51                              @ DW_AT_type
	.byte	1                               @ DW_AT_decl_file
	.byte	18                              @ DW_AT_decl_line
	.byte	5                               @ DW_AT_location
	.byte	3
	.long	.L.str
	.byte	3                               @ Abbrev [3] 0x33:0xc DW_TAG_array_type
	.long	63                              @ DW_AT_type
	.byte	4                               @ Abbrev [4] 0x38:0x6 DW_TAG_subrange_type
	.long	70                              @ DW_AT_type
	.byte	19                              @ DW_AT_count
	.byte	0                               @ End Of Children Mark
	.byte	5                               @ Abbrev [5] 0x3f:0x7 DW_TAG_base_type
	.long	.Linfo_string3                  @ DW_AT_name
	.byte	8                               @ DW_AT_encoding
	.byte	1                               @ DW_AT_byte_size
	.byte	6                               @ Abbrev [6] 0x46:0x7 DW_TAG_base_type
	.long	.Linfo_string4                  @ DW_AT_name
	.byte	8                               @ DW_AT_byte_size
	.byte	7                               @ DW_AT_encoding
	.byte	7                               @ Abbrev [7] 0x4d:0x7 DW_TAG_variable
	.long	84                              @ DW_AT_type
	.byte	1                               @ DW_AT_decl_file
	.byte	20                              @ DW_AT_decl_line
	.byte	3                               @ Abbrev [3] 0x54:0xc DW_TAG_array_type
	.long	63                              @ DW_AT_type
	.byte	4                               @ Abbrev [4] 0x59:0x6 DW_TAG_subrange_type
	.long	70                              @ DW_AT_type
	.byte	12                              @ DW_AT_count
	.byte	0                               @ End Of Children Mark
	.byte	2                               @ Abbrev [2] 0x60:0xd DW_TAG_variable
	.long	109                             @ DW_AT_type
	.byte	1                               @ DW_AT_decl_file
	.byte	23                              @ DW_AT_decl_line
	.byte	5                               @ DW_AT_location
	.byte	3
	.long	.L.str.2
	.byte	3                               @ Abbrev [3] 0x6d:0xc DW_TAG_array_type
	.long	63                              @ DW_AT_type
	.byte	4                               @ Abbrev [4] 0x72:0x6 DW_TAG_subrange_type
	.long	70                              @ DW_AT_type
	.byte	18                              @ DW_AT_count
	.byte	0                               @ End Of Children Mark
	.byte	7                               @ Abbrev [7] 0x79:0x7 DW_TAG_variable
	.long	128                             @ DW_AT_type
	.byte	1                               @ DW_AT_decl_file
	.byte	23                              @ DW_AT_decl_line
	.byte	3                               @ Abbrev [3] 0x80:0xc DW_TAG_array_type
	.long	63                              @ DW_AT_type
	.byte	4                               @ Abbrev [4] 0x85:0x6 DW_TAG_subrange_type
	.long	70                              @ DW_AT_type
	.byte	17                              @ DW_AT_count
	.byte	0                               @ End Of Children Mark
	.byte	8                               @ Abbrev [8] 0x8c:0xb DW_TAG_typedef
	.long	151                             @ DW_AT_type
	.long	.Linfo_string6                  @ DW_AT_name
	.byte	2                               @ DW_AT_decl_file
	.byte	66                              @ DW_AT_decl_line
	.byte	5                               @ Abbrev [5] 0x97:0x7 DW_TAG_base_type
	.long	.Linfo_string5                  @ DW_AT_name
	.byte	7                               @ DW_AT_encoding
	.byte	4                               @ DW_AT_byte_size
	.byte	5                               @ Abbrev [5] 0x9e:0x7 DW_TAG_base_type
	.long	.Linfo_string7                  @ DW_AT_name
	.byte	8                               @ DW_AT_encoding
	.byte	1                               @ DW_AT_byte_size
	.byte	9                               @ Abbrev [9] 0xa5:0x66 DW_TAG_subprogram
	.long	.Linfo_string8                  @ DW_AT_name
	.byte	2                               @ DW_AT_decl_file
	.short	427                             @ DW_AT_decl_line
	.byte	1                               @ DW_AT_prototyped
	.byte	3                               @ DW_AT_calling_convention
	.long	267                             @ DW_AT_type
	.byte	1                               @ DW_AT_inline
	.byte	10                              @ Abbrev [10] 0xb4:0xc DW_TAG_formal_parameter
	.long	.Linfo_string10                 @ DW_AT_name
	.byte	2                               @ DW_AT_decl_file
	.short	427                             @ DW_AT_decl_line
	.long	274                             @ DW_AT_type
	.byte	10                              @ Abbrev [10] 0xc0:0xc DW_TAG_formal_parameter
	.long	.Linfo_string11                 @ DW_AT_name
	.byte	2                               @ DW_AT_decl_file
	.short	427                             @ DW_AT_decl_line
	.long	274                             @ DW_AT_type
	.byte	10                              @ Abbrev [10] 0xcc:0xc DW_TAG_formal_parameter
	.long	.Linfo_string12                 @ DW_AT_name
	.byte	2                               @ DW_AT_decl_file
	.short	427                             @ DW_AT_decl_line
	.long	140                             @ DW_AT_type
	.byte	11                              @ Abbrev [11] 0xd8:0x32 DW_TAG_lexical_block
	.byte	12                              @ Abbrev [12] 0xd9:0xc DW_TAG_variable
	.long	.Linfo_string13                 @ DW_AT_name
	.byte	2                               @ DW_AT_decl_file
	.short	431                             @ DW_AT_decl_line
	.long	274                             @ DW_AT_type
	.byte	12                              @ Abbrev [12] 0xe5:0xc DW_TAG_variable
	.long	.Linfo_string14                 @ DW_AT_name
	.byte	2                               @ DW_AT_decl_file
	.short	434                             @ DW_AT_decl_line
	.long	267                             @ DW_AT_type
	.byte	12                              @ Abbrev [12] 0xf1:0xc DW_TAG_variable
	.long	.Linfo_string15                 @ DW_AT_name
	.byte	2                               @ DW_AT_decl_file
	.short	433                             @ DW_AT_decl_line
	.long	158                             @ DW_AT_type
	.byte	12                              @ Abbrev [12] 0xfd:0xc DW_TAG_variable
	.long	.Linfo_string16                 @ DW_AT_name
	.byte	2                               @ DW_AT_decl_file
	.short	432                             @ DW_AT_decl_line
	.long	274                             @ DW_AT_type
	.byte	0                               @ End Of Children Mark
	.byte	0                               @ End Of Children Mark
	.byte	5                               @ Abbrev [5] 0x10b:0x7 DW_TAG_base_type
	.long	.Linfo_string9                  @ DW_AT_name
	.byte	5                               @ DW_AT_encoding
	.byte	4                               @ DW_AT_byte_size
	.byte	13                              @ Abbrev [13] 0x112:0x5 DW_TAG_pointer_type
	.long	279                             @ DW_AT_type
	.byte	14                              @ Abbrev [14] 0x117:0x5 DW_TAG_const_type
	.long	63                              @ DW_AT_type
	.byte	15                              @ Abbrev [15] 0x11c:0xc2 DW_TAG_subprogram
	.long	.Lfunc_begin0                   @ DW_AT_low_pc
	.long	.Lfunc_end0                     @ DW_AT_high_pc
	.byte	1                               @ DW_AT_frame_base
	.byte	93
	.byte	24                              @ DW_AT_TI_max_frame_size
	.long	.Linfo_string22                 @ DW_AT_name
	.byte	1                               @ DW_AT_decl_file
	.byte	11                              @ DW_AT_decl_line
	.long	267                             @ DW_AT_type
	.byte	1                               @ DW_AT_external
	.byte	16                              @ Abbrev [16] 0x133:0xe DW_TAG_variable
	.byte	2                               @ DW_AT_location
	.byte	145
	.byte	20
	.long	.Linfo_string23                 @ DW_AT_name
	.byte	1                               @ DW_AT_decl_file
	.byte	13                              @ DW_AT_decl_line
	.long	478                             @ DW_AT_type
	.byte	16                              @ Abbrev [16] 0x141:0xe DW_TAG_variable
	.byte	2                               @ DW_AT_location
	.byte	145
	.byte	8
	.long	.Linfo_string24                 @ DW_AT_name
	.byte	1                               @ DW_AT_decl_file
	.byte	15                              @ DW_AT_decl_line
	.long	483                             @ DW_AT_type
	.byte	16                              @ Abbrev [16] 0x14f:0xe DW_TAG_variable
	.byte	2                               @ DW_AT_location
	.byte	145
	.byte	4
	.long	.Linfo_string25                 @ DW_AT_name
	.byte	1                               @ DW_AT_decl_file
	.byte	16                              @ DW_AT_decl_line
	.long	478                             @ DW_AT_type
	.byte	17                              @ Abbrev [17] 0x15d:0x44 DW_TAG_lexical_block
	.long	.Ldebug_ranges0                 @ DW_AT_ranges
	.byte	18                              @ Abbrev [18] 0x162:0xb DW_TAG_variable
	.long	.Linfo_string12                 @ DW_AT_name
	.byte	1                               @ DW_AT_decl_file
	.byte	19                              @ DW_AT_decl_line
	.long	267                             @ DW_AT_type
	.byte	19                              @ Abbrev [19] 0x16d:0x33 DW_TAG_inlined_subroutine
	.long	165                             @ DW_AT_abstract_origin
	.long	.Ltmp8                          @ DW_AT_low_pc
	.long	.Ltmp44                         @ DW_AT_high_pc
	.byte	1                               @ DW_AT_call_file
	.byte	20                              @ DW_AT_call_line
	.byte	15                              @ DW_AT_call_column
	.byte	20                              @ Abbrev [20] 0x17d:0x5 DW_TAG_formal_parameter
	.long	180                             @ DW_AT_abstract_origin
	.byte	21                              @ Abbrev [21] 0x182:0x1d DW_TAG_lexical_block
	.long	.Ltmp8                          @ DW_AT_low_pc
	.long	.Ltmp44                         @ DW_AT_high_pc
	.byte	22                              @ Abbrev [22] 0x18b:0x5 DW_TAG_variable
	.long	217                             @ DW_AT_abstract_origin
	.byte	22                              @ Abbrev [22] 0x190:0x5 DW_TAG_variable
	.long	229                             @ DW_AT_abstract_origin
	.byte	23                              @ Abbrev [23] 0x195:0x9 DW_TAG_variable
	.long	.Ldebug_loc0                    @ DW_AT_location
	.long	241                             @ DW_AT_abstract_origin
	.byte	0                               @ End Of Children Mark
	.byte	0                               @ End Of Children Mark
	.byte	0                               @ End Of Children Mark
	.byte	24                              @ Abbrev [24] 0x1a1:0xa DW_TAG_TI_reserved_3
	.long	.Ltmp1                          @ DW_AT_low_pc
	.byte	1                               @ DW_AT_TI_reserved_9
	.long	.Linfo_string17                 @ DW_AT_name
	.byte	24                              @ Abbrev [24] 0x1ab:0xa DW_TAG_TI_reserved_3
	.long	.Ltmp5                          @ DW_AT_low_pc
	.byte	1                               @ DW_AT_TI_reserved_9
	.long	.Linfo_string18                 @ DW_AT_name
	.byte	24                              @ Abbrev [24] 0x1b5:0xa DW_TAG_TI_reserved_3
	.long	.Ltmp7                          @ DW_AT_low_pc
	.byte	1                               @ DW_AT_TI_reserved_9
	.long	.Linfo_string19                 @ DW_AT_name
	.byte	24                              @ Abbrev [24] 0x1bf:0xa DW_TAG_TI_reserved_3
	.long	.Ltmp8                          @ DW_AT_low_pc
	.byte	1                               @ DW_AT_TI_reserved_9
	.long	.Linfo_string20                 @ DW_AT_name
	.byte	24                              @ Abbrev [24] 0x1c9:0xa DW_TAG_TI_reserved_3
	.long	.Ltmp45                         @ DW_AT_low_pc
	.byte	1                               @ DW_AT_TI_reserved_9
	.long	.Linfo_string21                 @ DW_AT_name
	.byte	24                              @ Abbrev [24] 0x1d3:0xa DW_TAG_TI_reserved_3
	.long	.Ltmp48                         @ DW_AT_low_pc
	.byte	1                               @ DW_AT_TI_reserved_9
	.long	.Linfo_string19                 @ DW_AT_name
	.byte	0                               @ End Of Children Mark
	.byte	25                              @ Abbrev [25] 0x1de:0x5 DW_TAG_volatile_type
	.long	267                             @ DW_AT_type
	.byte	3                               @ Abbrev [3] 0x1e3:0xc DW_TAG_array_type
	.long	63                              @ DW_AT_type
	.byte	4                               @ Abbrev [4] 0x1e8:0x6 DW_TAG_subrange_type
	.long	70                              @ DW_AT_type
	.byte	11                              @ DW_AT_count
	.byte	0                               @ End Of Children Mark
	.byte	0                               @ End Of Children Mark
.Ldebug_info_end0:
	.section	.debug_ranges,"",%progbits
.Ldebug_ranges0:
	.long	.Ltmp6-.Lfunc_begin0
	.long	.Ltmp45-.Lfunc_begin0
	.long	.Ltmp46-.Lfunc_begin0
	.long	.Ltmp47-.Lfunc_begin0
	.long	0
	.long	0
	.section	.debug_str,"MS",%progbits,1
.Linfo_string0:
	.asciz	"TI clang version 18.1.8 (ssh://git@bitbucket.itg.ti.com/code/llvm-project.git 41ce286cff6db007d382d297353d8bf884b450b7)" @ string offset=0
.Linfo_string1:
	.asciz	"password/main.c"               @ string offset=120
.Linfo_string2:
	.asciz	"/home/main/Documents/school/Fault-Injection-Finder/targets/timspm0l2228/source" @ string offset=136
.Linfo_string3:
	.asciz	"char"                          @ string offset=215
.Linfo_string4:
	.asciz	"__ARRAY_SIZE_TYPE__"           @ string offset=220
.Linfo_string5:
	.asciz	"unsigned int"                  @ string offset=240
.Linfo_string6:
	.asciz	"size_t"                        @ string offset=253
.Linfo_string7:
	.asciz	"unsigned char"                 @ string offset=260
.Linfo_string8:
	.asciz	"strncmp"                       @ string offset=274
.Linfo_string9:
	.asciz	"int"                           @ string offset=282
.Linfo_string10:
	.asciz	"string1"                       @ string offset=286
.Linfo_string11:
	.asciz	"string2"                       @ string offset=294
.Linfo_string12:
	.asciz	"n"                             @ string offset=302
.Linfo_string13:
	.asciz	"s1"                            @ string offset=304
.Linfo_string14:
	.asciz	"result"                        @ string offset=307
.Linfo_string15:
	.asciz	"cp"                            @ string offset=314
.Linfo_string16:
	.asciz	"s2"                            @ string offset=317
.Linfo_string17:
	.asciz	"init_device"                   @ string offset=320
.Linfo_string18:
	.asciz	"pwned"                         @ string offset=332
.Linfo_string19:
	.asciz	"_write"                        @ string offset=338
.Linfo_string20:
	.asciz	"_read"                         @ string offset=345
.Linfo_string21:
	.asciz	"led_blip"                      @ string offset=351
.Linfo_string22:
	.asciz	"main"                          @ string offset=360
.Linfo_string23:
	.asciz	"lol"                           @ string offset=365
.Linfo_string24:
	.asciz	"input"                         @ string offset=369
.Linfo_string25:
	.asciz	"out"                           @ string offset=375
	.ident	"TI clang version 18.1.8 (ssh://git@bitbucket.itg.ti.com/code/llvm-project.git 41ce286cff6db007d382d297353d8bf884b450b7)"
	.section	".note.GNU-stack","",%progbits
	.addrsig
	.eabi_attribute	30, 1	@ Tag_ABI_optimization_goals
	.TI_attribute	16, 0	@ Tag_Instrumentation
	.section	.debug_line,"",%progbits
.Lline_table_start0:
