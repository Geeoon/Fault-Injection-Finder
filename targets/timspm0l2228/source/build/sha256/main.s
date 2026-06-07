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
	.file	1 "/home/main/Documents/school/Fault-Injection-Finder/targets/timspm0l2228/source" "sha256/main.c"
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
	.loc	1 10 0                          @ sha256/main.c:10:0
	.fnstart
	.cfi_sections .debug_frame
	.cfi_startproc
@ %bb.0:
	.pad	#56
	sub	sp, #56
	.cfi_def_cfa_offset 56
.Ltmp0:
	.loc	1 11 5 prologue_end             @ sha256/main.c:11:5
	bl	init_device
.Ltmp1:
	.loc	1 0 5 is_stmt 0                 @ sha256/main.c:0:5
	movs	r4, #0
	.loc	1 12 18 is_stmt 1               @ sha256/main.c:12:18
	str	r4, [sp, #52]
.Ltmp2:
	.loc	1 13 9                          @ sha256/main.c:13:9
	ldr	r0, [sp, #52]
.Ltmp3:
	.loc	1 13 9 is_stmt 0                @ sha256/main.c:13:9
	cmp	r0, #0
	beq	.LBB0_2
@ %bb.1:
.Ltmp4:
	.loc	1 13 16                         @ sha256/main.c:13:16
	bl	pwned
.Ltmp5:
.LBB0_2:
	.loc	1 0 16                          @ sha256/main.c:0:16
	ldr	r5, .LCPI0_0
	ldr	r7, .LCPI0_1
	b	.LBB0_4
.LBB0_3:                                @   in Loop: Header=BB0_4 Depth=1
	movs	r2, #16
.Ltmp6:
	.loc	1 26 13 is_stmt 1               @ sha256/main.c:26:13
	ldr	r1, .LCPI0_3
	bl	_write
.Ltmp7:
.LBB0_4:                                @ =>This Loop Header: Depth=1
                                        @     Child Loop BB0_5 Depth 2
                                        @     Child Loop BB0_11 Depth 2
	.loc	1 0 13 is_stmt 0                @ sha256/main.c:0:13
	movs	r2, #21
	.loc	1 15 9 is_stmt 1                @ sha256/main.c:15:9
	mov	r0, r4
	mov	r1, r5
	bl	_write
.Ltmp8:
	.loc	1 0 9 is_stmt 0                 @ sha256/main.c:0:9
	add	r6, sp, #36
	movs	r2, #16
	.loc	1 17 17 is_stmt 1               @ sha256/main.c:17:17
	mov	r0, r4
	mov	r1, r6
	bl	_read
.Ltmp9:
	@DEBUG_VALUE: n <- $r0
	.loc	1 18 17                         @ sha256/main.c:18:17
	adds	r0, r0, r6
.Ltmp10:
	.loc	1 18 9 is_stmt 0                @ sha256/main.c:18:9
	subs	r0, r0, #1
	.loc	1 18 22                         @ sha256/main.c:18:22
	strb	r4, [r0]
	@DEBUG_VALUE: strlen:s <- [DW_OP_plus_uconst 36, DW_OP_stack_value] $sp
	@DEBUG_VALUE: strlen:n <- -1
	@DEBUG_VALUE: strlen:string <- [DW_OP_plus_uconst 36, DW_OP_stack_value] $sp
.Ltmp11:
	@DEBUG_VALUE: real_hash <- undef
	.loc	1 0 22                          @ sha256/main.c:0:22
	mov	r1, r4
.Ltmp12:
.LBB0_5:                                @   Parent Loop BB0_4 Depth=1
                                        @ =>  This Inner Loop Header: Depth=2
	@DEBUG_VALUE: strlen:string <- [DW_OP_plus_uconst 36, DW_OP_stack_value] $sp
	add	r0, sp, #36
.Ltmp13:
	@DEBUG_VALUE: strlen:s <- [DW_OP_plus_uconst 1, DW_OP_stack_value] $r1
	@DEBUG_VALUE: strlen:n <- [DW_OP_plus_uconst 1, DW_OP_stack_value] $r1
	.loc	2 298 19 is_stmt 1              @ /opt/ti-cgt-armllvm_4.0.3.LTS/include/c/string.h:298:19
	ldrb	r2, [r0, r1]
	.loc	2 298 7 is_stmt 0               @ /opt/ti-cgt-armllvm_4.0.3.LTS/include/c/string.h:298:7
	cmp	r2, #0
	beq	.LBB0_10
.Ltmp14:
@ %bb.6:                                @   in Loop: Header=BB0_5 Depth=2
	@DEBUG_VALUE: strlen:n <- [DW_OP_plus_uconst 1, DW_OP_stack_value] $r1
	@DEBUG_VALUE: strlen:s <- [DW_OP_plus_uconst 1, DW_OP_stack_value] $r1
	@DEBUG_VALUE: strlen:string <- [DW_OP_plus_uconst 36, DW_OP_stack_value] $sp
	.loc	2 0 0                           @ /opt/ti-cgt-armllvm_4.0.3.LTS/include/c/string.h:0:0
	adds	r0, r0, r1
	@DEBUG_VALUE: strlen:s <- [DW_OP_plus_uconst 1, DW_OP_stack_value] $r1
.Ltmp15:
	@DEBUG_VALUE: strlen:n <- [DW_OP_plus_uconst 2, DW_OP_stack_value] $r1
	.loc	2 298 19                        @ /opt/ti-cgt-armllvm_4.0.3.LTS/include/c/string.h:298:19
	ldrb	r2, [r0, #1]
	.loc	2 298 7                         @ /opt/ti-cgt-armllvm_4.0.3.LTS/include/c/string.h:298:7
	cmp	r2, #0
	beq	.LBB0_9
.Ltmp16:
@ %bb.7:                                @   in Loop: Header=BB0_5 Depth=2
	@DEBUG_VALUE: strlen:n <- [DW_OP_plus_uconst 2, DW_OP_stack_value] $r1
	@DEBUG_VALUE: strlen:s <- [DW_OP_plus_uconst 1, DW_OP_stack_value] $r1
	@DEBUG_VALUE: strlen:string <- [DW_OP_plus_uconst 36, DW_OP_stack_value] $sp
	@DEBUG_VALUE: strlen:n <- [DW_OP_plus_uconst 2, DW_OP_stack_value] $r1
	@DEBUG_VALUE: strlen:s <- [DW_OP_LLVM_arg 0, DW_OP_consts 3, DW_OP_div, DW_OP_consts 3, DW_OP_mul, DW_OP_consts 3, DW_OP_LLVM_arg 1, DW_OP_plus_uconst 36, DW_OP_plus, DW_OP_plus, DW_OP_stack_value] $r1, $sp
	.loc	2 298 19                        @ /opt/ti-cgt-armllvm_4.0.3.LTS/include/c/string.h:298:19
	ldrb	r0, [r0, #2]
	.loc	2 298 7                         @ /opt/ti-cgt-armllvm_4.0.3.LTS/include/c/string.h:298:7
	adds	r1, r1, #3
.Ltmp17:
	cmp	r0, #0
	bne	.LBB0_5
.Ltmp18:
@ %bb.8:                                @   in Loop: Header=BB0_4 Depth=1
	.loc	1 22 9 is_stmt 1                @ sha256/main.c:22:9
	subs	r1, r1, #1
	b	.LBB0_10
.LBB0_9:                                @   in Loop: Header=BB0_4 Depth=1
	adds	r1, r1, #1
.LBB0_10:                               @   in Loop: Header=BB0_4 Depth=1
	.loc	1 0 9 is_stmt 0                 @ sha256/main.c:0:9
	add	r0, sp, #36
	add	r2, sp, #4
	.loc	1 22 9                          @ sha256/main.c:22:9
	bl	sha256_easy_hash
.Ltmp19:
	.loc	1 23 9 is_stmt 1                @ sha256/main.c:23:9
	bl	led_blip
.Ltmp20:
	.loc	1 0 9 is_stmt 0                 @ sha256/main.c:0:9
	movs	r0, #0
	@DEBUG_VALUE: mem2 <- undef
	@DEBUG_VALUE: memcmp:ct <- undef
	@DEBUG_VALUE: mem1 <- [DW_OP_plus_uconst 4, DW_OP_stack_value] $sp
	@DEBUG_VALUE: memcmp:n <- 32
	@DEBUG_VALUE: memcmp:cs <- [DW_OP_plus_uconst 4, DW_OP_stack_value] $sp
.LBB0_11:                               @   Parent Loop BB0_4 Depth=1
                                        @ =>  This Inner Loop Header: Depth=2
.Ltmp21:
	@DEBUG_VALUE: memcmp:cs <- [DW_OP_plus_uconst 4, DW_OP_stack_value] $sp
	@DEBUG_VALUE: mem2 <- [DW_OP_LLVM_arg 0, DW_OP_LLVM_arg 0, DW_OP_plus, DW_OP_stack_value] undef
	add	r1, sp, #4
.Ltmp22:
	@DEBUG_VALUE: mem1 <- [DW_OP_plus_uconst 1, DW_OP_stack_value] $r0
	@DEBUG_VALUE: memcmp:n <- [DW_OP_consts 18446744073709551615, DW_OP_mul, DW_OP_consts 32, DW_OP_plus, DW_OP_stack_value] $r0
	.loc	2 454 22 is_stmt 1              @ /opt/ti-cgt-armllvm_4.0.3.LTS/include/c/string.h:454:22
	ldrb	r1, [r1, r0]
.Ltmp23:
	@DEBUG_VALUE: cp1 <- undef
	@DEBUG_VALUE: mem2 <- [DW_OP_plus_uconst 1, DW_OP_stack_value] $r0
	.loc	2 454 41 is_stmt 0              @ /opt/ti-cgt-armllvm_4.0.3.LTS/include/c/string.h:454:41
	ldrb	r2, [r7, r0]
.Ltmp24:
	@DEBUG_VALUE: cp2 <- undef
	@DEBUG_VALUE: mem2 <- [DW_OP_LLVM_arg 0, DW_OP_consts 1, DW_OP_LLVM_arg 1, DW_OP_plus, DW_OP_plus, DW_OP_stack_value] $r0, $r7
	@DEBUG_VALUE: mem1 <- [DW_OP_LLVM_arg 0, DW_OP_consts 1, DW_OP_LLVM_arg 1, DW_OP_plus_uconst 4, DW_OP_plus, DW_OP_plus, DW_OP_stack_value] $r0, $sp
	@DEBUG_VALUE: memcmp:n <- [DW_OP_consts 18446744073709551615, DW_OP_mul, DW_OP_consts 31, DW_OP_plus, DW_OP_stack_value] $r0
	.loc	2 454 50                        @ /opt/ti-cgt-armllvm_4.0.3.LTS/include/c/string.h:454:50
	cmp	r1, r2
	bne	.LBB0_13
.Ltmp25:
@ %bb.12:                               @   in Loop: Header=BB0_11 Depth=2
	@DEBUG_VALUE: memcmp:n <- [DW_OP_consts 18446744073709551615, DW_OP_mul, DW_OP_consts 31, DW_OP_plus, DW_OP_stack_value] $r0
	@DEBUG_VALUE: mem1 <- [DW_OP_LLVM_arg 0, DW_OP_consts 1, DW_OP_LLVM_arg 1, DW_OP_plus_uconst 4, DW_OP_plus, DW_OP_plus, DW_OP_stack_value] $r0, $sp
	@DEBUG_VALUE: mem2 <- [DW_OP_LLVM_arg 0, DW_OP_consts 1, DW_OP_LLVM_arg 1, DW_OP_plus, DW_OP_plus, DW_OP_stack_value] $r0, $r7
	@DEBUG_VALUE: memcmp:cs <- [DW_OP_plus_uconst 4, DW_OP_stack_value] $sp
	adds	r3, r0, #1
	cmp	r0, #31
	mov	r0, r3
.Ltmp26:
	bne	.LBB0_11
.Ltmp27:
.LBB0_13:                               @   in Loop: Header=BB0_4 Depth=1
	.loc	2 0 50                          @ /opt/ti-cgt-armllvm_4.0.3.LTS/include/c/string.h:0:50
	movs	r0, #0
	.loc	1 25 13 is_stmt 1               @ sha256/main.c:25:13
	cmp	r1, r2
	@DEBUG_VALUE: cp2 <- [DW_OP_LLVM_convert 8 7, DW_OP_LLVM_convert 32 7, DW_OP_stack_value] undef
	@DEBUG_VALUE: cp1 <- [DW_OP_LLVM_convert 8 7, DW_OP_LLVM_convert 32 7, DW_OP_stack_value] undef
	beq	.LBB0_3
@ %bb.14:                               @   in Loop: Header=BB0_4 Depth=1
	.loc	1 0 13 is_stmt 0                @ sha256/main.c:0:13
	movs	r2, #15
.Ltmp28:
	.loc	1 28 13 is_stmt 1               @ sha256/main.c:28:13
	ldr	r1, .LCPI0_2
	bl	_write
.Ltmp29:
	.loc	1 0 13 is_stmt 0                @ sha256/main.c:0:13
	b	.LBB0_4
.Ltmp30:
	.p2align	2
@ %bb.15:
.LCPI0_0:
	.long	.L.str
.LCPI0_1:
	.long	.L__const.main.real_hash
.LCPI0_2:
	.long	.L.str.3
.LCPI0_3:
	.long	.L.str.1
.Lfunc_end0:
	.size	main, .Lfunc_end0-main
	.cfi_endproc
	.cantunwind
	.fnend
                                        @ -- End function
	.type	.L.str,%object                  @ @.str
	.section	.rodata.str1.15159059442110792349.1,"aMS",%progbits,1
.L.str:
	.asciz	"Enter your password: "
	.size	.L.str, 22

	.type	.L__const.main.real_hash,%object @ @__const.main.real_hash
	.section	.rodata.cst32,"aM",%progbits,32
.L__const.main.real_hash:
	.ascii	",\362M\272_\260\243\016&\350;*\305\271\342\236\033\026\036\\\037\247B^s\0043b\223\213\230$"
	.size	.L__const.main.real_hash, 32

	.type	.L.str.1,%object                @ @.str.1
	.section	.rodata.str1.8154729771448623357.1,"aMS",%progbits,1
.L.str.1:
	.asciz	"\naccess granted.\n"
	.size	.L.str.1, 18

	.type	.L.str.3,%object                @ @.str.3
	.section	.rodata.str1.18227636981041470289.1,"aMS",%progbits,1
.L.str.3:
	.asciz	"\naccess denied.\n"
	.size	.L.str.3, 17

	.section	.debug_loc,"",%progbits
.Ldebug_loc0:
	.long	.Ltmp9-.Lfunc_begin0
	.long	.Ltmp10-.Lfunc_begin0
	.short	1                               @ Loc expr size
	.byte	80                              @ DW_OP_reg0
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
	.byte	15                              @ DW_TAG_pointer_type
	.byte	0                               @ DW_CHILDREN_no
	.byte	73                              @ DW_AT_type
	.byte	19                              @ DW_FORM_ref4
	.byte	0                               @ EOM(1)
	.byte	0                               @ EOM(2)
	.byte	10                              @ Abbreviation Code
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
	.byte	11                              @ Abbreviation Code
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
	.byte	38                              @ DW_TAG_const_type
	.byte	0                               @ DW_CHILDREN_no
	.byte	73                              @ DW_AT_type
	.byte	19                              @ DW_FORM_ref4
	.byte	0                               @ EOM(1)
	.byte	0                               @ EOM(2)
	.byte	14                              @ Abbreviation Code
	.byte	11                              @ DW_TAG_lexical_block
	.byte	1                               @ DW_CHILDREN_yes
	.byte	0                               @ EOM(1)
	.byte	0                               @ EOM(2)
	.byte	15                              @ Abbreviation Code
	.byte	38                              @ DW_TAG_const_type
	.byte	0                               @ DW_CHILDREN_no
	.byte	0                               @ EOM(1)
	.byte	0                               @ EOM(2)
	.byte	16                              @ Abbreviation Code
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
	.byte	17                              @ Abbreviation Code
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
	.byte	18                              @ Abbreviation Code
	.byte	11                              @ DW_TAG_lexical_block
	.byte	1                               @ DW_CHILDREN_yes
	.byte	17                              @ DW_AT_low_pc
	.byte	1                               @ DW_FORM_addr
	.byte	18                              @ DW_AT_high_pc
	.byte	1                               @ DW_FORM_addr
	.byte	0                               @ EOM(1)
	.byte	0                               @ EOM(2)
	.byte	19                              @ Abbreviation Code
	.byte	52                              @ DW_TAG_variable
	.byte	0                               @ DW_CHILDREN_no
	.byte	2                               @ DW_AT_location
	.byte	6                               @ DW_FORM_data4
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
	.byte	20                              @ Abbreviation Code
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
	.byte	21                              @ Abbreviation Code
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
	.byte	22                              @ Abbreviation Code
	.byte	5                               @ DW_TAG_formal_parameter
	.byte	0                               @ DW_CHILDREN_no
	.byte	49                              @ DW_AT_abstract_origin
	.byte	19                              @ DW_FORM_ref4
	.byte	0                               @ EOM(1)
	.byte	0                               @ EOM(2)
	.byte	23                              @ Abbreviation Code
	.byte	52                              @ DW_TAG_variable
	.byte	0                               @ DW_CHILDREN_no
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
	.byte	1                               @ Abbrev [1] 0xb:0x27e DW_TAG_compile_unit
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
	.byte	15                              @ DW_AT_decl_line
	.byte	5                               @ DW_AT_location
	.byte	3
	.long	.L.str
	.byte	3                               @ Abbrev [3] 0x33:0xc DW_TAG_array_type
	.long	63                              @ DW_AT_type
	.byte	4                               @ Abbrev [4] 0x38:0x6 DW_TAG_subrange_type
	.long	70                              @ DW_AT_type
	.byte	22                              @ DW_AT_count
	.byte	0                               @ End Of Children Mark
	.byte	5                               @ Abbrev [5] 0x3f:0x7 DW_TAG_base_type
	.long	.Linfo_string3                  @ DW_AT_name
	.byte	8                               @ DW_AT_encoding
	.byte	1                               @ DW_AT_byte_size
	.byte	6                               @ Abbrev [6] 0x46:0x7 DW_TAG_base_type
	.long	.Linfo_string4                  @ DW_AT_name
	.byte	8                               @ DW_AT_byte_size
	.byte	7                               @ DW_AT_encoding
	.byte	2                               @ Abbrev [2] 0x4d:0xd DW_TAG_variable
	.long	90                              @ DW_AT_type
	.byte	1                               @ DW_AT_decl_file
	.byte	26                              @ DW_AT_decl_line
	.byte	5                               @ DW_AT_location
	.byte	3
	.long	.L.str.1
	.byte	3                               @ Abbrev [3] 0x5a:0xc DW_TAG_array_type
	.long	63                              @ DW_AT_type
	.byte	4                               @ Abbrev [4] 0x5f:0x6 DW_TAG_subrange_type
	.long	70                              @ DW_AT_type
	.byte	18                              @ DW_AT_count
	.byte	0                               @ End Of Children Mark
	.byte	7                               @ Abbrev [7] 0x66:0x7 DW_TAG_variable
	.long	109                             @ DW_AT_type
	.byte	1                               @ DW_AT_decl_file
	.byte	26                              @ DW_AT_decl_line
	.byte	3                               @ Abbrev [3] 0x6d:0xc DW_TAG_array_type
	.long	63                              @ DW_AT_type
	.byte	4                               @ Abbrev [4] 0x72:0x6 DW_TAG_subrange_type
	.long	70                              @ DW_AT_type
	.byte	17                              @ DW_AT_count
	.byte	0                               @ End Of Children Mark
	.byte	2                               @ Abbrev [2] 0x79:0xd DW_TAG_variable
	.long	109                             @ DW_AT_type
	.byte	1                               @ DW_AT_decl_file
	.byte	28                              @ DW_AT_decl_line
	.byte	5                               @ DW_AT_location
	.byte	3
	.long	.L.str.3
	.byte	7                               @ Abbrev [7] 0x86:0x7 DW_TAG_variable
	.long	141                             @ DW_AT_type
	.byte	1                               @ DW_AT_decl_file
	.byte	28                              @ DW_AT_decl_line
	.byte	3                               @ Abbrev [3] 0x8d:0xc DW_TAG_array_type
	.long	63                              @ DW_AT_type
	.byte	4                               @ Abbrev [4] 0x92:0x6 DW_TAG_subrange_type
	.long	70                              @ DW_AT_type
	.byte	16                              @ DW_AT_count
	.byte	0                               @ End Of Children Mark
	.byte	8                               @ Abbrev [8] 0x99:0xb DW_TAG_typedef
	.long	164                             @ DW_AT_type
	.long	.Linfo_string6                  @ DW_AT_name
	.byte	2                               @ DW_AT_decl_file
	.byte	66                              @ DW_AT_decl_line
	.byte	5                               @ Abbrev [5] 0xa4:0x7 DW_TAG_base_type
	.long	.Linfo_string5                  @ DW_AT_name
	.byte	7                               @ DW_AT_encoding
	.byte	4                               @ DW_AT_byte_size
	.byte	9                               @ Abbrev [9] 0xab:0x5 DW_TAG_pointer_type
	.long	176                             @ DW_AT_type
	.byte	5                               @ Abbrev [5] 0xb0:0x7 DW_TAG_base_type
	.long	.Linfo_string7                  @ DW_AT_name
	.byte	8                               @ DW_AT_encoding
	.byte	1                               @ DW_AT_byte_size
	.byte	10                              @ Abbrev [10] 0xb7:0x34 DW_TAG_subprogram
	.long	.Linfo_string8                  @ DW_AT_name
	.byte	2                               @ DW_AT_decl_file
	.short	293                             @ DW_AT_decl_line
	.byte	1                               @ DW_AT_prototyped
	.byte	3                               @ DW_AT_calling_convention
	.long	153                             @ DW_AT_type
	.byte	1                               @ DW_AT_inline
	.byte	11                              @ Abbrev [11] 0xc6:0xc DW_TAG_formal_parameter
	.long	.Linfo_string9                  @ DW_AT_name
	.byte	2                               @ DW_AT_decl_file
	.short	293                             @ DW_AT_decl_line
	.long	235                             @ DW_AT_type
	.byte	12                              @ Abbrev [12] 0xd2:0xc DW_TAG_variable
	.long	.Linfo_string10                 @ DW_AT_name
	.byte	2                               @ DW_AT_decl_file
	.short	296                             @ DW_AT_decl_line
	.long	235                             @ DW_AT_type
	.byte	12                              @ Abbrev [12] 0xde:0xc DW_TAG_variable
	.long	.Linfo_string11                 @ DW_AT_name
	.byte	2                               @ DW_AT_decl_file
	.short	295                             @ DW_AT_decl_line
	.long	153                             @ DW_AT_type
	.byte	0                               @ End Of Children Mark
	.byte	9                               @ Abbrev [9] 0xeb:0x5 DW_TAG_pointer_type
	.long	240                             @ DW_AT_type
	.byte	13                              @ Abbrev [13] 0xf0:0x5 DW_TAG_const_type
	.long	63                              @ DW_AT_type
	.byte	10                              @ Abbrev [10] 0xf5:0x66 DW_TAG_subprogram
	.long	.Linfo_string12                 @ DW_AT_name
	.byte	2                               @ DW_AT_decl_file
	.short	446                             @ DW_AT_decl_line
	.byte	1                               @ DW_AT_prototyped
	.byte	3                               @ DW_AT_calling_convention
	.long	347                             @ DW_AT_type
	.byte	1                               @ DW_AT_inline
	.byte	11                              @ Abbrev [11] 0x104:0xc DW_TAG_formal_parameter
	.long	.Linfo_string14                 @ DW_AT_name
	.byte	2                               @ DW_AT_decl_file
	.short	446                             @ DW_AT_decl_line
	.long	354                             @ DW_AT_type
	.byte	11                              @ Abbrev [11] 0x110:0xc DW_TAG_formal_parameter
	.long	.Linfo_string15                 @ DW_AT_name
	.byte	2                               @ DW_AT_decl_file
	.short	446                             @ DW_AT_decl_line
	.long	354                             @ DW_AT_type
	.byte	11                              @ Abbrev [11] 0x11c:0xc DW_TAG_formal_parameter
	.long	.Linfo_string11                 @ DW_AT_name
	.byte	2                               @ DW_AT_decl_file
	.short	446                             @ DW_AT_decl_line
	.long	153                             @ DW_AT_type
	.byte	14                              @ Abbrev [14] 0x128:0x32 DW_TAG_lexical_block
	.byte	12                              @ Abbrev [12] 0x129:0xc DW_TAG_variable
	.long	.Linfo_string16                 @ DW_AT_name
	.byte	2                               @ DW_AT_decl_file
	.short	451                             @ DW_AT_decl_line
	.long	360                             @ DW_AT_type
	.byte	12                              @ Abbrev [12] 0x135:0xc DW_TAG_variable
	.long	.Linfo_string17                 @ DW_AT_name
	.byte	2                               @ DW_AT_decl_file
	.short	450                             @ DW_AT_decl_line
	.long	360                             @ DW_AT_type
	.byte	12                              @ Abbrev [12] 0x141:0xc DW_TAG_variable
	.long	.Linfo_string18                 @ DW_AT_name
	.byte	2                               @ DW_AT_decl_file
	.short	452                             @ DW_AT_decl_line
	.long	347                             @ DW_AT_type
	.byte	12                              @ Abbrev [12] 0x14d:0xc DW_TAG_variable
	.long	.Linfo_string19                 @ DW_AT_name
	.byte	2                               @ DW_AT_decl_file
	.short	452                             @ DW_AT_decl_line
	.long	347                             @ DW_AT_type
	.byte	0                               @ End Of Children Mark
	.byte	0                               @ End Of Children Mark
	.byte	5                               @ Abbrev [5] 0x15b:0x7 DW_TAG_base_type
	.long	.Linfo_string13                 @ DW_AT_name
	.byte	5                               @ DW_AT_encoding
	.byte	4                               @ DW_AT_byte_size
	.byte	9                               @ Abbrev [9] 0x162:0x5 DW_TAG_pointer_type
	.long	359                             @ DW_AT_type
	.byte	15                              @ Abbrev [15] 0x167:0x1 DW_TAG_const_type
	.byte	9                               @ Abbrev [9] 0x168:0x5 DW_TAG_pointer_type
	.long	365                             @ DW_AT_type
	.byte	13                              @ Abbrev [13] 0x16d:0x5 DW_TAG_const_type
	.long	176                             @ DW_AT_type
	.byte	16                              @ Abbrev [16] 0x172:0x105 DW_TAG_subprogram
	.long	.Lfunc_begin0                   @ DW_AT_low_pc
	.long	.Lfunc_end0                     @ DW_AT_high_pc
	.byte	1                               @ DW_AT_frame_base
	.byte	93
	.byte	56                              @ DW_AT_TI_max_frame_size
	.long	.Linfo_string26                 @ DW_AT_name
	.byte	1                               @ DW_AT_decl_file
	.byte	10                              @ DW_AT_decl_line
	.long	347                             @ DW_AT_type
	.byte	1                               @ DW_AT_external
	.byte	17                              @ Abbrev [17] 0x189:0xe DW_TAG_variable
	.byte	2                               @ DW_AT_location
	.byte	145
	.byte	52
	.long	.Linfo_string27                 @ DW_AT_name
	.byte	1                               @ DW_AT_decl_file
	.byte	12                              @ DW_AT_decl_line
	.long	631                             @ DW_AT_type
	.byte	18                              @ Abbrev [18] 0x197:0x8f DW_TAG_lexical_block
	.long	.Ltmp6                          @ DW_AT_low_pc
	.long	.Ltmp30                         @ DW_AT_high_pc
	.byte	17                              @ Abbrev [17] 0x1a0:0xe DW_TAG_variable
	.byte	2                               @ DW_AT_location
	.byte	145
	.byte	36
	.long	.Linfo_string28                 @ DW_AT_name
	.byte	1                               @ DW_AT_decl_file
	.byte	16                              @ DW_AT_decl_line
	.long	141                             @ DW_AT_type
	.byte	17                              @ Abbrev [17] 0x1ae:0xe DW_TAG_variable
	.byte	2                               @ DW_AT_location
	.byte	145
	.byte	4
	.long	.Linfo_string29                 @ DW_AT_name
	.byte	1                               @ DW_AT_decl_file
	.byte	20                              @ DW_AT_decl_line
	.long	636                             @ DW_AT_type
	.byte	19                              @ Abbrev [19] 0x1bc:0xf DW_TAG_variable
	.long	.Ldebug_loc0                    @ DW_AT_location
	.long	.Linfo_string11                 @ DW_AT_name
	.byte	1                               @ DW_AT_decl_file
	.byte	17                              @ DW_AT_decl_line
	.long	347                             @ DW_AT_type
	.byte	20                              @ Abbrev [20] 0x1cb:0xb DW_TAG_variable
	.long	.Linfo_string30                 @ DW_AT_name
	.byte	1                               @ DW_AT_decl_file
	.byte	19                              @ DW_AT_decl_line
	.long	636                             @ DW_AT_type
	.byte	21                              @ Abbrev [21] 0x1d6:0x2f DW_TAG_inlined_subroutine
	.long	245                             @ DW_AT_abstract_origin
	.long	.Ltmp22                         @ DW_AT_low_pc
	.long	.Ltmp27                         @ DW_AT_high_pc
	.byte	1                               @ DW_AT_call_file
	.byte	25                              @ DW_AT_call_line
	.byte	13                              @ DW_AT_call_column
	.byte	22                              @ Abbrev [22] 0x1e6:0x5 DW_TAG_formal_parameter
	.long	260                             @ DW_AT_abstract_origin
	.byte	22                              @ Abbrev [22] 0x1eb:0x5 DW_TAG_formal_parameter
	.long	284                             @ DW_AT_abstract_origin
	.byte	18                              @ Abbrev [18] 0x1f0:0x14 DW_TAG_lexical_block
	.long	.Ltmp22                         @ DW_AT_low_pc
	.long	.Ltmp27                         @ DW_AT_high_pc
	.byte	23                              @ Abbrev [23] 0x1f9:0x5 DW_TAG_variable
	.long	297                             @ DW_AT_abstract_origin
	.byte	23                              @ Abbrev [23] 0x1fe:0x5 DW_TAG_variable
	.long	309                             @ DW_AT_abstract_origin
	.byte	0                               @ End Of Children Mark
	.byte	0                               @ End Of Children Mark
	.byte	21                              @ Abbrev [21] 0x205:0x20 DW_TAG_inlined_subroutine
	.long	183                             @ DW_AT_abstract_origin
	.long	.Ltmp13                         @ DW_AT_low_pc
	.long	.Ltmp18                         @ DW_AT_high_pc
	.byte	1                               @ DW_AT_call_file
	.byte	22                              @ DW_AT_call_line
	.byte	33                              @ DW_AT_call_column
	.byte	22                              @ Abbrev [22] 0x215:0x5 DW_TAG_formal_parameter
	.long	198                             @ DW_AT_abstract_origin
	.byte	23                              @ Abbrev [23] 0x21a:0x5 DW_TAG_variable
	.long	210                             @ DW_AT_abstract_origin
	.byte	23                              @ Abbrev [23] 0x21f:0x5 DW_TAG_variable
	.long	222                             @ DW_AT_abstract_origin
	.byte	0                               @ End Of Children Mark
	.byte	0                               @ End Of Children Mark
	.byte	24                              @ Abbrev [24] 0x226:0xa DW_TAG_TI_reserved_3
	.long	.Ltmp1                          @ DW_AT_low_pc
	.byte	1                               @ DW_AT_TI_reserved_9
	.long	.Linfo_string20                 @ DW_AT_name
	.byte	24                              @ Abbrev [24] 0x230:0xa DW_TAG_TI_reserved_3
	.long	.Ltmp5                          @ DW_AT_low_pc
	.byte	1                               @ DW_AT_TI_reserved_9
	.long	.Linfo_string21                 @ DW_AT_name
	.byte	24                              @ Abbrev [24] 0x23a:0xa DW_TAG_TI_reserved_3
	.long	.Ltmp7                          @ DW_AT_low_pc
	.byte	1                               @ DW_AT_TI_reserved_9
	.long	.Linfo_string22                 @ DW_AT_name
	.byte	24                              @ Abbrev [24] 0x244:0xa DW_TAG_TI_reserved_3
	.long	.Ltmp8                          @ DW_AT_low_pc
	.byte	1                               @ DW_AT_TI_reserved_9
	.long	.Linfo_string22                 @ DW_AT_name
	.byte	24                              @ Abbrev [24] 0x24e:0xa DW_TAG_TI_reserved_3
	.long	.Ltmp9                          @ DW_AT_low_pc
	.byte	1                               @ DW_AT_TI_reserved_9
	.long	.Linfo_string23                 @ DW_AT_name
	.byte	24                              @ Abbrev [24] 0x258:0xa DW_TAG_TI_reserved_3
	.long	.Ltmp19                         @ DW_AT_low_pc
	.byte	1                               @ DW_AT_TI_reserved_9
	.long	.Linfo_string24                 @ DW_AT_name
	.byte	24                              @ Abbrev [24] 0x262:0xa DW_TAG_TI_reserved_3
	.long	.Ltmp20                         @ DW_AT_low_pc
	.byte	1                               @ DW_AT_TI_reserved_9
	.long	.Linfo_string25                 @ DW_AT_name
	.byte	24                              @ Abbrev [24] 0x26c:0xa DW_TAG_TI_reserved_3
	.long	.Ltmp29                         @ DW_AT_low_pc
	.byte	1                               @ DW_AT_TI_reserved_9
	.long	.Linfo_string22                 @ DW_AT_name
	.byte	0                               @ End Of Children Mark
	.byte	25                              @ Abbrev [25] 0x277:0x5 DW_TAG_volatile_type
	.long	347                             @ DW_AT_type
	.byte	3                               @ Abbrev [3] 0x27c:0xc DW_TAG_array_type
	.long	63                              @ DW_AT_type
	.byte	4                               @ Abbrev [4] 0x281:0x6 DW_TAG_subrange_type
	.long	70                              @ DW_AT_type
	.byte	32                              @ DW_AT_count
	.byte	0                               @ End Of Children Mark
	.byte	0                               @ End Of Children Mark
.Ldebug_info_end0:
	.section	.debug_str,"MS",%progbits,1
.Linfo_string0:
	.asciz	"TI clang version 18.1.8 (ssh://git@bitbucket.itg.ti.com/code/llvm-project.git 41ce286cff6db007d382d297353d8bf884b450b7)" @ string offset=0
.Linfo_string1:
	.asciz	"sha256/main.c"                 @ string offset=120
.Linfo_string2:
	.asciz	"/home/main/Documents/school/Fault-Injection-Finder/targets/timspm0l2228/source" @ string offset=134
.Linfo_string3:
	.asciz	"char"                          @ string offset=213
.Linfo_string4:
	.asciz	"__ARRAY_SIZE_TYPE__"           @ string offset=218
.Linfo_string5:
	.asciz	"unsigned int"                  @ string offset=238
.Linfo_string6:
	.asciz	"size_t"                        @ string offset=251
.Linfo_string7:
	.asciz	"unsigned char"                 @ string offset=258
.Linfo_string8:
	.asciz	"strlen"                        @ string offset=272
.Linfo_string9:
	.asciz	"string"                        @ string offset=279
.Linfo_string10:
	.asciz	"s"                             @ string offset=286
.Linfo_string11:
	.asciz	"n"                             @ string offset=288
.Linfo_string12:
	.asciz	"memcmp"                        @ string offset=290
.Linfo_string13:
	.asciz	"int"                           @ string offset=297
.Linfo_string14:
	.asciz	"cs"                            @ string offset=301
.Linfo_string15:
	.asciz	"ct"                            @ string offset=304
.Linfo_string16:
	.asciz	"mem2"                          @ string offset=307
.Linfo_string17:
	.asciz	"mem1"                          @ string offset=312
.Linfo_string18:
	.asciz	"cp1"                           @ string offset=317
.Linfo_string19:
	.asciz	"cp2"                           @ string offset=321
.Linfo_string20:
	.asciz	"init_device"                   @ string offset=325
.Linfo_string21:
	.asciz	"pwned"                         @ string offset=337
.Linfo_string22:
	.asciz	"_write"                        @ string offset=343
.Linfo_string23:
	.asciz	"_read"                         @ string offset=350
.Linfo_string24:
	.asciz	"sha256_easy_hash"              @ string offset=356
.Linfo_string25:
	.asciz	"led_blip"                      @ string offset=373
.Linfo_string26:
	.asciz	"main"                          @ string offset=382
.Linfo_string27:
	.asciz	"dummy"                         @ string offset=387
.Linfo_string28:
	.asciz	"input"                         @ string offset=393
.Linfo_string29:
	.asciz	"test_hash"                     @ string offset=399
.Linfo_string30:
	.asciz	"real_hash"                     @ string offset=409
	.ident	"TI clang version 18.1.8 (ssh://git@bitbucket.itg.ti.com/code/llvm-project.git 41ce286cff6db007d382d297353d8bf884b450b7)"
	.section	".note.GNU-stack","",%progbits
	.addrsig
	.eabi_attribute	30, 1	@ Tag_ABI_optimization_goals
	.TI_attribute	16, 0	@ Tag_Instrumentation
	.section	.debug_line,"",%progbits
.Lline_table_start0:
