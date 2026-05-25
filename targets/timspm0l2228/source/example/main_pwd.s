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
	.section	.text.main,"ax",%progbits
	.hidden	main                            @ -- Begin function main
	.globl	main
	.p2align	2
	.type	main,%function
	.code	16                              @ @main
	.thumb_func
main:
.Lfunc_begin0:
	.fnstart
	.cfi_sections .debug_frame
	.cfi_startproc
@ %bb.0:
	.save	{r4, r5, r6, lr}
	push	{r4, r5, r6, lr}
	.cfi_def_cfa_offset 16
	.cfi_offset lr, -4
	.cfi_offset r6, -8
	.cfi_offset r5, -12
	.cfi_offset r4, -16
	.pad	#104
	sub	sp, #104
	.cfi_def_cfa_offset 120
.Ltmp0:
	bl	init_device
.Ltmp1:
	ldr	r4, .LCPI0_0
.LBB0_1:                                @ =>This Inner Loop Header: Depth=1
	movs	r6, #0
	movs	r2, #17
.Ltmp2:
	mov	r0, r6
	mov	r1, r4
	bl	_write
.Ltmp3:
	add	r5, sp, #4
	movs	r2, #12
	mov	r0, r6
	mov	r1, r5
	bl	_read
.Ltmp4:
	@DEBUG_VALUE: n <- $r0
	adds	r0, r0, r5
.Ltmp5:
	subs	r0, r0, #1
	strb	r6, [r0]
.Ltmp6:
	@DEBUG_VALUE: s1 <- [DW_OP_plus_uconst 4, DW_OP_plus_uconst 1, DW_OP_stack_value] $sp
	@DEBUG_VALUE: s2 <- undef
	@DEBUG_VALUE: strncmp:n <- undef
	@DEBUG_VALUE: strncmp:string2 <- undef
	@DEBUG_VALUE: strncmp:string1 <- [DW_OP_plus_uconst 4, DW_OP_stack_value] $sp
	ldrb	r0, [r5]
.Ltmp7:
	@DEBUG_VALUE: cp <- 51
	@DEBUG_VALUE: result <- undef
	@DEBUG_VALUE: s1 <- [DW_OP_plus_uconst 4, DW_OP_plus_uconst 10, DW_OP_plus_uconst 1, DW_OP_stack_value] $sp
	cmp	r0, #112
	bne	.LBB0_1
.Ltmp8:
@ %bb.2:                                @   in Loop: Header=BB0_1 Depth=1
	@DEBUG_VALUE: s1 <- [DW_OP_plus_uconst 4, DW_OP_plus_uconst 10, DW_OP_plus_uconst 1, DW_OP_stack_value] $sp
	@DEBUG_VALUE: cp <- 51
	@DEBUG_VALUE: strncmp:string1 <- [DW_OP_plus_uconst 4, DW_OP_stack_value] $sp
	ldrb	r0, [r5, #1]
	cmp	r0, #97
	bne	.LBB0_1
.Ltmp9:
@ %bb.3:                                @   in Loop: Header=BB0_1 Depth=1
	@DEBUG_VALUE: s1 <- [DW_OP_plus_uconst 4, DW_OP_plus_uconst 10, DW_OP_plus_uconst 1, DW_OP_stack_value] $sp
	@DEBUG_VALUE: cp <- 51
	@DEBUG_VALUE: strncmp:string1 <- [DW_OP_plus_uconst 4, DW_OP_stack_value] $sp
	ldrb	r0, [r5, #2]
	cmp	r0, #115
	bne	.LBB0_1
.Ltmp10:
@ %bb.4:                                @   in Loop: Header=BB0_1 Depth=1
	@DEBUG_VALUE: s1 <- [DW_OP_plus_uconst 4, DW_OP_plus_uconst 10, DW_OP_plus_uconst 1, DW_OP_stack_value] $sp
	@DEBUG_VALUE: cp <- 51
	@DEBUG_VALUE: strncmp:string1 <- [DW_OP_plus_uconst 4, DW_OP_stack_value] $sp
	ldrb	r0, [r5, #3]
	cmp	r0, #115
	bne	.LBB0_1
.Ltmp11:
@ %bb.5:                                @   in Loop: Header=BB0_1 Depth=1
	@DEBUG_VALUE: s1 <- [DW_OP_plus_uconst 4, DW_OP_plus_uconst 10, DW_OP_plus_uconst 1, DW_OP_stack_value] $sp
	@DEBUG_VALUE: cp <- 51
	@DEBUG_VALUE: strncmp:string1 <- [DW_OP_plus_uconst 4, DW_OP_stack_value] $sp
	ldrb	r0, [r5, #4]
	cmp	r0, #119
	bne	.LBB0_1
.Ltmp12:
@ %bb.6:                                @   in Loop: Header=BB0_1 Depth=1
	@DEBUG_VALUE: s1 <- [DW_OP_plus_uconst 4, DW_OP_plus_uconst 10, DW_OP_plus_uconst 1, DW_OP_stack_value] $sp
	@DEBUG_VALUE: cp <- 51
	@DEBUG_VALUE: strncmp:string1 <- [DW_OP_plus_uconst 4, DW_OP_stack_value] $sp
	ldrb	r0, [r5, #5]
	cmp	r0, #111
	bne	.LBB0_1
.Ltmp13:
@ %bb.7:                                @   in Loop: Header=BB0_1 Depth=1
	@DEBUG_VALUE: s1 <- [DW_OP_plus_uconst 4, DW_OP_plus_uconst 10, DW_OP_plus_uconst 1, DW_OP_stack_value] $sp
	@DEBUG_VALUE: cp <- 51
	@DEBUG_VALUE: strncmp:string1 <- [DW_OP_plus_uconst 4, DW_OP_stack_value] $sp
	ldrb	r0, [r5, #6]
	cmp	r0, #114
	bne	.LBB0_1
.Ltmp14:
@ %bb.8:                                @   in Loop: Header=BB0_1 Depth=1
	@DEBUG_VALUE: s1 <- [DW_OP_plus_uconst 4, DW_OP_plus_uconst 10, DW_OP_plus_uconst 1, DW_OP_stack_value] $sp
	@DEBUG_VALUE: cp <- 51
	@DEBUG_VALUE: strncmp:string1 <- [DW_OP_plus_uconst 4, DW_OP_stack_value] $sp
	ldrb	r0, [r5, #7]
	cmp	r0, #100
	bne	.LBB0_1
.Ltmp15:
@ %bb.9:                                @   in Loop: Header=BB0_1 Depth=1
	@DEBUG_VALUE: s1 <- [DW_OP_plus_uconst 4, DW_OP_plus_uconst 10, DW_OP_plus_uconst 1, DW_OP_stack_value] $sp
	@DEBUG_VALUE: cp <- 51
	@DEBUG_VALUE: strncmp:string1 <- [DW_OP_plus_uconst 4, DW_OP_stack_value] $sp
	ldrb	r0, [r5, #8]
	cmp	r0, #49
	bne	.LBB0_1
.Ltmp16:
@ %bb.10:                               @   in Loop: Header=BB0_1 Depth=1
	@DEBUG_VALUE: s1 <- [DW_OP_plus_uconst 4, DW_OP_plus_uconst 10, DW_OP_plus_uconst 1, DW_OP_stack_value] $sp
	@DEBUG_VALUE: cp <- 51
	@DEBUG_VALUE: strncmp:string1 <- [DW_OP_plus_uconst 4, DW_OP_stack_value] $sp
	ldrb	r0, [r5, #9]
	cmp	r0, #50
	bne	.LBB0_1
.Ltmp17:
@ %bb.11:                               @   in Loop: Header=BB0_1 Depth=1
	@DEBUG_VALUE: s1 <- [DW_OP_plus_uconst 4, DW_OP_plus_uconst 10, DW_OP_plus_uconst 1, DW_OP_stack_value] $sp
	@DEBUG_VALUE: cp <- 51
	@DEBUG_VALUE: strncmp:string1 <- [DW_OP_plus_uconst 4, DW_OP_stack_value] $sp
	ldrb	r0, [r5, #10]
	cmp	r0, #51
	bne	.LBB0_1
.Ltmp18:
@ %bb.12:
	@DEBUG_VALUE: strncmp:n <- undef
	@DEBUG_VALUE: s2 <- undef
	@DEBUG_VALUE: s1 <- [DW_OP_plus_uconst 4, DW_OP_plus_uconst 10, DW_OP_plus_uconst 1, DW_OP_stack_value] $sp
	ldr	r1, .LCPI0_1
	movs	r4, #0
	movs	r2, #15
	mov	r0, r4
	bl	_write
.Ltmp19:
	mov	r0, r4
	add	sp, #104
	pop	{r4, r5, r6, pc}
.Ltmp20:
	.p2align	2
@ %bb.13:
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
	.asciz	"enter a password:"
	.size	.L.str, 18

	.type	.L.str.2,%object                @ @.str.2
	.section	.rodata.str1.17100691992556644108.1,"aMS",%progbits,1
.L.str.2:
	.asciz	"access granted."
	.size	.L.str.2, 16

	.section	.debug_loc,"",%progbits
.Ldebug_loc0:
	.long	.Ltmp4-.Lfunc_begin0
	.long	.Ltmp5-.Lfunc_begin0
	.short	1                               @ Loc expr size
	.byte	80                              @ DW_OP_reg0
	.long	0
	.long	0
.Ldebug_loc1:
	.long	.Ltmp7-.Lfunc_begin0
	.long	.Ltmp18-.Lfunc_begin0
	.short	2                               @ Loc expr size
	.byte	16                              @ DW_OP_constu
	.byte	51                              @ 51
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
	.byte	17                              @ DW_AT_low_pc
	.byte	1                               @ DW_FORM_addr
	.byte	18                              @ DW_AT_high_pc
	.byte	1                               @ DW_FORM_addr
	.byte	0                               @ EOM(1)
	.byte	0                               @ EOM(2)
	.byte	18                              @ Abbreviation Code
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
	.byte	52                              @ DW_TAG_variable
	.byte	0                               @ DW_CHILDREN_no
	.byte	49                              @ DW_AT_abstract_origin
	.byte	19                              @ DW_FORM_ref4
	.byte	0                               @ EOM(1)
	.byte	0                               @ EOM(2)
	.byte	22                              @ Abbreviation Code
	.byte	52                              @ DW_TAG_variable
	.byte	0                               @ DW_CHILDREN_no
	.byte	2                               @ DW_AT_location
	.byte	6                               @ DW_FORM_data4
	.byte	49                              @ DW_AT_abstract_origin
	.byte	19                              @ DW_FORM_ref4
	.byte	0                               @ EOM(1)
	.byte	0                               @ EOM(2)
	.byte	23                              @ Abbreviation Code
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
	.byte	0                               @ EOM(3)
	.section	.debug_info,"",%progbits
.Lcu_begin0:
	.long	.Ldebug_info_end0-.Ldebug_info_start0 @ Length of Unit
.Ldebug_info_start0:
	.short	3                               @ DWARF version number
	.long	.debug_abbrev                   @ Offset Into Abbrev. Section
	.byte	4                               @ Address Size (in bytes)
	.byte	1                               @ Abbrev [1] 0xb:0x1a0 DW_TAG_compile_unit
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
	.byte	12                              @ DW_AT_decl_line
	.byte	5                               @ DW_AT_location
	.byte	3
	.long	.L.str
	.byte	3                               @ Abbrev [3] 0x33:0xc DW_TAG_array_type
	.long	63                              @ DW_AT_type
	.byte	4                               @ Abbrev [4] 0x38:0x6 DW_TAG_subrange_type
	.long	70                              @ DW_AT_type
	.byte	18                              @ DW_AT_count
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
	.byte	13                              @ DW_AT_decl_line
	.byte	3                               @ Abbrev [3] 0x54:0xc DW_TAG_array_type
	.long	63                              @ DW_AT_type
	.byte	4                               @ Abbrev [4] 0x59:0x6 DW_TAG_subrange_type
	.long	70                              @ DW_AT_type
	.byte	12                              @ DW_AT_count
	.byte	0                               @ End Of Children Mark
	.byte	2                               @ Abbrev [2] 0x60:0xd DW_TAG_variable
	.long	109                             @ DW_AT_type
	.byte	1                               @ DW_AT_decl_file
	.byte	16                              @ DW_AT_decl_line
	.byte	5                               @ DW_AT_location
	.byte	3
	.long	.L.str.2
	.byte	3                               @ Abbrev [3] 0x6d:0xc DW_TAG_array_type
	.long	63                              @ DW_AT_type
	.byte	4                               @ Abbrev [4] 0x72:0x6 DW_TAG_subrange_type
	.long	70                              @ DW_AT_type
	.byte	16                              @ DW_AT_count
	.byte	0                               @ End Of Children Mark
	.byte	8                               @ Abbrev [8] 0x79:0xb DW_TAG_typedef
	.long	132                             @ DW_AT_type
	.long	.Linfo_string6                  @ DW_AT_name
	.byte	2                               @ DW_AT_decl_file
	.byte	66                              @ DW_AT_decl_line
	.byte	5                               @ Abbrev [5] 0x84:0x7 DW_TAG_base_type
	.long	.Linfo_string5                  @ DW_AT_name
	.byte	7                               @ DW_AT_encoding
	.byte	4                               @ DW_AT_byte_size
	.byte	5                               @ Abbrev [5] 0x8b:0x7 DW_TAG_base_type
	.long	.Linfo_string7                  @ DW_AT_name
	.byte	8                               @ DW_AT_encoding
	.byte	1                               @ DW_AT_byte_size
	.byte	9                               @ Abbrev [9] 0x92:0x66 DW_TAG_subprogram
	.long	.Linfo_string8                  @ DW_AT_name
	.byte	2                               @ DW_AT_decl_file
	.short	427                             @ DW_AT_decl_line
	.byte	1                               @ DW_AT_prototyped
	.byte	3                               @ DW_AT_calling_convention
	.long	248                             @ DW_AT_type
	.byte	1                               @ DW_AT_inline
	.byte	10                              @ Abbrev [10] 0xa1:0xc DW_TAG_formal_parameter
	.long	.Linfo_string10                 @ DW_AT_name
	.byte	2                               @ DW_AT_decl_file
	.short	427                             @ DW_AT_decl_line
	.long	255                             @ DW_AT_type
	.byte	10                              @ Abbrev [10] 0xad:0xc DW_TAG_formal_parameter
	.long	.Linfo_string11                 @ DW_AT_name
	.byte	2                               @ DW_AT_decl_file
	.short	427                             @ DW_AT_decl_line
	.long	255                             @ DW_AT_type
	.byte	10                              @ Abbrev [10] 0xb9:0xc DW_TAG_formal_parameter
	.long	.Linfo_string12                 @ DW_AT_name
	.byte	2                               @ DW_AT_decl_file
	.short	427                             @ DW_AT_decl_line
	.long	121                             @ DW_AT_type
	.byte	11                              @ Abbrev [11] 0xc5:0x32 DW_TAG_lexical_block
	.byte	12                              @ Abbrev [12] 0xc6:0xc DW_TAG_variable
	.long	.Linfo_string13                 @ DW_AT_name
	.byte	2                               @ DW_AT_decl_file
	.short	431                             @ DW_AT_decl_line
	.long	255                             @ DW_AT_type
	.byte	12                              @ Abbrev [12] 0xd2:0xc DW_TAG_variable
	.long	.Linfo_string14                 @ DW_AT_name
	.byte	2                               @ DW_AT_decl_file
	.short	433                             @ DW_AT_decl_line
	.long	139                             @ DW_AT_type
	.byte	12                              @ Abbrev [12] 0xde:0xc DW_TAG_variable
	.long	.Linfo_string15                 @ DW_AT_name
	.byte	2                               @ DW_AT_decl_file
	.short	432                             @ DW_AT_decl_line
	.long	255                             @ DW_AT_type
	.byte	12                              @ Abbrev [12] 0xea:0xc DW_TAG_variable
	.long	.Linfo_string16                 @ DW_AT_name
	.byte	2                               @ DW_AT_decl_file
	.short	434                             @ DW_AT_decl_line
	.long	248                             @ DW_AT_type
	.byte	0                               @ End Of Children Mark
	.byte	0                               @ End Of Children Mark
	.byte	5                               @ Abbrev [5] 0xf8:0x7 DW_TAG_base_type
	.long	.Linfo_string9                  @ DW_AT_name
	.byte	5                               @ DW_AT_encoding
	.byte	4                               @ DW_AT_byte_size
	.byte	13                              @ Abbrev [13] 0xff:0x5 DW_TAG_pointer_type
	.long	260                             @ DW_AT_type
	.byte	14                              @ Abbrev [14] 0x104:0x5 DW_TAG_const_type
	.long	63                              @ DW_AT_type
	.byte	15                              @ Abbrev [15] 0x109:0x95 DW_TAG_subprogram
	.long	.Lfunc_begin0                   @ DW_AT_low_pc
	.long	.Lfunc_end0                     @ DW_AT_high_pc
	.byte	1                               @ DW_AT_frame_base
	.byte	93
	.byte	120                             @ DW_AT_TI_max_frame_size
	.long	.Linfo_string20                 @ DW_AT_name
	.byte	1                               @ DW_AT_decl_file
	.byte	8                               @ DW_AT_decl_line
	.long	248                             @ DW_AT_type
	.byte	1                               @ DW_AT_external
	.byte	16                              @ Abbrev [16] 0x120:0xe DW_TAG_variable
	.byte	2                               @ DW_AT_location
	.byte	145
	.byte	4
	.long	.Linfo_string21                 @ DW_AT_name
	.byte	1                               @ DW_AT_decl_file
	.byte	10                              @ DW_AT_decl_line
	.long	414                             @ DW_AT_type
	.byte	17                              @ Abbrev [17] 0x12e:0x19 DW_TAG_lexical_block
	.long	.Ltmp2                          @ DW_AT_low_pc
	.long	.Ltmp6                          @ DW_AT_high_pc
	.byte	18                              @ Abbrev [18] 0x137:0xf DW_TAG_variable
	.long	.Ldebug_loc0                    @ DW_AT_location
	.long	.Linfo_string12                 @ DW_AT_name
	.byte	1                               @ DW_AT_decl_file
	.byte	13                              @ DW_AT_decl_line
	.long	248                             @ DW_AT_type
	.byte	0                               @ End Of Children Mark
	.byte	19                              @ Abbrev [19] 0x147:0x2e DW_TAG_inlined_subroutine
	.long	146                             @ DW_AT_abstract_origin
	.long	.Ltmp6                          @ DW_AT_low_pc
	.long	.Ltmp18                         @ DW_AT_high_pc
	.byte	1                               @ DW_AT_call_file
	.byte	15                              @ DW_AT_call_line
	.byte	13                              @ DW_AT_call_column
	.byte	20                              @ Abbrev [20] 0x157:0x5 DW_TAG_formal_parameter
	.long	161                             @ DW_AT_abstract_origin
	.byte	17                              @ Abbrev [17] 0x15c:0x18 DW_TAG_lexical_block
	.long	.Ltmp6                          @ DW_AT_low_pc
	.long	.Ltmp18                         @ DW_AT_high_pc
	.byte	21                              @ Abbrev [21] 0x165:0x5 DW_TAG_variable
	.long	198                             @ DW_AT_abstract_origin
	.byte	22                              @ Abbrev [22] 0x16a:0x9 DW_TAG_variable
	.long	.Ldebug_loc1                    @ DW_AT_location
	.long	210                             @ DW_AT_abstract_origin
	.byte	0                               @ End Of Children Mark
	.byte	0                               @ End Of Children Mark
	.byte	23                              @ Abbrev [23] 0x175:0xa DW_TAG_TI_reserved_3
	.long	.Ltmp1                          @ DW_AT_low_pc
	.byte	1                               @ DW_AT_TI_reserved_9
	.long	.Linfo_string17                 @ DW_AT_name
	.byte	23                              @ Abbrev [23] 0x17f:0xa DW_TAG_TI_reserved_3
	.long	.Ltmp3                          @ DW_AT_low_pc
	.byte	1                               @ DW_AT_TI_reserved_9
	.long	.Linfo_string18                 @ DW_AT_name
	.byte	23                              @ Abbrev [23] 0x189:0xa DW_TAG_TI_reserved_3
	.long	.Ltmp4                          @ DW_AT_low_pc
	.byte	1                               @ DW_AT_TI_reserved_9
	.long	.Linfo_string19                 @ DW_AT_name
	.byte	23                              @ Abbrev [23] 0x193:0xa DW_TAG_TI_reserved_3
	.long	.Ltmp19                         @ DW_AT_low_pc
	.byte	1                               @ DW_AT_TI_reserved_9
	.long	.Linfo_string18                 @ DW_AT_name
	.byte	0                               @ End Of Children Mark
	.byte	3                               @ Abbrev [3] 0x19e:0xc DW_TAG_array_type
	.long	63                              @ DW_AT_type
	.byte	4                               @ Abbrev [4] 0x1a3:0x6 DW_TAG_subrange_type
	.long	70                              @ DW_AT_type
	.byte	100                             @ DW_AT_count
	.byte	0                               @ End Of Children Mark
	.byte	0                               @ End Of Children Mark
.Ldebug_info_end0:
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
	.asciz	"cp"                            @ string offset=307
.Linfo_string15:
	.asciz	"s2"                            @ string offset=310
.Linfo_string16:
	.asciz	"result"                        @ string offset=313
.Linfo_string17:
	.asciz	"init_device"                   @ string offset=320
.Linfo_string18:
	.asciz	"_write"                        @ string offset=332
.Linfo_string19:
	.asciz	"_read"                         @ string offset=339
.Linfo_string20:
	.asciz	"main"                          @ string offset=345
.Linfo_string21:
	.asciz	"input"                         @ string offset=350
	.ident	"TI clang version 18.1.8 (ssh://git@bitbucket.itg.ti.com/code/llvm-project.git 41ce286cff6db007d382d297353d8bf884b450b7)"
	.section	".note.GNU-stack","",%progbits
	.eabi_attribute	30, 1	@ Tag_ABI_optimization_goals
	.section	.debug_line,"",%progbits
.Lline_table_start0:
