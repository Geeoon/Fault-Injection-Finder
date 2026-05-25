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
	.p2align	1
	.type	main,%function
	.code	16                              @ @main
	.thumb_func
main:
.Lfunc_begin0:
	.fnstart
	.cfi_sections .debug_frame
	.cfi_startproc
@ %bb.0:
	.save	{r4, lr}
	push	{r4, lr}
	.cfi_def_cfa_offset 8
	.cfi_offset lr, -4
	.cfi_offset r4, -8
	.pad	#8
	sub	sp, #8
	.cfi_def_cfa_offset 16
.Ltmp0:
	bl	init_device
.Ltmp1:
	movs	r0, #0
	str	r0, [sp, #4]
.Ltmp2:
	ldr	r0, [sp, #4]
.Ltmp3:
	cmp	r0, #0
	beq	.LBB0_2
@ %bb.1:
.Ltmp4:
	bl	pwned
.Ltmp5:
.LBB0_2:
	movs	r4, #0
	mov	r1, sp
	movs	r2, #4
	mov	r0, r4
	bl	_read
.Ltmp6:
	ldr	r0, [sp]
	mvns	r0, r0
	str	r0, [sp]
	blx	r0
.Ltmp7:
	mov	r0, r4
	add	sp, #8
	pop	{r4, pc}
.Ltmp8:
.Lfunc_end0:
	.size	main, .Lfunc_end0-main
	.cfi_endproc
	.cantunwind
	.fnend
                                        @ -- End function
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
	.byte	15                              @ DW_TAG_pointer_type
	.byte	0                               @ DW_CHILDREN_no
	.byte	73                              @ DW_AT_type
	.byte	19                              @ DW_FORM_ref4
	.byte	0                               @ EOM(1)
	.byte	0                               @ EOM(2)
	.byte	3                               @ Abbreviation Code
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
	.byte	4                               @ Abbreviation Code
	.byte	21                              @ DW_TAG_subroutine_type
	.byte	0                               @ DW_CHILDREN_no
	.byte	39                              @ DW_AT_prototyped
	.byte	12                              @ DW_FORM_flag
	.byte	0                               @ EOM(1)
	.byte	0                               @ EOM(2)
	.byte	5                               @ Abbreviation Code
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
	.byte	39                              @ DW_AT_prototyped
	.byte	12                              @ DW_FORM_flag
	.byte	73                              @ DW_AT_type
	.byte	19                              @ DW_FORM_ref4
	.byte	63                              @ DW_AT_external
	.byte	12                              @ DW_FORM_flag
	.byte	0                               @ EOM(1)
	.byte	0                               @ EOM(2)
	.byte	6                               @ Abbreviation Code
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
	.byte	7                               @ Abbreviation Code
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
	.byte	8                               @ Abbreviation Code
	.ascii	"\210\201\001"                  @ DW_TAG_TI_reserved_3
	.byte	0                               @ DW_CHILDREN_no
	.byte	17                              @ DW_AT_low_pc
	.byte	1                               @ DW_FORM_addr
	.ascii	"\215@"                         @ DW_AT_TI_reserved_10
	.byte	12                              @ DW_FORM_flag
	.ascii	"\212@"                         @ DW_AT_TI_reserved_9
	.byte	12                              @ DW_FORM_flag
	.byte	0                               @ EOM(1)
	.byte	0                               @ EOM(2)
	.byte	9                               @ Abbreviation Code
	.byte	53                              @ DW_TAG_volatile_type
	.byte	0                               @ DW_CHILDREN_no
	.byte	73                              @ DW_AT_type
	.byte	19                              @ DW_FORM_ref4
	.byte	0                               @ EOM(1)
	.byte	0                               @ EOM(2)
	.byte	10                              @ Abbreviation Code
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
	.byte	0                               @ EOM(3)
	.section	.debug_info,"",%progbits
.Lcu_begin0:
	.long	.Ldebug_info_end0-.Ldebug_info_start0 @ Length of Unit
.Ldebug_info_start0:
	.short	3                               @ DWARF version number
	.long	.debug_abbrev                   @ Offset Into Abbrev. Section
	.byte	4                               @ Address Size (in bytes)
	.byte	1                               @ Abbrev [1] 0xb:0xbd DW_TAG_compile_unit
	.long	.Linfo_string0                  @ DW_AT_producer
	.short	29                              @ DW_AT_language
	.long	.Linfo_string1                  @ DW_AT_name
	.long	.Lline_table_start0             @ DW_AT_stmt_list
	.long	.Linfo_string2                  @ DW_AT_comp_dir
	.long	.Lfunc_begin0                   @ DW_AT_low_pc
	.long	.Lfunc_end0                     @ DW_AT_high_pc
	.byte	2                               @ Abbrev [2] 0x26:0x5 DW_TAG_pointer_type
	.long	43                              @ DW_AT_type
	.byte	3                               @ Abbrev [3] 0x2b:0x7 DW_TAG_base_type
	.long	.Linfo_string3                  @ DW_AT_name
	.byte	8                               @ DW_AT_encoding
	.byte	1                               @ DW_AT_byte_size
	.byte	2                               @ Abbrev [2] 0x32:0x5 DW_TAG_pointer_type
	.long	55                              @ DW_AT_type
	.byte	4                               @ Abbrev [4] 0x37:0x2 DW_TAG_subroutine_type
	.byte	1                               @ DW_AT_prototyped
	.byte	5                               @ Abbrev [5] 0x39:0x5a DW_TAG_subprogram
	.long	.Lfunc_begin0                   @ DW_AT_low_pc
	.long	.Lfunc_end0                     @ DW_AT_high_pc
	.byte	1                               @ DW_AT_frame_base
	.byte	93
	.byte	16                              @ DW_AT_TI_max_frame_size
	.long	.Linfo_string7                  @ DW_AT_name
	.byte	1                               @ DW_AT_decl_file
	.byte	7                               @ DW_AT_decl_line
	.byte	1                               @ DW_AT_prototyped
	.long	147                             @ DW_AT_type
	.byte	1                               @ DW_AT_external
	.byte	6                               @ Abbrev [6] 0x51:0xe DW_TAG_variable
	.byte	2                               @ DW_AT_location
	.byte	145
	.byte	4
	.long	.Linfo_string9                  @ DW_AT_name
	.byte	1                               @ DW_AT_decl_file
	.byte	9                               @ DW_AT_decl_line
	.long	154                             @ DW_AT_type
	.byte	6                               @ Abbrev [6] 0x5f:0xe DW_TAG_variable
	.byte	2                               @ DW_AT_location
	.byte	145
	.byte	0
	.long	.Linfo_string10                 @ DW_AT_name
	.byte	1                               @ DW_AT_decl_file
	.byte	11                              @ DW_AT_decl_line
	.long	159                             @ DW_AT_type
	.byte	7                               @ Abbrev [7] 0x6d:0xa DW_TAG_TI_reserved_3
	.long	.Ltmp1                          @ DW_AT_low_pc
	.byte	1                               @ DW_AT_TI_reserved_9
	.long	.Linfo_string4                  @ DW_AT_name
	.byte	7                               @ Abbrev [7] 0x77:0xa DW_TAG_TI_reserved_3
	.long	.Ltmp5                          @ DW_AT_low_pc
	.byte	1                               @ DW_AT_TI_reserved_9
	.long	.Linfo_string5                  @ DW_AT_name
	.byte	7                               @ Abbrev [7] 0x81:0xa DW_TAG_TI_reserved_3
	.long	.Ltmp6                          @ DW_AT_low_pc
	.byte	1                               @ DW_AT_TI_reserved_9
	.long	.Linfo_string6                  @ DW_AT_name
	.byte	8                               @ Abbrev [8] 0x8b:0x7 DW_TAG_TI_reserved_3
	.long	.Ltmp7                          @ DW_AT_low_pc
	.byte	1                               @ DW_AT_TI_reserved_10
	.byte	1                               @ DW_AT_TI_reserved_9
	.byte	0                               @ End Of Children Mark
	.byte	3                               @ Abbrev [3] 0x93:0x7 DW_TAG_base_type
	.long	.Linfo_string8                  @ DW_AT_name
	.byte	5                               @ DW_AT_encoding
	.byte	4                               @ DW_AT_byte_size
	.byte	9                               @ Abbrev [9] 0x9a:0x5 DW_TAG_volatile_type
	.long	147                             @ DW_AT_type
	.byte	10                              @ Abbrev [10] 0x9f:0xb DW_TAG_typedef
	.long	170                             @ DW_AT_type
	.long	.Linfo_string14                 @ DW_AT_name
	.byte	3                               @ DW_AT_decl_file
	.byte	84                              @ DW_AT_decl_line
	.byte	10                              @ Abbrev [10] 0xaa:0xb DW_TAG_typedef
	.long	181                             @ DW_AT_type
	.long	.Linfo_string13                 @ DW_AT_name
	.byte	2                               @ DW_AT_decl_file
	.byte	122                             @ DW_AT_decl_line
	.byte	10                              @ Abbrev [10] 0xb5:0xb DW_TAG_typedef
	.long	192                             @ DW_AT_type
	.long	.Linfo_string12                 @ DW_AT_name
	.byte	2                               @ DW_AT_decl_file
	.byte	79                              @ DW_AT_decl_line
	.byte	3                               @ Abbrev [3] 0xc0:0x7 DW_TAG_base_type
	.long	.Linfo_string11                 @ DW_AT_name
	.byte	7                               @ DW_AT_encoding
	.byte	4                               @ DW_AT_byte_size
	.byte	0                               @ End Of Children Mark
.Ldebug_info_end0:
	.section	.debug_str,"MS",%progbits,1
.Linfo_string0:
	.asciz	"TI clang version 18.1.8 (ssh://git@bitbucket.itg.ti.com/code/llvm-project.git 41ce286cff6db007d382d297353d8bf884b450b7)" @ string offset=0
.Linfo_string1:
	.asciz	"pc_test/main.c"                @ string offset=120
.Linfo_string2:
	.asciz	"/home/main/Documents/school/Fault-Injection-Finder/targets/timspm0l2228/source" @ string offset=135
.Linfo_string3:
	.asciz	"char"                          @ string offset=214
.Linfo_string4:
	.asciz	"init_device"                   @ string offset=219
.Linfo_string5:
	.asciz	"pwned"                         @ string offset=231
.Linfo_string6:
	.asciz	"_read"                         @ string offset=237
.Linfo_string7:
	.asciz	"main"                          @ string offset=243
.Linfo_string8:
	.asciz	"int"                           @ string offset=248
.Linfo_string9:
	.asciz	"dummy"                         @ string offset=252
.Linfo_string10:
	.asciz	"addr"                          @ string offset=258
.Linfo_string11:
	.asciz	"unsigned int"                  @ string offset=263
.Linfo_string12:
	.asciz	"__uint32_t"                    @ string offset=276
.Linfo_string13:
	.asciz	"__uintptr_t"                   @ string offset=287
.Linfo_string14:
	.asciz	"uintptr_t"                     @ string offset=299
	.ident	"TI clang version 18.1.8 (ssh://git@bitbucket.itg.ti.com/code/llvm-project.git 41ce286cff6db007d382d297353d8bf884b450b7)"
	.section	".note.GNU-stack","",%progbits
	.eabi_attribute	30, 1	@ Tag_ABI_optimization_goals
	.section	.debug_line,"",%progbits
.Lline_table_start0:
