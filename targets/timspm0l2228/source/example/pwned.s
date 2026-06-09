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
	.file	"pwned.c"
	.section	.text.pwned,"ax",%progbits
	.hidden	pwned                           @ -- Begin function pwned
	.globl	pwned
	.p2align	2
	.type	pwned,%function
	.code	16                              @ @pwned
	.thumb_func
pwned:
.Lfunc_begin0:
	.fnstart
	.cfi_sections .debug_frame
	.cfi_startproc
@ %bb.0:
	ldr	r4, .LCPI0_0
.LBB0_1:                                @ =>This Inner Loop Header: Depth=1
	movs	r5, #0
	movs	r6, #6
.Ltmp0:
	mov	r0, r5
	mov	r1, r4
	mov	r2, r6
	bl	_write
.Ltmp1:
	mov	r0, r5
	mov	r1, r4
	mov	r2, r6
	bl	_write
.Ltmp2:
	mov	r0, r5
	mov	r1, r4
	mov	r2, r6
	bl	_write
.Ltmp3:
	b	.LBB0_1
.Ltmp4:
	.p2align	2
@ %bb.2:
.LCPI0_0:
	.long	.L.str
.Lfunc_end0:
	.size	pwned, .Lfunc_end0-pwned
	.cfi_endproc
	.cantunwind
	.fnend
                                        @ -- End function
	.section	.text.pwned2,"ax",%progbits
	.hidden	pwned2                          @ -- Begin function pwned2
	.globl	pwned2
	.p2align	2
	.type	pwned2,%function
	.code	16                              @ @pwned2
	.thumb_func
pwned2:
.Lfunc_begin1:
	.fnstart
	.cfi_startproc
@ %bb.0:
	ldr	r4, .LCPI1_0
.LBB1_1:                                @ =>This Inner Loop Header: Depth=1
	movs	r5, #0
	movs	r6, #7
.Ltmp5:
	mov	r0, r5
	mov	r1, r4
	mov	r2, r6
	bl	_write
.Ltmp6:
	mov	r0, r5
	mov	r1, r4
	mov	r2, r6
	bl	_write
.Ltmp7:
	mov	r0, r5
	mov	r1, r4
	mov	r2, r6
	bl	_write
.Ltmp8:
	b	.LBB1_1
.Ltmp9:
	.p2align	2
@ %bb.2:
.LCPI1_0:
	.long	.L.str.1
.Lfunc_end1:
	.size	pwned2, .Lfunc_end1-pwned2
	.cfi_endproc
	.cantunwind
	.fnend
                                        @ -- End function
	.section	.text.pwned3,"ax",%progbits
	.hidden	pwned3                          @ -- Begin function pwned3
	.globl	pwned3
	.p2align	2
	.type	pwned3,%function
	.code	16                              @ @pwned3
	.thumb_func
pwned3:
.Lfunc_begin2:
	.fnstart
	.cfi_startproc
@ %bb.0:
	ldr	r4, .LCPI2_0
.LBB2_1:                                @ =>This Inner Loop Header: Depth=1
	movs	r5, #0
	movs	r6, #7
.Ltmp10:
	mov	r0, r5
	mov	r1, r4
	mov	r2, r6
	bl	_write
.Ltmp11:
	mov	r0, r5
	mov	r1, r4
	mov	r2, r6
	bl	_write
.Ltmp12:
	mov	r0, r5
	mov	r1, r4
	mov	r2, r6
	bl	_write
.Ltmp13:
	b	.LBB2_1
.Ltmp14:
	.p2align	2
@ %bb.2:
.LCPI2_0:
	.long	.L.str.2
.Lfunc_end2:
	.size	pwned3, .Lfunc_end2-pwned3
	.cfi_endproc
	.cantunwind
	.fnend
                                        @ -- End function
	.section	.text.pwned4,"ax",%progbits
	.hidden	pwned4                          @ -- Begin function pwned4
	.globl	pwned4
	.p2align	2
	.type	pwned4,%function
	.code	16                              @ @pwned4
	.thumb_func
pwned4:
.Lfunc_begin3:
	.fnstart
	.cfi_startproc
@ %bb.0:
	ldr	r4, .LCPI3_0
.LBB3_1:                                @ =>This Inner Loop Header: Depth=1
	movs	r5, #0
	movs	r6, #7
.Ltmp15:
	mov	r0, r5
	mov	r1, r4
	mov	r2, r6
	bl	_write
.Ltmp16:
	mov	r0, r5
	mov	r1, r4
	mov	r2, r6
	bl	_write
.Ltmp17:
	mov	r0, r5
	mov	r1, r4
	mov	r2, r6
	bl	_write
.Ltmp18:
	b	.LBB3_1
.Ltmp19:
	.p2align	2
@ %bb.2:
.LCPI3_0:
	.long	.L.str.3
.Lfunc_end3:
	.size	pwned4, .Lfunc_end3-pwned4
	.cfi_endproc
	.cantunwind
	.fnend
                                        @ -- End function
	.type	.L.str,%object                  @ @.str
	.section	.rodata.str1.15224374608078079005.1,"aMS",%progbits,1
.L.str:
	.asciz	"pwned!"
	.size	.L.str, 7

	.type	.L.str.1,%object                @ @.str.1
	.section	.rodata.str1.2641679613676021314.1,"aMS",%progbits,1
.L.str.1:
	.asciz	"pwned2!"
	.size	.L.str.1, 8

	.type	.L.str.2,%object                @ @.str.2
	.section	.rodata.str1.7966847511046382108.1,"aMS",%progbits,1
.L.str.2:
	.asciz	"pwned3!"
	.size	.L.str.2, 8

	.type	.L.str.3,%object                @ @.str.3
	.section	.rodata.str1.15405730187598805421.1,"aMS",%progbits,1
.L.str.3:
	.asciz	"pwned4!"
	.size	.L.str.3, 8

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
	.byte	85                              @ DW_AT_ranges
	.byte	6                               @ DW_FORM_data4
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
	.byte	63                              @ DW_AT_external
	.byte	12                              @ DW_FORM_flag
	.byte	0                               @ EOM(1)
	.byte	0                               @ EOM(2)
	.byte	8                               @ Abbreviation Code
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
	.byte	1                               @ Abbrev [1] 0xb:0x142 DW_TAG_compile_unit
	.long	.Linfo_string0                  @ DW_AT_producer
	.short	29                              @ DW_AT_language
	.long	.Linfo_string1                  @ DW_AT_name
	.long	.Lline_table_start0             @ DW_AT_stmt_list
	.long	.Linfo_string2                  @ DW_AT_comp_dir
	.long	0                               @ DW_AT_low_pc
	.long	.Ldebug_ranges0                 @ DW_AT_ranges
	.byte	2                               @ Abbrev [2] 0x26:0xd DW_TAG_variable
	.long	51                              @ DW_AT_type
	.byte	1                               @ DW_AT_decl_file
	.byte	4                               @ DW_AT_decl_line
	.byte	5                               @ DW_AT_location
	.byte	3
	.long	.L.str
	.byte	3                               @ Abbrev [3] 0x33:0xc DW_TAG_array_type
	.long	63                              @ DW_AT_type
	.byte	4                               @ Abbrev [4] 0x38:0x6 DW_TAG_subrange_type
	.long	70                              @ DW_AT_type
	.byte	7                               @ DW_AT_count
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
	.byte	8                               @ DW_AT_decl_line
	.byte	5                               @ DW_AT_location
	.byte	3
	.long	.L.str.1
	.byte	3                               @ Abbrev [3] 0x5a:0xc DW_TAG_array_type
	.long	63                              @ DW_AT_type
	.byte	4                               @ Abbrev [4] 0x5f:0x6 DW_TAG_subrange_type
	.long	70                              @ DW_AT_type
	.byte	8                               @ DW_AT_count
	.byte	0                               @ End Of Children Mark
	.byte	2                               @ Abbrev [2] 0x66:0xd DW_TAG_variable
	.long	90                              @ DW_AT_type
	.byte	1                               @ DW_AT_decl_file
	.byte	12                              @ DW_AT_decl_line
	.byte	5                               @ DW_AT_location
	.byte	3
	.long	.L.str.2
	.byte	2                               @ Abbrev [2] 0x73:0xd DW_TAG_variable
	.long	90                              @ DW_AT_type
	.byte	1                               @ DW_AT_decl_file
	.byte	16                              @ DW_AT_decl_line
	.byte	5                               @ DW_AT_location
	.byte	3
	.long	.L.str.3
	.byte	7                               @ Abbrev [7] 0x80:0x33 DW_TAG_subprogram
	.long	.Lfunc_begin0                   @ DW_AT_low_pc
	.long	.Lfunc_end0                     @ DW_AT_high_pc
	.byte	1                               @ DW_AT_frame_base
	.byte	93
	.byte	0                               @ DW_AT_TI_max_frame_size
	.long	.Linfo_string6                  @ DW_AT_name
	.byte	1                               @ DW_AT_decl_file
	.byte	3                               @ DW_AT_decl_line
	.byte	1                               @ DW_AT_prototyped
	.byte	1                               @ DW_AT_external
	.byte	8                               @ Abbrev [8] 0x94:0xa DW_TAG_TI_reserved_3
	.long	.Ltmp1                          @ DW_AT_low_pc
	.byte	1                               @ DW_AT_TI_reserved_9
	.long	.Linfo_string5                  @ DW_AT_name
	.byte	8                               @ Abbrev [8] 0x9e:0xa DW_TAG_TI_reserved_3
	.long	.Ltmp2                          @ DW_AT_low_pc
	.byte	1                               @ DW_AT_TI_reserved_9
	.long	.Linfo_string5                  @ DW_AT_name
	.byte	8                               @ Abbrev [8] 0xa8:0xa DW_TAG_TI_reserved_3
	.long	.Ltmp3                          @ DW_AT_low_pc
	.byte	1                               @ DW_AT_TI_reserved_9
	.long	.Linfo_string5                  @ DW_AT_name
	.byte	0                               @ End Of Children Mark
	.byte	7                               @ Abbrev [7] 0xb3:0x33 DW_TAG_subprogram
	.long	.Lfunc_begin1                   @ DW_AT_low_pc
	.long	.Lfunc_end1                     @ DW_AT_high_pc
	.byte	1                               @ DW_AT_frame_base
	.byte	93
	.byte	0                               @ DW_AT_TI_max_frame_size
	.long	.Linfo_string7                  @ DW_AT_name
	.byte	1                               @ DW_AT_decl_file
	.byte	7                               @ DW_AT_decl_line
	.byte	1                               @ DW_AT_prototyped
	.byte	1                               @ DW_AT_external
	.byte	8                               @ Abbrev [8] 0xc7:0xa DW_TAG_TI_reserved_3
	.long	.Ltmp6                          @ DW_AT_low_pc
	.byte	1                               @ DW_AT_TI_reserved_9
	.long	.Linfo_string5                  @ DW_AT_name
	.byte	8                               @ Abbrev [8] 0xd1:0xa DW_TAG_TI_reserved_3
	.long	.Ltmp7                          @ DW_AT_low_pc
	.byte	1                               @ DW_AT_TI_reserved_9
	.long	.Linfo_string5                  @ DW_AT_name
	.byte	8                               @ Abbrev [8] 0xdb:0xa DW_TAG_TI_reserved_3
	.long	.Ltmp8                          @ DW_AT_low_pc
	.byte	1                               @ DW_AT_TI_reserved_9
	.long	.Linfo_string5                  @ DW_AT_name
	.byte	0                               @ End Of Children Mark
	.byte	7                               @ Abbrev [7] 0xe6:0x33 DW_TAG_subprogram
	.long	.Lfunc_begin2                   @ DW_AT_low_pc
	.long	.Lfunc_end2                     @ DW_AT_high_pc
	.byte	1                               @ DW_AT_frame_base
	.byte	93
	.byte	0                               @ DW_AT_TI_max_frame_size
	.long	.Linfo_string8                  @ DW_AT_name
	.byte	1                               @ DW_AT_decl_file
	.byte	11                              @ DW_AT_decl_line
	.byte	1                               @ DW_AT_prototyped
	.byte	1                               @ DW_AT_external
	.byte	8                               @ Abbrev [8] 0xfa:0xa DW_TAG_TI_reserved_3
	.long	.Ltmp11                         @ DW_AT_low_pc
	.byte	1                               @ DW_AT_TI_reserved_9
	.long	.Linfo_string5                  @ DW_AT_name
	.byte	8                               @ Abbrev [8] 0x104:0xa DW_TAG_TI_reserved_3
	.long	.Ltmp12                         @ DW_AT_low_pc
	.byte	1                               @ DW_AT_TI_reserved_9
	.long	.Linfo_string5                  @ DW_AT_name
	.byte	8                               @ Abbrev [8] 0x10e:0xa DW_TAG_TI_reserved_3
	.long	.Ltmp13                         @ DW_AT_low_pc
	.byte	1                               @ DW_AT_TI_reserved_9
	.long	.Linfo_string5                  @ DW_AT_name
	.byte	0                               @ End Of Children Mark
	.byte	7                               @ Abbrev [7] 0x119:0x33 DW_TAG_subprogram
	.long	.Lfunc_begin3                   @ DW_AT_low_pc
	.long	.Lfunc_end3                     @ DW_AT_high_pc
	.byte	1                               @ DW_AT_frame_base
	.byte	93
	.byte	0                               @ DW_AT_TI_max_frame_size
	.long	.Linfo_string9                  @ DW_AT_name
	.byte	1                               @ DW_AT_decl_file
	.byte	15                              @ DW_AT_decl_line
	.byte	1                               @ DW_AT_prototyped
	.byte	1                               @ DW_AT_external
	.byte	8                               @ Abbrev [8] 0x12d:0xa DW_TAG_TI_reserved_3
	.long	.Ltmp16                         @ DW_AT_low_pc
	.byte	1                               @ DW_AT_TI_reserved_9
	.long	.Linfo_string5                  @ DW_AT_name
	.byte	8                               @ Abbrev [8] 0x137:0xa DW_TAG_TI_reserved_3
	.long	.Ltmp17                         @ DW_AT_low_pc
	.byte	1                               @ DW_AT_TI_reserved_9
	.long	.Linfo_string5                  @ DW_AT_name
	.byte	8                               @ Abbrev [8] 0x141:0xa DW_TAG_TI_reserved_3
	.long	.Ltmp18                         @ DW_AT_low_pc
	.byte	1                               @ DW_AT_TI_reserved_9
	.long	.Linfo_string5                  @ DW_AT_name
	.byte	0                               @ End Of Children Mark
	.byte	0                               @ End Of Children Mark
.Ldebug_info_end0:
	.section	.debug_ranges,"",%progbits
.Ldebug_ranges0:
	.long	.Lfunc_begin0
	.long	.Lfunc_end0
	.long	.Lfunc_begin1
	.long	.Lfunc_end1
	.long	.Lfunc_begin2
	.long	.Lfunc_end2
	.long	.Lfunc_begin3
	.long	.Lfunc_end3
	.long	0
	.long	0
	.section	.debug_str,"MS",%progbits,1
.Linfo_string0:
	.asciz	"TI clang version 18.1.8 (ssh://git@bitbucket.itg.ti.com/code/llvm-project.git 41ce286cff6db007d382d297353d8bf884b450b7)" @ string offset=0
.Linfo_string1:
	.asciz	"shellcode/pwned.c"             @ string offset=120
.Linfo_string2:
	.asciz	"/home/main/Documents/school/Fault-Injection-Finder/targets/timspm0l2228/source" @ string offset=138
.Linfo_string3:
	.asciz	"char"                          @ string offset=217
.Linfo_string4:
	.asciz	"__ARRAY_SIZE_TYPE__"           @ string offset=222
.Linfo_string5:
	.asciz	"_write"                        @ string offset=242
.Linfo_string6:
	.asciz	"pwned"                         @ string offset=249
.Linfo_string7:
	.asciz	"pwned2"                        @ string offset=255
.Linfo_string8:
	.asciz	"pwned3"                        @ string offset=262
.Linfo_string9:
	.asciz	"pwned4"                        @ string offset=269
	.ident	"TI clang version 18.1.8 (ssh://git@bitbucket.itg.ti.com/code/llvm-project.git 41ce286cff6db007d382d297353d8bf884b450b7)"
	.section	".note.GNU-stack","",%progbits
	.eabi_attribute	30, 1	@ Tag_ABI_optimization_goals
	.section	.debug_line,"",%progbits
.Lline_table_start0:
