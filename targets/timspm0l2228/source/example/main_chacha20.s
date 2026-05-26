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
	.save	{r4, r5, r6, r7, lr}
	push	{r4, r5, r6, r7, lr}
	.cfi_def_cfa_offset 20
	.cfi_offset lr, -4
	.cfi_offset r7, -8
	.cfi_offset r6, -12
	.cfi_offset r5, -16
	.cfi_offset r4, -20
	.pad	#452
	sub	sp, #452
	.cfi_def_cfa_offset 472
	movs	r4, #0
.Ltmp0:
	str	r4, [sp, #448]
.Ltmp1:
	ldr	r0, [sp, #448]
.Ltmp2:
	cmp	r0, #0
	beq	.LBB0_2
@ %bb.1:
.Ltmp3:
	bl	pwned
.Ltmp4:
.LBB0_2:
	ldr	r0, .LCPI0_0
	add	r7, sp, #416
	mov	r1, r7
	ldm	r0!, {r2, r3, r5, r6}
	stm	r1!, {r2, r3, r5, r6}
	ldm	r0!, {r2, r3, r5, r6}
	stm	r1!, {r2, r3, r5, r6}
	str	r4, [sp, #412]
	str	r4, [sp, #408]
	str	r4, [sp, #404]
	add	r6, sp, #212
	movs	r2, #192
	str	r2, [sp, #20]                   @ 4-byte Spill
	mov	r0, r4
	mov	r1, r6
	bl	_read
.Ltmp5:
	@DEBUG_VALUE: main:n <- undef
	movs	r0, #1
	str	r0, [sp, #16]                   @ 4-byte Spill
	str	r0, [sp]
	str	r4, [sp, #4]
	add	r5, sp, #24
	add	r2, sp, #404
	str	r2, [sp, #12]                   @ 4-byte Spill
	mov	r0, r5
	mov	r1, r7
	bl	chacha20_init_context
.Ltmp6:
	mov	r0, r5
	mov	r1, r6
	ldr	r2, [sp, #20]                   @ 4-byte Reload
	bl	chacha20_xor
.Ltmp7:
	ldr	r0, [sp, #16]                   @ 4-byte Reload
	str	r0, [sp]
	str	r4, [sp, #4]
	mov	r0, r5
	mov	r1, r7
	ldr	r2, [sp, #12]                   @ 4-byte Reload
	bl	chacha20_init_context
.Ltmp8:
	mov	r0, r5
	mov	r1, r6
	ldr	r2, [sp, #20]                   @ 4-byte Reload
	bl	chacha20_xor
.Ltmp9:
	mov	r0, r4
	add	sp, #452
	pop	{r4, r5, r6, r7, pc}
.Ltmp10:
	.p2align	2
@ %bb.3:
.LCPI0_0:
	.long	.L__const.main.key
.Lfunc_end0:
	.size	main, .Lfunc_end0-main
	.cfi_endproc
	.cantunwind
	.fnend
                                        @ -- End function
	.type	.L__const.main.key,%object      @ @__const.main.key
	.section	.rodata.cst32,"aM",%progbits,32
	.p2align	2, 0x0
.L__const.main.key:
	.ascii	"\r\310\266\230\372sD\264b>\313\321C\274o\263\013\232\301\2207W0\367\025\251\377\375\001\325P\271"
	.size	.L__const.main.key, 32

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
	.byte	46                              @ DW_TAG_subprogram
	.byte	1                               @ DW_CHILDREN_yes
	.byte	17                              @ DW_AT_low_pc
	.byte	1                               @ DW_FORM_addr
	.byte	18                              @ DW_AT_high_pc
	.byte	1                               @ DW_FORM_addr
	.byte	64                              @ DW_AT_frame_base
	.byte	10                              @ DW_FORM_block1
	.ascii	"\224@"                         @ DW_AT_TI_max_frame_size
	.byte	5                               @ DW_FORM_data2
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
	.byte	3                               @ Abbreviation Code
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
	.byte	4                               @ Abbreviation Code
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
	.byte	5                               @ Abbreviation Code
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
	.byte	6                               @ Abbreviation Code
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
	.byte	7                               @ Abbreviation Code
	.byte	53                              @ DW_TAG_volatile_type
	.byte	0                               @ DW_CHILDREN_no
	.byte	73                              @ DW_AT_type
	.byte	19                              @ DW_FORM_ref4
	.byte	0                               @ EOM(1)
	.byte	0                               @ EOM(2)
	.byte	8                               @ Abbreviation Code
	.byte	1                               @ DW_TAG_array_type
	.byte	1                               @ DW_CHILDREN_yes
	.byte	73                              @ DW_AT_type
	.byte	19                              @ DW_FORM_ref4
	.byte	0                               @ EOM(1)
	.byte	0                               @ EOM(2)
	.byte	9                               @ Abbreviation Code
	.byte	33                              @ DW_TAG_subrange_type
	.byte	0                               @ DW_CHILDREN_no
	.byte	73                              @ DW_AT_type
	.byte	19                              @ DW_FORM_ref4
	.byte	55                              @ DW_AT_count
	.byte	11                              @ DW_FORM_data1
	.byte	0                               @ EOM(1)
	.byte	0                               @ EOM(2)
	.byte	10                              @ Abbreviation Code
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
	.byte	11                              @ Abbreviation Code
	.byte	19                              @ DW_TAG_structure_type
	.byte	1                               @ DW_CHILDREN_yes
	.byte	3                               @ DW_AT_name
	.byte	14                              @ DW_FORM_strp
	.byte	11                              @ DW_AT_byte_size
	.byte	11                              @ DW_FORM_data1
	.byte	58                              @ DW_AT_decl_file
	.byte	11                              @ DW_FORM_data1
	.byte	59                              @ DW_AT_decl_line
	.byte	11                              @ DW_FORM_data1
	.byte	0                               @ EOM(1)
	.byte	0                               @ EOM(2)
	.byte	12                              @ Abbreviation Code
	.byte	13                              @ DW_TAG_member
	.byte	0                               @ DW_CHILDREN_no
	.byte	3                               @ DW_AT_name
	.byte	14                              @ DW_FORM_strp
	.byte	73                              @ DW_AT_type
	.byte	19                              @ DW_FORM_ref4
	.byte	58                              @ DW_AT_decl_file
	.byte	11                              @ DW_FORM_data1
	.byte	59                              @ DW_AT_decl_line
	.byte	11                              @ DW_FORM_data1
	.byte	56                              @ DW_AT_data_member_location
	.byte	15                              @ DW_FORM_udata
	.byte	0                               @ EOM(1)
	.byte	0                               @ EOM(2)
	.byte	13                              @ Abbreviation Code
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
	.byte	1                               @ Abbrev [1] 0xb:0x1d5 DW_TAG_compile_unit
	.long	.Linfo_string0                  @ DW_AT_producer
	.short	29                              @ DW_AT_language
	.long	.Linfo_string1                  @ DW_AT_name
	.long	.Lline_table_start0             @ DW_AT_stmt_list
	.long	.Linfo_string2                  @ DW_AT_comp_dir
	.long	.Lfunc_begin0                   @ DW_AT_low_pc
	.long	.Lfunc_end0                     @ DW_AT_high_pc
	.byte	2                               @ Abbrev [2] 0x26:0xab DW_TAG_subprogram
	.long	.Lfunc_begin0                   @ DW_AT_low_pc
	.long	.Lfunc_end0                     @ DW_AT_high_pc
	.byte	1                               @ DW_AT_frame_base
	.byte	93
	.short	472                             @ DW_AT_TI_max_frame_size
	.long	.Linfo_string7                  @ DW_AT_name
	.byte	1                               @ DW_AT_decl_file
	.byte	7                               @ DW_AT_decl_line
	.byte	1                               @ DW_AT_prototyped
	.long	209                             @ DW_AT_type
	.byte	1                               @ DW_AT_external
	.byte	3                               @ Abbrev [3] 0x3f:0xf DW_TAG_variable
	.byte	3                               @ DW_AT_location
	.byte	145
	.ascii	"\300\003"
	.long	.Linfo_string9                  @ DW_AT_name
	.byte	1                               @ DW_AT_decl_file
	.byte	8                               @ DW_AT_decl_line
	.long	216                             @ DW_AT_type
	.byte	3                               @ Abbrev [3] 0x4e:0xf DW_TAG_variable
	.byte	3                               @ DW_AT_location
	.byte	145
	.ascii	"\240\003"
	.long	.Linfo_string10                 @ DW_AT_name
	.byte	1                               @ DW_AT_decl_file
	.byte	11                              @ DW_AT_decl_line
	.long	221                             @ DW_AT_type
	.byte	3                               @ Abbrev [3] 0x5d:0xf DW_TAG_variable
	.byte	3                               @ DW_AT_location
	.byte	145
	.ascii	"\224\003"
	.long	.Linfo_string13                 @ DW_AT_name
	.byte	1                               @ DW_AT_decl_file
	.byte	12                              @ DW_AT_decl_line
	.long	247                             @ DW_AT_type
	.byte	3                               @ Abbrev [3] 0x6c:0xf DW_TAG_variable
	.byte	3                               @ DW_AT_location
	.byte	145
	.ascii	"\324\001"
	.long	.Linfo_string14                 @ DW_AT_name
	.byte	1                               @ DW_AT_decl_file
	.byte	13                              @ DW_AT_decl_line
	.long	259                             @ DW_AT_type
	.byte	3                               @ Abbrev [3] 0x7b:0xe DW_TAG_variable
	.byte	2                               @ DW_AT_location
	.byte	145
	.byte	24
	.long	.Linfo_string15                 @ DW_AT_name
	.byte	1                               @ DW_AT_decl_file
	.byte	19                              @ DW_AT_decl_line
	.long	271                             @ DW_AT_type
	.byte	4                               @ Abbrev [4] 0x89:0xb DW_TAG_variable
	.long	.Linfo_string30                 @ DW_AT_name
	.byte	1                               @ DW_AT_decl_file
	.byte	16                              @ DW_AT_decl_line
	.long	209                             @ DW_AT_type
	.byte	5                               @ Abbrev [5] 0x94:0xa DW_TAG_TI_reserved_3
	.long	.Ltmp4                          @ DW_AT_low_pc
	.byte	1                               @ DW_AT_TI_reserved_9
	.long	.Linfo_string3                  @ DW_AT_name
	.byte	5                               @ Abbrev [5] 0x9e:0xa DW_TAG_TI_reserved_3
	.long	.Ltmp5                          @ DW_AT_low_pc
	.byte	1                               @ DW_AT_TI_reserved_9
	.long	.Linfo_string4                  @ DW_AT_name
	.byte	5                               @ Abbrev [5] 0xa8:0xa DW_TAG_TI_reserved_3
	.long	.Ltmp6                          @ DW_AT_low_pc
	.byte	1                               @ DW_AT_TI_reserved_9
	.long	.Linfo_string5                  @ DW_AT_name
	.byte	5                               @ Abbrev [5] 0xb2:0xa DW_TAG_TI_reserved_3
	.long	.Ltmp7                          @ DW_AT_low_pc
	.byte	1                               @ DW_AT_TI_reserved_9
	.long	.Linfo_string6                  @ DW_AT_name
	.byte	5                               @ Abbrev [5] 0xbc:0xa DW_TAG_TI_reserved_3
	.long	.Ltmp8                          @ DW_AT_low_pc
	.byte	1                               @ DW_AT_TI_reserved_9
	.long	.Linfo_string5                  @ DW_AT_name
	.byte	5                               @ Abbrev [5] 0xc6:0xa DW_TAG_TI_reserved_3
	.long	.Ltmp9                          @ DW_AT_low_pc
	.byte	1                               @ DW_AT_TI_reserved_9
	.long	.Linfo_string6                  @ DW_AT_name
	.byte	0                               @ End Of Children Mark
	.byte	6                               @ Abbrev [6] 0xd1:0x7 DW_TAG_base_type
	.long	.Linfo_string8                  @ DW_AT_name
	.byte	5                               @ DW_AT_encoding
	.byte	4                               @ DW_AT_byte_size
	.byte	7                               @ Abbrev [7] 0xd8:0x5 DW_TAG_volatile_type
	.long	209                             @ DW_AT_type
	.byte	8                               @ Abbrev [8] 0xdd:0xc DW_TAG_array_type
	.long	233                             @ DW_AT_type
	.byte	9                               @ Abbrev [9] 0xe2:0x6 DW_TAG_subrange_type
	.long	240                             @ DW_AT_type
	.byte	32                              @ DW_AT_count
	.byte	0                               @ End Of Children Mark
	.byte	6                               @ Abbrev [6] 0xe9:0x7 DW_TAG_base_type
	.long	.Linfo_string11                 @ DW_AT_name
	.byte	8                               @ DW_AT_encoding
	.byte	1                               @ DW_AT_byte_size
	.byte	10                              @ Abbrev [10] 0xf0:0x7 DW_TAG_base_type
	.long	.Linfo_string12                 @ DW_AT_name
	.byte	8                               @ DW_AT_byte_size
	.byte	7                               @ DW_AT_encoding
	.byte	8                               @ Abbrev [8] 0xf7:0xc DW_TAG_array_type
	.long	233                             @ DW_AT_type
	.byte	9                               @ Abbrev [9] 0xfc:0x6 DW_TAG_subrange_type
	.long	240                             @ DW_AT_type
	.byte	12                              @ DW_AT_count
	.byte	0                               @ End Of Children Mark
	.byte	8                               @ Abbrev [8] 0x103:0xc DW_TAG_array_type
	.long	233                             @ DW_AT_type
	.byte	9                               @ Abbrev [9] 0x108:0x6 DW_TAG_subrange_type
	.long	240                             @ DW_AT_type
	.byte	192                             @ DW_AT_count
	.byte	0                               @ End Of Children Mark
	.byte	11                              @ Abbrev [11] 0x10f:0x51 DW_TAG_structure_type
	.long	.Linfo_string29                 @ DW_AT_name
	.byte	184                             @ DW_AT_byte_size
	.byte	4                               @ DW_AT_decl_file
	.byte	12                              @ DW_AT_decl_line
	.byte	12                              @ Abbrev [12] 0x117:0xc DW_TAG_member
	.long	.Linfo_string16                 @ DW_AT_name
	.long	352                             @ DW_AT_type
	.byte	4                               @ DW_AT_decl_file
	.byte	14                              @ DW_AT_decl_line
	.byte	0                               @ DW_AT_data_member_location
	.byte	12                              @ Abbrev [12] 0x123:0xc DW_TAG_member
	.long	.Linfo_string20                 @ DW_AT_name
	.long	393                             @ DW_AT_type
	.byte	4                               @ DW_AT_decl_file
	.byte	15                              @ DW_AT_decl_line
	.byte	64                              @ DW_AT_data_member_location
	.byte	12                              @ Abbrev [12] 0x12f:0xc DW_TAG_member
	.long	.Linfo_string10                 @ DW_AT_name
	.long	404                             @ DW_AT_type
	.byte	4                               @ DW_AT_decl_file
	.byte	17                              @ DW_AT_decl_line
	.byte	68                              @ DW_AT_data_member_location
	.byte	12                              @ Abbrev [12] 0x13b:0xc DW_TAG_member
	.long	.Linfo_string13                 @ DW_AT_name
	.long	438                             @ DW_AT_type
	.byte	4                               @ DW_AT_decl_file
	.byte	18                              @ DW_AT_decl_line
	.byte	100                             @ DW_AT_data_member_location
	.byte	12                              @ Abbrev [12] 0x147:0xc DW_TAG_member
	.long	.Linfo_string24                 @ DW_AT_name
	.long	450                             @ DW_AT_type
	.byte	4                               @ DW_AT_decl_file
	.byte	19                              @ DW_AT_decl_line
	.byte	112                             @ DW_AT_data_member_location
	.byte	12                              @ Abbrev [12] 0x153:0xc DW_TAG_member
	.long	.Linfo_string28                 @ DW_AT_name
	.long	352                             @ DW_AT_type
	.byte	4                               @ DW_AT_decl_file
	.byte	21                              @ DW_AT_decl_line
	.byte	120                             @ DW_AT_data_member_location
	.byte	0                               @ End Of Children Mark
	.byte	8                               @ Abbrev [8] 0x160:0xc DW_TAG_array_type
	.long	364                             @ DW_AT_type
	.byte	9                               @ Abbrev [9] 0x165:0x6 DW_TAG_subrange_type
	.long	240                             @ DW_AT_type
	.byte	16                              @ DW_AT_count
	.byte	0                               @ End Of Children Mark
	.byte	13                              @ Abbrev [13] 0x16c:0xb DW_TAG_typedef
	.long	375                             @ DW_AT_type
	.long	.Linfo_string19                 @ DW_AT_name
	.byte	3                               @ DW_AT_decl_file
	.byte	70                              @ DW_AT_decl_line
	.byte	13                              @ Abbrev [13] 0x177:0xb DW_TAG_typedef
	.long	386                             @ DW_AT_type
	.long	.Linfo_string18                 @ DW_AT_name
	.byte	2                               @ DW_AT_decl_file
	.byte	79                              @ DW_AT_decl_line
	.byte	6                               @ Abbrev [6] 0x182:0x7 DW_TAG_base_type
	.long	.Linfo_string17                 @ DW_AT_name
	.byte	7                               @ DW_AT_encoding
	.byte	4                               @ DW_AT_byte_size
	.byte	13                              @ Abbrev [13] 0x189:0xb DW_TAG_typedef
	.long	386                             @ DW_AT_type
	.long	.Linfo_string21                 @ DW_AT_name
	.byte	5                               @ DW_AT_decl_file
	.byte	66                              @ DW_AT_decl_line
	.byte	8                               @ Abbrev [8] 0x194:0xc DW_TAG_array_type
	.long	416                             @ DW_AT_type
	.byte	9                               @ Abbrev [9] 0x199:0x6 DW_TAG_subrange_type
	.long	240                             @ DW_AT_type
	.byte	32                              @ DW_AT_count
	.byte	0                               @ End Of Children Mark
	.byte	13                              @ Abbrev [13] 0x1a0:0xb DW_TAG_typedef
	.long	427                             @ DW_AT_type
	.long	.Linfo_string23                 @ DW_AT_name
	.byte	3                               @ DW_AT_decl_file
	.byte	59                              @ DW_AT_decl_line
	.byte	13                              @ Abbrev [13] 0x1ab:0xb DW_TAG_typedef
	.long	233                             @ DW_AT_type
	.long	.Linfo_string22                 @ DW_AT_name
	.byte	2                               @ DW_AT_decl_file
	.byte	75                              @ DW_AT_decl_line
	.byte	8                               @ Abbrev [8] 0x1b6:0xc DW_TAG_array_type
	.long	416                             @ DW_AT_type
	.byte	9                               @ Abbrev [9] 0x1bb:0x6 DW_TAG_subrange_type
	.long	240                             @ DW_AT_type
	.byte	12                              @ DW_AT_count
	.byte	0                               @ End Of Children Mark
	.byte	13                              @ Abbrev [13] 0x1c2:0xb DW_TAG_typedef
	.long	461                             @ DW_AT_type
	.long	.Linfo_string27                 @ DW_AT_name
	.byte	3                               @ DW_AT_decl_file
	.byte	75                              @ DW_AT_decl_line
	.byte	13                              @ Abbrev [13] 0x1cd:0xb DW_TAG_typedef
	.long	472                             @ DW_AT_type
	.long	.Linfo_string26                 @ DW_AT_name
	.byte	2                               @ DW_AT_decl_file
	.byte	89                              @ DW_AT_decl_line
	.byte	6                               @ Abbrev [6] 0x1d8:0x7 DW_TAG_base_type
	.long	.Linfo_string25                 @ DW_AT_name
	.byte	7                               @ DW_AT_encoding
	.byte	8                               @ DW_AT_byte_size
	.byte	0                               @ End Of Children Mark
.Ldebug_info_end0:
	.section	.debug_str,"MS",%progbits,1
.Linfo_string0:
	.asciz	"TI clang version 18.1.8 (ssh://git@bitbucket.itg.ti.com/code/llvm-project.git 41ce286cff6db007d382d297353d8bf884b450b7)" @ string offset=0
.Linfo_string1:
	.asciz	"chacha20/main.c"               @ string offset=120
.Linfo_string2:
	.asciz	"/home/main/Documents/school/Fault-Injection-Finder/targets/timspm0l2228/source" @ string offset=136
.Linfo_string3:
	.asciz	"pwned"                         @ string offset=215
.Linfo_string4:
	.asciz	"_read"                         @ string offset=221
.Linfo_string5:
	.asciz	"chacha20_init_context"         @ string offset=227
.Linfo_string6:
	.asciz	"chacha20_xor"                  @ string offset=249
.Linfo_string7:
	.asciz	"main"                          @ string offset=262
.Linfo_string8:
	.asciz	"int"                           @ string offset=267
.Linfo_string9:
	.asciz	"dummy"                         @ string offset=271
.Linfo_string10:
	.asciz	"key"                           @ string offset=277
.Linfo_string11:
	.asciz	"unsigned char"                 @ string offset=281
.Linfo_string12:
	.asciz	"__ARRAY_SIZE_TYPE__"           @ string offset=295
.Linfo_string13:
	.asciz	"nonce"                         @ string offset=315
.Linfo_string14:
	.asciz	"data"                          @ string offset=321
.Linfo_string15:
	.asciz	"ctx"                           @ string offset=326
.Linfo_string16:
	.asciz	"keystream32"                   @ string offset=330
.Linfo_string17:
	.asciz	"unsigned int"                  @ string offset=342
.Linfo_string18:
	.asciz	"__uint32_t"                    @ string offset=355
.Linfo_string19:
	.asciz	"uint32_t"                      @ string offset=366
.Linfo_string20:
	.asciz	"position"                      @ string offset=375
.Linfo_string21:
	.asciz	"size_t"                        @ string offset=384
.Linfo_string22:
	.asciz	"__uint8_t"                     @ string offset=391
.Linfo_string23:
	.asciz	"uint8_t"                       @ string offset=401
.Linfo_string24:
	.asciz	"counter"                       @ string offset=409
.Linfo_string25:
	.asciz	"unsigned long long"            @ string offset=417
.Linfo_string26:
	.asciz	"__uint64_t"                    @ string offset=436
.Linfo_string27:
	.asciz	"uint64_t"                      @ string offset=447
.Linfo_string28:
	.asciz	"state"                         @ string offset=456
.Linfo_string29:
	.asciz	"chacha20_context"              @ string offset=462
.Linfo_string30:
	.asciz	"n"                             @ string offset=479
	.ident	"TI clang version 18.1.8 (ssh://git@bitbucket.itg.ti.com/code/llvm-project.git 41ce286cff6db007d382d297353d8bf884b450b7)"
	.section	".note.GNU-stack","",%progbits
	.eabi_attribute	30, 1	@ Tag_ABI_optimization_goals
	.section	.debug_line,"",%progbits
.Lline_table_start0:
