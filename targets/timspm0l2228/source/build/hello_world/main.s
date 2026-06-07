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
	.file	1 "/home/main/Documents/school/Fault-Injection-Finder/targets/timspm0l2228/source" "hello_world/main.c"
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
	.fnstart
	.cfi_sections .debug_frame
	.cfi_startproc
@ %bb.0:
	.loc	1 7 5 prologue_end              @ hello_world/main.c:7:5
	bl	init_device
.Ltmp0:
	.loc	1 0 5 is_stmt 0                 @ hello_world/main.c:0:5
	ldr	r4, .LCPI0_0
.LBB0_1:                                @ =>This Inner Loop Header: Depth=1
	movs	r5, #0
	movs	r6, #13
.Ltmp1:
	.loc	1 9 9 is_stmt 1                 @ hello_world/main.c:9:9
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
	mov	r0, r5
	mov	r1, r4
	mov	r2, r6
	bl	_write
.Ltmp4:
	.loc	1 8 5                           @ hello_world/main.c:8:5
	b	.LBB0_1
.Ltmp5:
	.p2align	2
@ %bb.2:
	.loc	1 0 5 is_stmt 0                 @ hello_world/main.c:0:5
.LCPI0_0:
	.long	.L.str
.Lfunc_end0:
	.size	main, .Lfunc_end0-main
	.cfi_endproc
	.cantunwind
	.fnend
                                        @ -- End function
	.type	.L.str,%object                  @ @.str
	.section	.rodata.str1.15159059442110792349.1,"aMS",%progbits,1
.L.str:
	.asciz	"hello world!\n"
	.size	.L.str, 14

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
	.byte	8                               @ Abbreviation Code
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
	.byte	9                               @ Abbreviation Code
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
	.byte	1                               @ Abbrev [1] 0xb:0x9d DW_TAG_compile_unit
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
	.byte	9                               @ DW_AT_decl_line
	.byte	5                               @ DW_AT_location
	.byte	3
	.long	.L.str
	.byte	3                               @ Abbrev [3] 0x33:0xc DW_TAG_array_type
	.long	63                              @ DW_AT_type
	.byte	4                               @ Abbrev [4] 0x38:0x6 DW_TAG_subrange_type
	.long	70                              @ DW_AT_type
	.byte	14                              @ DW_AT_count
	.byte	0                               @ End Of Children Mark
	.byte	5                               @ Abbrev [5] 0x3f:0x7 DW_TAG_base_type
	.long	.Linfo_string3                  @ DW_AT_name
	.byte	8                               @ DW_AT_encoding
	.byte	1                               @ DW_AT_byte_size
	.byte	6                               @ Abbrev [6] 0x46:0x7 DW_TAG_base_type
	.long	.Linfo_string4                  @ DW_AT_name
	.byte	8                               @ DW_AT_byte_size
	.byte	7                               @ DW_AT_encoding
	.byte	7                               @ Abbrev [7] 0x4d:0xb DW_TAG_typedef
	.long	88                              @ DW_AT_type
	.long	.Linfo_string6                  @ DW_AT_name
	.byte	2                               @ DW_AT_decl_file
	.byte	66                              @ DW_AT_decl_line
	.byte	5                               @ Abbrev [5] 0x58:0x7 DW_TAG_base_type
	.long	.Linfo_string5                  @ DW_AT_name
	.byte	7                               @ DW_AT_encoding
	.byte	4                               @ DW_AT_byte_size
	.byte	8                               @ Abbrev [8] 0x5f:0x41 DW_TAG_subprogram
	.long	.Lfunc_begin0                   @ DW_AT_low_pc
	.long	.Lfunc_end0                     @ DW_AT_high_pc
	.byte	1                               @ DW_AT_frame_base
	.byte	93
	.byte	0                               @ DW_AT_TI_max_frame_size
	.long	.Linfo_string9                  @ DW_AT_name
	.byte	1                               @ DW_AT_decl_file
	.byte	6                               @ DW_AT_decl_line
	.byte	1                               @ DW_AT_prototyped
	.long	160                             @ DW_AT_type
	.byte	1                               @ DW_AT_external
	.byte	9                               @ Abbrev [9] 0x77:0xa DW_TAG_TI_reserved_3
	.long	.Ltmp0                          @ DW_AT_low_pc
	.byte	1                               @ DW_AT_TI_reserved_9
	.long	.Linfo_string7                  @ DW_AT_name
	.byte	9                               @ Abbrev [9] 0x81:0xa DW_TAG_TI_reserved_3
	.long	.Ltmp2                          @ DW_AT_low_pc
	.byte	1                               @ DW_AT_TI_reserved_9
	.long	.Linfo_string8                  @ DW_AT_name
	.byte	9                               @ Abbrev [9] 0x8b:0xa DW_TAG_TI_reserved_3
	.long	.Ltmp3                          @ DW_AT_low_pc
	.byte	1                               @ DW_AT_TI_reserved_9
	.long	.Linfo_string8                  @ DW_AT_name
	.byte	9                               @ Abbrev [9] 0x95:0xa DW_TAG_TI_reserved_3
	.long	.Ltmp4                          @ DW_AT_low_pc
	.byte	1                               @ DW_AT_TI_reserved_9
	.long	.Linfo_string8                  @ DW_AT_name
	.byte	0                               @ End Of Children Mark
	.byte	5                               @ Abbrev [5] 0xa0:0x7 DW_TAG_base_type
	.long	.Linfo_string10                 @ DW_AT_name
	.byte	5                               @ DW_AT_encoding
	.byte	4                               @ DW_AT_byte_size
	.byte	0                               @ End Of Children Mark
.Ldebug_info_end0:
	.section	.debug_str,"MS",%progbits,1
.Linfo_string0:
	.asciz	"TI clang version 18.1.8 (ssh://git@bitbucket.itg.ti.com/code/llvm-project.git 41ce286cff6db007d382d297353d8bf884b450b7)" @ string offset=0
.Linfo_string1:
	.asciz	"hello_world/main.c"            @ string offset=120
.Linfo_string2:
	.asciz	"/home/main/Documents/school/Fault-Injection-Finder/targets/timspm0l2228/source" @ string offset=139
.Linfo_string3:
	.asciz	"char"                          @ string offset=218
.Linfo_string4:
	.asciz	"__ARRAY_SIZE_TYPE__"           @ string offset=223
.Linfo_string5:
	.asciz	"unsigned int"                  @ string offset=243
.Linfo_string6:
	.asciz	"size_t"                        @ string offset=256
.Linfo_string7:
	.asciz	"init_device"                   @ string offset=263
.Linfo_string8:
	.asciz	"_write"                        @ string offset=275
.Linfo_string9:
	.asciz	"main"                          @ string offset=282
.Linfo_string10:
	.asciz	"int"                           @ string offset=287
	.ident	"TI clang version 18.1.8 (ssh://git@bitbucket.itg.ti.com/code/llvm-project.git 41ce286cff6db007d382d297353d8bf884b450b7)"
	.section	".note.GNU-stack","",%progbits
	.addrsig
	.eabi_attribute	30, 1	@ Tag_ABI_optimization_goals
	.TI_attribute	16, 0	@ Tag_Instrumentation
	.section	.debug_line,"",%progbits
.Lline_table_start0:
