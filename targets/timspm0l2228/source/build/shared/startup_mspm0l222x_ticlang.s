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
	.file	"startup_mspm0l222x_ticlang.c"
	.file	1 "/home/main/Documents/school/Fault-Injection-Finder/targets/timspm0l2228/source" "startup_mspm0l222x_ticlang.c"
	.section	.text.Default_Handler,"ax",%progbits
	.hidden	Default_Handler                 @ -- Begin function Default_Handler
	.weak	Default_Handler
	.p2align	1
	.type	Default_Handler,%function
	.code	16                              @ @Default_Handler
	.thumb_func
Default_Handler:
.Lfunc_begin0:
	.fnstart
	.cfi_sections .debug_frame
	.cfi_startproc
@ %bb.0:
.LBB0_1:                                @ =>This Inner Loop Header: Depth=1
	.loc	1 171 5 prologue_end            @ startup_mspm0l222x_ticlang.c:171:5
	b	.LBB0_1
.Ltmp0:
.Lfunc_end0:
	.size	Default_Handler, .Lfunc_end0-Default_Handler
	.cfi_endproc
	.cantunwind
	.fnend
                                        @ -- End function
	.section	.text.Reset_Handler,"ax",%progbits
	.hidden	Reset_Handler                   @ -- Begin function Reset_Handler
	.weak	Reset_Handler
	.p2align	1
	.type	Reset_Handler,%function
	.code	16                              @ @Reset_Handler
	.thumb_func
Reset_Handler:
.Lfunc_begin1:
	.fnstart
	.cfi_startproc
@ %bb.0:
	.loc	1 158 5 prologue_end            @ startup_mspm0l222x_ticlang.c:158:5
	@APP
	.globl	_c_int00
	b	_c_int00
	@NO_APP
	.loc	1 161 1                         @ startup_mspm0l222x_ticlang.c:161:1
	bx	lr
.Ltmp1:
.Lfunc_end1:
	.size	Reset_Handler, .Lfunc_end1-Reset_Handler
	.cfi_endproc
	.cantunwind
	.fnend
                                        @ -- End function
	.hidden	interruptVectors                @ @interruptVectors
	.type	interruptVectors,%object
	.section	.intvecs,"aR",%progbits,unique,1
	.globl	interruptVectors
	.p2align	2, 0x0
interruptVectors:
	.long	__STACK_END
	.long	Reset_Handler
	.long	NMI_Handler
	.long	HardFault_Handler
	.long	0
	.long	0
	.long	0
	.long	0
	.long	0
	.long	0
	.long	0
	.long	SVC_Handler
	.long	0
	.long	0
	.long	PendSV_Handler
	.long	SysTick_Handler
	.long	GROUP0_IRQHandler
	.long	GROUP1_IRQHandler
	.long	TIMG12_IRQHandler
	.long	UART4_IRQHandler
	.long	ADC0_IRQHandler
	.long	0
	.long	0
	.long	0
	.long	0
	.long	SPI0_IRQHandler
	.long	SPI1_IRQHandler
	.long	0
	.long	0
	.long	UART2_IRQHandler
	.long	UART3_IRQHandler
	.long	UART0_IRQHandler
	.long	UART1_IRQHandler
	.long	0
	.long	TIMA0_IRQHandler
	.long	0
	.long	TIMG8_IRQHandler
	.long	TIMG0_IRQHandler
	.long	TIMG4_IRQHandler
	.long	TIMG5_IRQHandler
	.long	I2C0_IRQHandler
	.long	I2C1_IRQHandler
	.long	I2C2_IRQHandler
	.long	0
	.long	AESADV_IRQHandler
	.long	LCD_IRQHandler
	.long	LFSS_IRQHandler
	.long	DMA_IRQHandler
	.size	interruptVectors, 192

	.no_dead_strip	interruptVectors
	.weak	NMI_Handler
	.type	NMI_Handler,%function
	.hidden	NMI_Handler
.set NMI_Handler, Default_Handler
	.weak	HardFault_Handler
	.type	HardFault_Handler,%function
	.hidden	HardFault_Handler
.set HardFault_Handler, Default_Handler
	.weak	SVC_Handler
	.type	SVC_Handler,%function
	.hidden	SVC_Handler
.set SVC_Handler, Default_Handler
	.weak	PendSV_Handler
	.type	PendSV_Handler,%function
	.hidden	PendSV_Handler
.set PendSV_Handler, Default_Handler
	.weak	SysTick_Handler
	.type	SysTick_Handler,%function
	.hidden	SysTick_Handler
.set SysTick_Handler, Default_Handler
	.weak	GROUP0_IRQHandler
	.type	GROUP0_IRQHandler,%function
	.hidden	GROUP0_IRQHandler
.set GROUP0_IRQHandler, Default_Handler
	.weak	GROUP1_IRQHandler
	.type	GROUP1_IRQHandler,%function
	.hidden	GROUP1_IRQHandler
.set GROUP1_IRQHandler, Default_Handler
	.weak	TIMG12_IRQHandler
	.type	TIMG12_IRQHandler,%function
	.hidden	TIMG12_IRQHandler
.set TIMG12_IRQHandler, Default_Handler
	.weak	UART4_IRQHandler
	.type	UART4_IRQHandler,%function
	.hidden	UART4_IRQHandler
.set UART4_IRQHandler, Default_Handler
	.weak	ADC0_IRQHandler
	.type	ADC0_IRQHandler,%function
	.hidden	ADC0_IRQHandler
.set ADC0_IRQHandler, Default_Handler
	.weak	SPI0_IRQHandler
	.type	SPI0_IRQHandler,%function
	.hidden	SPI0_IRQHandler
.set SPI0_IRQHandler, Default_Handler
	.weak	SPI1_IRQHandler
	.type	SPI1_IRQHandler,%function
	.hidden	SPI1_IRQHandler
.set SPI1_IRQHandler, Default_Handler
	.weak	UART2_IRQHandler
	.type	UART2_IRQHandler,%function
	.hidden	UART2_IRQHandler
.set UART2_IRQHandler, Default_Handler
	.weak	UART3_IRQHandler
	.type	UART3_IRQHandler,%function
	.hidden	UART3_IRQHandler
.set UART3_IRQHandler, Default_Handler
	.weak	UART0_IRQHandler
	.type	UART0_IRQHandler,%function
	.hidden	UART0_IRQHandler
.set UART0_IRQHandler, Default_Handler
	.weak	UART1_IRQHandler
	.type	UART1_IRQHandler,%function
	.hidden	UART1_IRQHandler
.set UART1_IRQHandler, Default_Handler
	.weak	TIMA0_IRQHandler
	.type	TIMA0_IRQHandler,%function
	.hidden	TIMA0_IRQHandler
.set TIMA0_IRQHandler, Default_Handler
	.weak	TIMG8_IRQHandler
	.type	TIMG8_IRQHandler,%function
	.hidden	TIMG8_IRQHandler
.set TIMG8_IRQHandler, Default_Handler
	.weak	TIMG0_IRQHandler
	.type	TIMG0_IRQHandler,%function
	.hidden	TIMG0_IRQHandler
.set TIMG0_IRQHandler, Default_Handler
	.weak	TIMG4_IRQHandler
	.type	TIMG4_IRQHandler,%function
	.hidden	TIMG4_IRQHandler
.set TIMG4_IRQHandler, Default_Handler
	.weak	TIMG5_IRQHandler
	.type	TIMG5_IRQHandler,%function
	.hidden	TIMG5_IRQHandler
.set TIMG5_IRQHandler, Default_Handler
	.weak	I2C0_IRQHandler
	.type	I2C0_IRQHandler,%function
	.hidden	I2C0_IRQHandler
.set I2C0_IRQHandler, Default_Handler
	.weak	I2C1_IRQHandler
	.type	I2C1_IRQHandler,%function
	.hidden	I2C1_IRQHandler
.set I2C1_IRQHandler, Default_Handler
	.weak	I2C2_IRQHandler
	.type	I2C2_IRQHandler,%function
	.hidden	I2C2_IRQHandler
.set I2C2_IRQHandler, Default_Handler
	.weak	AESADV_IRQHandler
	.type	AESADV_IRQHandler,%function
	.hidden	AESADV_IRQHandler
.set AESADV_IRQHandler, Default_Handler
	.weak	LCD_IRQHandler
	.type	LCD_IRQHandler,%function
	.hidden	LCD_IRQHandler
.set LCD_IRQHandler, Default_Handler
	.weak	LFSS_IRQHandler
	.type	LFSS_IRQHandler,%function
	.hidden	LFSS_IRQHandler
.set LFSS_IRQHandler, Default_Handler
	.weak	DMA_IRQHandler
	.type	DMA_IRQHandler,%function
	.hidden	DMA_IRQHandler
.set DMA_IRQHandler, Default_Handler
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
	.byte	3                               @ DW_AT_name
	.byte	14                              @ DW_FORM_strp
	.byte	73                              @ DW_AT_type
	.byte	19                              @ DW_FORM_ref4
	.byte	63                              @ DW_AT_external
	.byte	12                              @ DW_FORM_flag
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
	.byte	38                              @ DW_TAG_const_type
	.byte	0                               @ DW_CHILDREN_no
	.byte	73                              @ DW_AT_type
	.byte	19                              @ DW_FORM_ref4
	.byte	0                               @ EOM(1)
	.byte	0                               @ EOM(2)
	.byte	6                               @ Abbreviation Code
	.byte	15                              @ DW_TAG_pointer_type
	.byte	0                               @ DW_CHILDREN_no
	.byte	73                              @ DW_AT_type
	.byte	19                              @ DW_FORM_ref4
	.byte	0                               @ EOM(1)
	.byte	0                               @ EOM(2)
	.byte	7                               @ Abbreviation Code
	.byte	21                              @ DW_TAG_subroutine_type
	.byte	0                               @ DW_CHILDREN_no
	.byte	39                              @ DW_AT_prototyped
	.byte	12                              @ DW_FORM_flag
	.byte	0                               @ EOM(1)
	.byte	0                               @ EOM(2)
	.byte	8                               @ Abbreviation Code
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
	.byte	9                               @ Abbreviation Code
	.byte	46                              @ DW_TAG_subprogram
	.byte	0                               @ DW_CHILDREN_no
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
	.byte	0                               @ EOM(3)
	.section	.debug_info,"",%progbits
.Lcu_begin0:
	.long	.Ldebug_info_end0-.Ldebug_info_start0 @ Length of Unit
.Ldebug_info_start0:
	.short	3                               @ DWARF version number
	.long	.debug_abbrev                   @ Offset Into Abbrev. Section
	.byte	4                               @ Address Size (in bytes)
	.byte	1                               @ Abbrev [1] 0xb:0x75 DW_TAG_compile_unit
	.long	.Linfo_string0                  @ DW_AT_producer
	.short	29                              @ DW_AT_language
	.long	.Linfo_string1                  @ DW_AT_name
	.long	.Lline_table_start0             @ DW_AT_stmt_list
	.long	.Linfo_string2                  @ DW_AT_comp_dir
	.long	0                               @ DW_AT_low_pc
	.long	.Ldebug_ranges0                 @ DW_AT_ranges
	.byte	2                               @ Abbrev [2] 0x26:0x12 DW_TAG_variable
	.long	.Linfo_string3                  @ DW_AT_name
	.long	56                              @ DW_AT_type
	.byte	1                               @ DW_AT_external
	.byte	1                               @ DW_AT_decl_file
	.byte	87                              @ DW_AT_decl_line
	.byte	5                               @ DW_AT_location
	.byte	3
	.long	interruptVectors
	.byte	3                               @ Abbrev [3] 0x38:0xc DW_TAG_array_type
	.long	68                              @ DW_AT_type
	.byte	4                               @ Abbrev [4] 0x3d:0x6 DW_TAG_subrange_type
	.long	80                              @ DW_AT_type
	.byte	48                              @ DW_AT_count
	.byte	0                               @ End Of Children Mark
	.byte	5                               @ Abbrev [5] 0x44:0x5 DW_TAG_const_type
	.long	73                              @ DW_AT_type
	.byte	6                               @ Abbrev [6] 0x49:0x5 DW_TAG_pointer_type
	.long	78                              @ DW_AT_type
	.byte	7                               @ Abbrev [7] 0x4e:0x2 DW_TAG_subroutine_type
	.byte	1                               @ DW_AT_prototyped
	.byte	8                               @ Abbrev [8] 0x50:0x7 DW_TAG_base_type
	.long	.Linfo_string4                  @ DW_AT_name
	.byte	8                               @ DW_AT_byte_size
	.byte	7                               @ DW_AT_encoding
	.byte	9                               @ Abbrev [9] 0x57:0x14 DW_TAG_subprogram
	.long	.Lfunc_begin0                   @ DW_AT_low_pc
	.long	.Lfunc_end0                     @ DW_AT_high_pc
	.byte	1                               @ DW_AT_frame_base
	.byte	93
	.byte	0                               @ DW_AT_TI_max_frame_size
	.long	.Linfo_string5                  @ DW_AT_name
	.byte	1                               @ DW_AT_decl_file
	.byte	168                             @ DW_AT_decl_line
	.byte	1                               @ DW_AT_prototyped
	.byte	1                               @ DW_AT_external
	.byte	9                               @ Abbrev [9] 0x6b:0x14 DW_TAG_subprogram
	.long	.Lfunc_begin1                   @ DW_AT_low_pc
	.long	.Lfunc_end1                     @ DW_AT_high_pc
	.byte	1                               @ DW_AT_frame_base
	.byte	93
	.byte	0                               @ DW_AT_TI_max_frame_size
	.long	.Linfo_string6                  @ DW_AT_name
	.byte	1                               @ DW_AT_decl_file
	.byte	155                             @ DW_AT_decl_line
	.byte	1                               @ DW_AT_prototyped
	.byte	1                               @ DW_AT_external
	.byte	0                               @ End Of Children Mark
.Ldebug_info_end0:
	.section	.debug_ranges,"",%progbits
.Ldebug_ranges0:
	.long	.Lfunc_begin0
	.long	.Lfunc_end0
	.long	.Lfunc_begin1
	.long	.Lfunc_end1
	.long	0
	.long	0
	.section	.debug_str,"MS",%progbits,1
.Linfo_string0:
	.asciz	"TI clang version 18.1.8 (ssh://git@bitbucket.itg.ti.com/code/llvm-project.git 41ce286cff6db007d382d297353d8bf884b450b7)" @ string offset=0
.Linfo_string1:
	.asciz	"startup_mspm0l222x_ticlang.c"  @ string offset=120
.Linfo_string2:
	.asciz	"/home/main/Documents/school/Fault-Injection-Finder/targets/timspm0l2228/source" @ string offset=149
.Linfo_string3:
	.asciz	"interruptVectors"              @ string offset=228
.Linfo_string4:
	.asciz	"__ARRAY_SIZE_TYPE__"           @ string offset=245
.Linfo_string5:
	.asciz	"Default_Handler"               @ string offset=265
.Linfo_string6:
	.asciz	"Reset_Handler"                 @ string offset=281
	.ident	"TI clang version 18.1.8 (ssh://git@bitbucket.itg.ti.com/code/llvm-project.git 41ce286cff6db007d382d297353d8bf884b450b7)"
	.section	".note.GNU-stack","",%progbits
	.addrsig
	.addrsig_sym Default_Handler
	.addrsig_sym Reset_Handler
	.addrsig_sym __STACK_END
	.addrsig_sym interruptVectors
	.addrsig_sym NMI_Handler
	.addrsig_sym HardFault_Handler
	.addrsig_sym SVC_Handler
	.addrsig_sym PendSV_Handler
	.addrsig_sym SysTick_Handler
	.addrsig_sym GROUP0_IRQHandler
	.addrsig_sym GROUP1_IRQHandler
	.addrsig_sym TIMG12_IRQHandler
	.addrsig_sym UART4_IRQHandler
	.addrsig_sym ADC0_IRQHandler
	.addrsig_sym SPI0_IRQHandler
	.addrsig_sym SPI1_IRQHandler
	.addrsig_sym UART2_IRQHandler
	.addrsig_sym UART3_IRQHandler
	.addrsig_sym UART0_IRQHandler
	.addrsig_sym UART1_IRQHandler
	.addrsig_sym TIMA0_IRQHandler
	.addrsig_sym TIMG8_IRQHandler
	.addrsig_sym TIMG0_IRQHandler
	.addrsig_sym TIMG4_IRQHandler
	.addrsig_sym TIMG5_IRQHandler
	.addrsig_sym I2C0_IRQHandler
	.addrsig_sym I2C1_IRQHandler
	.addrsig_sym I2C2_IRQHandler
	.addrsig_sym AESADV_IRQHandler
	.addrsig_sym LCD_IRQHandler
	.addrsig_sym LFSS_IRQHandler
	.addrsig_sym DMA_IRQHandler
	.eabi_attribute	30, 1	@ Tag_ABI_optimization_goals
	.TI_attribute	16, 0	@ Tag_Instrumentation
	.section	.debug_line,"",%progbits
.Lline_table_start0:
