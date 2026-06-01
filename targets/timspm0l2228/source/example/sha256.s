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
	.file	"sha256.c"
	.section	.text.sha256_init,"ax",%progbits
	.hidden	sha256_init                     @ -- Begin function sha256_init
	.globl	sha256_init
	.p2align	2
	.type	sha256_init,%function
	.code	16                              @ @sha256_init
	.thumb_func
sha256_init:
.Lfunc_begin0:
	.fnstart
	.cfi_sections .debug_frame
	.cfi_startproc
@ %bb.0:
	@DEBUG_VALUE: sha256_init:buff <- $r0
	.save	{r4, r5, r6, r7, lr}
	push	{r4, r5, r6, r7, lr}
	.cfi_def_cfa_offset 20
	.cfi_offset lr, -4
	.cfi_offset r7, -8
	.cfi_offset r6, -12
	.cfi_offset r5, -16
	.cfi_offset r4, -20
	ldr	r2, .LCPI0_1
	ldr	r3, .LCPI0_2
	ldr	r4, .LCPI0_3
	ldr	r5, .LCPI0_4
	ldr	r6, .LCPI0_5
	ldr	r7, .LCPI0_6
	ldr	r1, .LCPI0_7
.Ltmp0:
	str	r7, [r0, #32]
	str	r1, [r0, #36]
	movs	r1, #0
	str	r1, [r0]
	str	r1, [r0, #4]
	ldr	r7, .LCPI0_0
	str	r7, [r0, #8]
	mov	r7, r0
	adds	r7, #12
	stm	r7!, {r2, r3, r4, r5, r6}
	movs	r2, #104
	strb	r1, [r0, r2]
	pop	{r4, r5, r6, r7, pc}
.Ltmp1:
	.p2align	2
@ %bb.1:
.LCPI0_0:
	.long	1779033703                      @ 0x6a09e667
.LCPI0_1:
	.long	3144134277                      @ 0xbb67ae85
.LCPI0_2:
	.long	1013904242                      @ 0x3c6ef372
.LCPI0_3:
	.long	2773480762                      @ 0xa54ff53a
.LCPI0_4:
	.long	1359893119                      @ 0x510e527f
.LCPI0_5:
	.long	2600822924                      @ 0x9b05688c
.LCPI0_6:
	.long	528734635                       @ 0x1f83d9ab
.LCPI0_7:
	.long	1541459225                      @ 0x5be0cd19
.Lfunc_end0:
	.size	sha256_init, .Lfunc_end0-sha256_init
	.cfi_endproc
	.cantunwind
	.fnend
                                        @ -- End function
	.section	.text.sha256_update,"ax",%progbits
	.hidden	sha256_update                   @ -- Begin function sha256_update
	.globl	sha256_update
	.p2align	1
	.type	sha256_update,%function
	.code	16                              @ @sha256_update
	.thumb_func
sha256_update:
.Lfunc_begin1:
	.fnstart
	.cfi_startproc
@ %bb.0:
	@DEBUG_VALUE: sha256_update:buff <- $r0
	@DEBUG_VALUE: sha256_update:data <- $r1
	@DEBUG_VALUE: sha256_update:size <- $r2
	.save	{r4, r5, r6, r7, lr}
	push	{r4, r5, r6, r7, lr}
	.cfi_def_cfa_offset 20
	.cfi_offset lr, -4
	.cfi_offset r7, -8
	.cfi_offset r6, -12
	.cfi_offset r5, -16
	.cfi_offset r4, -20
	.pad	#76
	sub	sp, #76
	.cfi_def_cfa_offset 96
	mov	r4, r2
.Ltmp2:
	@DEBUG_VALUE: sha256_update:size <- $r4
	mov	r5, r1
.Ltmp3:
	@DEBUG_VALUE: sha256_update:data <- $r5
	mov	r6, r0
.Ltmp4:
	@DEBUG_VALUE: sha256_update:ptr <- undef
	@DEBUG_VALUE: sha256_update:buff <- $r6
	ldr	r0, [r0]
	ldr	r1, [r6, #4]
	movs	r7, #0
	adds	r0, r0, r2
	adcs	r1, r7
	stm	r6!, {r0, r1}
.Ltmp5:
	@DEBUG_VALUE: sha256_update:buff <- [DW_OP_LLVM_entry_value 1] $r0
	subs	r6, #8
.Ltmp6:
	mov	r1, r6
	adds	r1, #104
	movs	r0, #104
	ldrb	r0, [r6, r0]
	uxtb	r2, r0
	adds	r0, r2, r4
.Ltmp7:
	cmp	r0, #64
	str	r1, [sp, #8]                    @ 4-byte Spill
	blo	.LBB1_2
.Ltmp8:
@ %bb.1:
	@DEBUG_VALUE: sha256_update:buff <- [DW_OP_LLVM_entry_value 1] $r0
	@DEBUG_VALUE: sha256_update:data <- $r5
	@DEBUG_VALUE: sha256_update:size <- $r4
	mov	r1, r6
	adds	r1, #40
	add	r0, sp, #12
	str	r0, [sp, #4]                    @ 4-byte Spill
	str	r2, [sp]                        @ 4-byte Spill
	bl	__aeabi_memcpy4
.Ltmp9:
	ldr	r0, [sp, #4]                    @ 4-byte Reload
	ldr	r2, [sp]                        @ 4-byte Reload
	adds	r0, r0, r2
	movs	r1, #64
	subs	r2, r1, r2
	str	r2, [sp]                        @ 4-byte Spill
	mov	r1, r5
	bl	__aeabi_memcpy
.Ltmp10:
	ldr	r0, [sp]                        @ 4-byte Reload
	adds	r5, r5, r0
.Ltmp11:
	@DEBUG_VALUE: sha256_update:data <- [DW_OP_LLVM_entry_value 1] $r1
	@DEBUG_VALUE: sha256_update:ptr <- $r5
	subs	r4, r4, r0
.Ltmp12:
	@DEBUG_VALUE: sha256_update:size <- $r4
	movs	r0, #0
	ldr	r1, [sp, #8]                    @ 4-byte Reload
	strb	r0, [r1]
	mov	r0, r6
	ldr	r1, [sp, #4]                    @ 4-byte Reload
	bl	sha256_calc_chunk
.Ltmp13:
.LBB1_2:
	@DEBUG_VALUE: sha256_update:buff <- [DW_OP_LLVM_entry_value 1] $r0
	@DEBUG_VALUE: sha256_update:size <- $r4
	@DEBUG_VALUE: sha256_update:size <- $r4
	@DEBUG_VALUE: sha256_update:ptr <- $r5
	cmp	r4, #64
	blo	.LBB1_8
.Ltmp14:
@ %bb.3:
	@DEBUG_VALUE: sha256_update:ptr <- $r5
	@DEBUG_VALUE: sha256_update:buff <- [DW_OP_LLVM_entry_value 1] $r0
	@DEBUG_VALUE: sha256_update:size <- $r4
	mov	r0, r4
	subs	r0, #64
	str	r0, [sp, #4]                    @ 4-byte Spill
	lsrs	r0, r0, #6
	movs	r1, #3
	bl	__aeabi_uidivmod
.Ltmp15:
	adds	r0, r1, #1
	cmp	r0, #3
	beq	.LBB1_5
.Ltmp16:
@ %bb.4:
	@DEBUG_VALUE: sha256_update:ptr <- $r5
	@DEBUG_VALUE: sha256_update:buff <- [DW_OP_LLVM_entry_value 1] $r0
	@DEBUG_VALUE: sha256_update:size <- $r4
	mov	r7, r0
.Ltmp17:
.LBB1_5:
	@DEBUG_VALUE: sha256_update:ptr <- $r5
	@DEBUG_VALUE: sha256_update:buff <- [DW_OP_LLVM_entry_value 1] $r0
	@DEBUG_VALUE: sha256_update:size <- $r4
	cmp	r0, #3
	beq	.LBB1_10
.Ltmp18:
.LBB1_6:                                @ =>This Inner Loop Header: Depth=1
	@DEBUG_VALUE: sha256_update:ptr <- $r5
	@DEBUG_VALUE: sha256_update:buff <- [DW_OP_LLVM_entry_value 1] $r0
	@DEBUG_VALUE: sha256_update:size <- $r4
	@DEBUG_VALUE: sha256_update:size <- $r4
	@DEBUG_VALUE: sha256_update:ptr <- $r5
	mov	r0, r6
	mov	r1, r5
	bl	sha256_calc_chunk
.Ltmp19:
	mov	r1, r5
	adds	r1, #64
.Ltmp20:
	@DEBUG_VALUE: sha256_update:ptr <- $r1
	@DEBUG_VALUE: sha256_update:size <- [DW_OP_constu 64, DW_OP_minus, DW_OP_stack_value] $r4
	cmp	r7, #1
	beq	.LBB1_9
.Ltmp21:
@ %bb.7:                                @   in Loop: Header=BB1_6 Depth=1
	@DEBUG_VALUE: sha256_update:size <- [DW_OP_constu 64, DW_OP_minus, DW_OP_stack_value] $r4
	@DEBUG_VALUE: sha256_update:ptr <- $r1
	@DEBUG_VALUE: sha256_update:buff <- [DW_OP_LLVM_entry_value 1] $r0
	@DEBUG_VALUE: sha256_update:size <- [DW_OP_constu 64, DW_OP_minus, DW_OP_stack_value] $r4
	@DEBUG_VALUE: sha256_update:ptr <- $r1
	mov	r0, r6
	bl	sha256_calc_chunk
.Ltmp22:
	adds	r5, #128
.Ltmp23:
	@DEBUG_VALUE: sha256_update:ptr <- $r5
	subs	r4, #128
.Ltmp24:
	@DEBUG_VALUE: sha256_update:size <- $r4
	subs	r7, r7, #2
	bne	.LBB1_6
	b	.LBB1_10
.Ltmp25:
.LBB1_8:
	@DEBUG_VALUE: sha256_update:ptr <- $r5
	@DEBUG_VALUE: sha256_update:buff <- [DW_OP_LLVM_entry_value 1] $r0
	@DEBUG_VALUE: sha256_update:size <- $r4
	ldr	r7, [sp, #8]                    @ 4-byte Reload
	b	.LBB1_12
.Ltmp26:
.LBB1_9:
	@DEBUG_VALUE: sha256_update:size <- [DW_OP_constu 64, DW_OP_minus, DW_OP_stack_value] $r4
	@DEBUG_VALUE: sha256_update:ptr <- $r1
	@DEBUG_VALUE: sha256_update:buff <- [DW_OP_LLVM_entry_value 1] $r0
	subs	r4, #64
.Ltmp27:
	mov	r5, r1
.Ltmp28:
	@DEBUG_VALUE: sha256_update:ptr <- $r5
.LBB1_10:
	@DEBUG_VALUE: sha256_update:ptr <- $r5
	@DEBUG_VALUE: sha256_update:buff <- [DW_OP_LLVM_entry_value 1] $r0
	ldr	r0, [sp, #4]                    @ 4-byte Reload
	cmp	r0, #128
	ldr	r7, [sp, #8]                    @ 4-byte Reload
	blo	.LBB1_12
.Ltmp29:
.LBB1_11:                               @ =>This Inner Loop Header: Depth=1
	@DEBUG_VALUE: sha256_update:ptr <- $r5
	@DEBUG_VALUE: sha256_update:buff <- [DW_OP_LLVM_entry_value 1] $r0
	@DEBUG_VALUE: sha256_update:size <- $r4
	@DEBUG_VALUE: sha256_update:ptr <- $r5
	mov	r0, r6
	mov	r1, r5
	bl	sha256_calc_chunk
.Ltmp30:
	mov	r1, r5
	adds	r1, #64
.Ltmp31:
	@DEBUG_VALUE: sha256_update:ptr <- $r1
	@DEBUG_VALUE: sha256_update:size <- [DW_OP_constu 64, DW_OP_minus, DW_OP_stack_value] $r4
	mov	r0, r6
	bl	sha256_calc_chunk
.Ltmp32:
	@DEBUG_VALUE: sha256_update:ptr <- [DW_OP_plus_uconst 128, DW_OP_stack_value] $r5
	@DEBUG_VALUE: sha256_update:size <- [DW_OP_constu 128, DW_OP_minus, DW_OP_stack_value] $r4
	mov	r1, r5
	adds	r1, #128
	mov	r0, r6
	bl	sha256_calc_chunk
.Ltmp33:
	adds	r5, #192
.Ltmp34:
	@DEBUG_VALUE: sha256_update:ptr <- $r5
	subs	r4, #192
.Ltmp35:
	@DEBUG_VALUE: sha256_update:size <- $r4
	cmp	r4, #63
	bhi	.LBB1_11
.Ltmp36:
.LBB1_12:
	@DEBUG_VALUE: sha256_update:ptr <- $r5
	@DEBUG_VALUE: sha256_update:buff <- [DW_OP_LLVM_entry_value 1] $r0
	ldrb	r0, [r7]
	adds	r0, r6, r0
	adds	r0, #40
	mov	r1, r5
	mov	r2, r4
	bl	__aeabi_memcpy
.Ltmp37:
	ldrb	r0, [r7]
	adds	r0, r0, r4
	strb	r0, [r7]
	add	sp, #76
	pop	{r4, r5, r6, r7, pc}
.Ltmp38:
.Lfunc_end1:
	.size	sha256_update, .Lfunc_end1-sha256_update
	.cfi_endproc
	.cantunwind
	.fnend
                                        @ -- End function
	.section	.text.sha256_calc_chunk,"ax",%progbits
	.p2align	2                               @ -- Begin function sha256_calc_chunk
	.type	sha256_calc_chunk,%function
	.code	16                              @ @sha256_calc_chunk
	.thumb_func
sha256_calc_chunk:
.Lfunc_begin2:
	.fnstart
	.cfi_startproc
@ %bb.0:
	@DEBUG_VALUE: sha256_calc_chunk:buff <- $r0
	@DEBUG_VALUE: sha256_calc_chunk:chunk <- $r1
	.save	{r4, r5, r6, r7, lr}
	push	{r4, r5, r6, r7, lr}
	.cfi_def_cfa_offset 20
	.cfi_offset lr, -4
	.cfi_offset r7, -8
	.cfi_offset r6, -12
	.cfi_offset r5, -16
	.cfi_offset r4, -20
	.pad	#324
	sub	sp, #324
	.cfi_def_cfa_offset 344
	str	r0, [sp, #32]                   @ 4-byte Spill
.Ltmp39:
	@DEBUG_VALUE: sha256_calc_chunk:buff <- [DW_OP_plus_uconst 32] [$sp+0]
	movs	r2, #0
.Ltmp40:
	@DEBUG_VALUE: sha256_calc_chunk:i <- 0
.LBB2_1:                                @ =>This Inner Loop Header: Depth=1
	@DEBUG_VALUE: sha256_calc_chunk:buff <- [DW_OP_plus_uconst 32] [$sp+0]
	@DEBUG_VALUE: sha256_calc_chunk:chunk <- [DW_OP_LLVM_arg 0, DW_OP_consts 32, DW_OP_div, DW_OP_consts 32, DW_OP_mul, DW_OP_LLVM_arg 0, DW_OP_plus, DW_OP_stack_value] undef
	@DEBUG_VALUE: sha256_calc_chunk:i <- [DW_OP_consts 32, DW_OP_div, DW_OP_consts 8, DW_OP_mul, DW_OP_stack_value] $r2
	adds	r3, r1, r2
	ldrb	r0, [r1, r2]
	lsls	r0, r0, #24
	ldrb	r4, [r3, #1]
	lsls	r4, r4, #16
	adds	r0, r4, r0
	ldrb	r4, [r3, #2]
	lsls	r4, r4, #8
	adds	r0, r0, r4
	ldrb	r4, [r3, #3]
	adds	r0, r0, r4
	add	r5, sp, #68
	adds	r4, r5, r2
	str	r0, [r5, r2]
.Ltmp41:
	@DEBUG_VALUE: sha256_calc_chunk:i <- [DW_OP_consts 32, DW_OP_div, DW_OP_consts 8, DW_OP_mul, DW_OP_consts 1, DW_OP_plus, DW_OP_stack_value] $r2
	@DEBUG_VALUE: sha256_calc_chunk:chunk <- [DW_OP_LLVM_arg 0, DW_OP_consts 32, DW_OP_div, DW_OP_consts 32, DW_OP_mul, DW_OP_consts 4, DW_OP_LLVM_arg 0, DW_OP_plus, DW_OP_plus, DW_OP_stack_value] undef
	ldrb	r0, [r3, #4]
	lsls	r0, r0, #24
	ldrb	r5, [r3, #5]
	lsls	r5, r5, #16
	adds	r0, r5, r0
	ldrb	r5, [r3, #6]
	lsls	r5, r5, #8
	adds	r0, r0, r5
	ldrb	r5, [r3, #7]
	adds	r0, r0, r5
	str	r0, [r4, #4]
.Ltmp42:
	@DEBUG_VALUE: sha256_calc_chunk:i <- [DW_OP_consts 32, DW_OP_div, DW_OP_consts 8, DW_OP_mul, DW_OP_consts 2, DW_OP_plus, DW_OP_stack_value] $r2
	@DEBUG_VALUE: sha256_calc_chunk:chunk <- [DW_OP_LLVM_arg 0, DW_OP_consts 32, DW_OP_div, DW_OP_consts 32, DW_OP_mul, DW_OP_consts 8, DW_OP_LLVM_arg 0, DW_OP_plus, DW_OP_plus, DW_OP_stack_value] undef
	ldrb	r0, [r3, #8]
	lsls	r0, r0, #24
	ldrb	r5, [r3, #9]
	lsls	r5, r5, #16
	adds	r0, r5, r0
	ldrb	r5, [r3, #10]
	lsls	r5, r5, #8
	adds	r0, r0, r5
	ldrb	r5, [r3, #11]
	adds	r0, r0, r5
	str	r0, [r4, #8]
.Ltmp43:
	@DEBUG_VALUE: sha256_calc_chunk:i <- [DW_OP_consts 32, DW_OP_div, DW_OP_consts 8, DW_OP_mul, DW_OP_consts 3, DW_OP_plus, DW_OP_stack_value] $r2
	@DEBUG_VALUE: sha256_calc_chunk:chunk <- [DW_OP_LLVM_arg 0, DW_OP_consts 32, DW_OP_div, DW_OP_consts 32, DW_OP_mul, DW_OP_consts 12, DW_OP_LLVM_arg 0, DW_OP_plus, DW_OP_plus, DW_OP_stack_value] undef
	ldrb	r0, [r3, #12]
	lsls	r0, r0, #24
	ldrb	r5, [r3, #13]
	lsls	r5, r5, #16
	adds	r0, r5, r0
	ldrb	r5, [r3, #14]
	lsls	r5, r5, #8
	adds	r0, r0, r5
	ldrb	r5, [r3, #15]
	adds	r0, r0, r5
	str	r0, [r4, #12]
.Ltmp44:
	@DEBUG_VALUE: sha256_calc_chunk:i <- [DW_OP_consts 32, DW_OP_div, DW_OP_consts 8, DW_OP_mul, DW_OP_consts 4, DW_OP_plus, DW_OP_stack_value] $r2
	@DEBUG_VALUE: sha256_calc_chunk:chunk <- [DW_OP_LLVM_arg 0, DW_OP_consts 32, DW_OP_div, DW_OP_consts 32, DW_OP_mul, DW_OP_consts 16, DW_OP_LLVM_arg 0, DW_OP_plus, DW_OP_plus, DW_OP_stack_value] undef
	ldrb	r0, [r3, #16]
	lsls	r0, r0, #24
	ldrb	r5, [r3, #17]
	lsls	r5, r5, #16
	adds	r0, r5, r0
	ldrb	r5, [r3, #18]
	lsls	r5, r5, #8
	adds	r0, r0, r5
	ldrb	r5, [r3, #19]
	adds	r0, r0, r5
	str	r0, [r4, #16]
.Ltmp45:
	@DEBUG_VALUE: sha256_calc_chunk:i <- [DW_OP_consts 32, DW_OP_div, DW_OP_consts 8, DW_OP_mul, DW_OP_consts 5, DW_OP_plus, DW_OP_stack_value] $r2
	@DEBUG_VALUE: sha256_calc_chunk:chunk <- [DW_OP_LLVM_arg 0, DW_OP_consts 32, DW_OP_div, DW_OP_consts 32, DW_OP_mul, DW_OP_consts 20, DW_OP_LLVM_arg 0, DW_OP_plus, DW_OP_plus, DW_OP_stack_value] undef
	ldrb	r0, [r3, #20]
	lsls	r0, r0, #24
	ldrb	r5, [r3, #21]
	lsls	r5, r5, #16
	adds	r0, r5, r0
	ldrb	r5, [r3, #22]
	lsls	r5, r5, #8
	adds	r0, r0, r5
	ldrb	r5, [r3, #23]
	adds	r0, r0, r5
	str	r0, [r4, #20]
.Ltmp46:
	@DEBUG_VALUE: sha256_calc_chunk:i <- [DW_OP_consts 32, DW_OP_div, DW_OP_consts 8, DW_OP_mul, DW_OP_consts 6, DW_OP_plus, DW_OP_stack_value] $r2
	@DEBUG_VALUE: sha256_calc_chunk:chunk <- [DW_OP_LLVM_arg 0, DW_OP_consts 32, DW_OP_div, DW_OP_consts 32, DW_OP_mul, DW_OP_consts 24, DW_OP_LLVM_arg 0, DW_OP_plus, DW_OP_plus, DW_OP_stack_value] undef
	ldrb	r0, [r3, #24]
	lsls	r0, r0, #24
	ldrb	r5, [r3, #25]
	lsls	r5, r5, #16
	adds	r0, r5, r0
	ldrb	r5, [r3, #26]
	lsls	r5, r5, #8
	adds	r0, r0, r5
	ldrb	r5, [r3, #27]
	adds	r0, r0, r5
	str	r0, [r4, #24]
.Ltmp47:
	@DEBUG_VALUE: sha256_calc_chunk:i <- [DW_OP_consts 32, DW_OP_div, DW_OP_consts 8, DW_OP_mul, DW_OP_consts 7, DW_OP_plus, DW_OP_stack_value] $r2
	@DEBUG_VALUE: sha256_calc_chunk:chunk <- [DW_OP_LLVM_arg 0, DW_OP_consts 32, DW_OP_div, DW_OP_consts 32, DW_OP_mul, DW_OP_consts 28, DW_OP_LLVM_arg 0, DW_OP_plus, DW_OP_plus, DW_OP_stack_value] undef
	ldrb	r0, [r3, #28]
	lsls	r0, r0, #24
	ldrb	r5, [r3, #29]
	lsls	r5, r5, #16
	adds	r0, r5, r0
	ldrb	r5, [r3, #30]
	lsls	r5, r5, #8
	adds	r0, r0, r5
	ldrb	r3, [r3, #31]
	adds	r0, r0, r3
	str	r0, [r4, #28]
.Ltmp48:
	@DEBUG_VALUE: sha256_calc_chunk:i <- [DW_OP_consts 32, DW_OP_div, DW_OP_consts 8, DW_OP_mul, DW_OP_consts 8, DW_OP_plus, DW_OP_stack_value] $r2
	@DEBUG_VALUE: sha256_calc_chunk:chunk <- [DW_OP_LLVM_arg 0, DW_OP_consts 32, DW_OP_div, DW_OP_consts 32, DW_OP_mul, DW_OP_consts 32, DW_OP_LLVM_arg 0, DW_OP_plus, DW_OP_plus, DW_OP_stack_value] undef
	adds	r2, #32
.Ltmp49:
	cmp	r2, #64
	bne	.LBB2_1
.Ltmp50:
@ %bb.2:
	@DEBUG_VALUE: sha256_calc_chunk:buff <- [DW_OP_plus_uconst 32] [$sp+0]
	movs	r1, #0
.Ltmp51:
	ldr	r5, [sp, #68]
.Ltmp52:
.LBB2_3:                                @ =>This Inner Loop Header: Depth=1
	@DEBUG_VALUE: sha256_calc_chunk:i <- [DW_OP_consts 16, DW_OP_div, DW_OP_consts 4, DW_OP_mul, DW_OP_consts 16, DW_OP_plus, DW_OP_stack_value] $r1
	str	r1, [sp, #48]                   @ 4-byte Spill
.Ltmp53:
	@DEBUG_VALUE: sha256_calc_chunk:buff <- [DW_OP_plus_uconst 48, DW_OP_deref, DW_OP_plus_uconst 32] [$sp+0]
	add	r0, sp, #68
	adds	r2, r0, r1
	ldr	r4, [r2, #4]
	str	r4, [sp, #44]                   @ 4-byte Spill
	movs	r1, #7
.Ltmp54:
	@DEBUG_VALUE: sha256_calc_chunk:i <- [DW_OP_consts 16, DW_OP_div, DW_OP_consts 4, DW_OP_mul, DW_OP_consts 16, DW_OP_plus, DW_OP_stack_value] $r1
	mov	r0, r4
	rors	r0, r1
	mov	r7, r1
	str	r1, [sp, #60]                   @ 4-byte Spill
	movs	r3, #18
	str	r3, [sp, #56]                   @ 4-byte Spill
.Ltmp55:
	@DEBUG_VALUE: sha256_calc_chunk:i <- [DW_OP_plus_uconst 48, DW_OP_deref_size 4, DW_OP_consts 16, DW_OP_div, DW_OP_consts 4, DW_OP_mul, DW_OP_consts 16, DW_OP_plus, DW_OP_stack_value] $sp
	mov	r1, r4
	rors	r1, r3
	eors	r1, r0
	lsrs	r0, r4, #3
	eors	r0, r1
.Ltmp56:
	@DEBUG_VALUE: s0 <- $r0
	ldr	r1, [r2, #56]
	movs	r3, #17
	str	r3, [sp, #52]                   @ 4-byte Spill
	mov	r4, r1
	rors	r4, r3
	movs	r6, #19
	str	r6, [sp, #64]                   @ 4-byte Spill
	lsrs	r3, r1, #10
	rors	r1, r6
	eors	r1, r4
	eors	r1, r3
.Ltmp57:
	@DEBUG_VALUE: s1 <- $r1
	adds	r0, r0, r5
.Ltmp58:
	ldr	r3, [r2, #36]
	adds	r0, r0, r3
	adds	r6, r0, r1
	str	r6, [r2, #64]
.Ltmp59:
	@DEBUG_VALUE: sha256_calc_chunk:i <- [DW_OP_plus_uconst 48, DW_OP_deref_size 4, DW_OP_consts 16, DW_OP_div, DW_OP_consts 4, DW_OP_mul, DW_OP_consts 17, DW_OP_plus, DW_OP_stack_value] $sp
	ldr	r0, [r2, #8]
	str	r0, [sp, #40]                   @ 4-byte Spill
	mov	r1, r0
.Ltmp60:
	rors	r1, r7
	mov	r3, r0
	ldr	r5, [sp, #56]                   @ 4-byte Reload
	rors	r3, r5
	eors	r3, r1
	lsrs	r1, r0, #3
	eors	r1, r3
.Ltmp61:
	@DEBUG_VALUE: s0 <- $r1
	ldr	r3, [r2, #60]
	mov	r4, r3
	ldr	r0, [sp, #52]                   @ 4-byte Reload
	rors	r4, r0
	lsrs	r7, r3, #10
	str	r7, [sp, #36]                   @ 4-byte Spill
	ldr	r7, [sp, #64]                   @ 4-byte Reload
	rors	r3, r7
	eors	r3, r4
	ldr	r4, [sp, #36]                   @ 4-byte Reload
	eors	r3, r4
.Ltmp62:
	@DEBUG_VALUE: s1 <- $r3
	ldr	r4, [sp, #44]                   @ 4-byte Reload
	adds	r1, r1, r4
.Ltmp63:
	ldr	r4, [r2, #40]
	adds	r1, r1, r4
	adds	r7, r1, r3
	str	r7, [r2, #68]
.Ltmp64:
	@DEBUG_VALUE: sha256_calc_chunk:i <- [DW_OP_plus_uconst 48, DW_OP_deref_size 4, DW_OP_consts 16, DW_OP_div, DW_OP_consts 4, DW_OP_mul, DW_OP_consts 18, DW_OP_plus, DW_OP_stack_value] $sp
	ldr	r1, [r2, #12]
	mov	r3, r1
.Ltmp65:
	ldr	r4, [sp, #60]                   @ 4-byte Reload
	rors	r3, r4
	mov	r4, r1
	rors	r4, r5
	eors	r4, r3
	lsrs	r3, r1, #3
	eors	r3, r4
.Ltmp66:
	@DEBUG_VALUE: s0 <- $r3
	mov	r4, r6
	rors	r4, r0
	lsrs	r0, r6, #10
	ldr	r5, [sp, #64]                   @ 4-byte Reload
	rors	r6, r5
	eors	r6, r4
	eors	r6, r0
.Ltmp67:
	@DEBUG_VALUE: s1 <- $r6
	ldr	r0, [sp, #40]                   @ 4-byte Reload
	adds	r0, r3, r0
	ldr	r3, [r2, #44]
.Ltmp68:
	adds	r0, r0, r3
	adds	r0, r0, r6
	str	r0, [r2, #72]
.Ltmp69:
	@DEBUG_VALUE: sha256_calc_chunk:i <- [DW_OP_plus_uconst 48, DW_OP_deref_size 4, DW_OP_consts 16, DW_OP_div, DW_OP_consts 4, DW_OP_mul, DW_OP_consts 19, DW_OP_plus, DW_OP_stack_value] $sp
	ldr	r5, [r2, #16]
	mov	r0, r5
	ldr	r3, [sp, #60]                   @ 4-byte Reload
	rors	r0, r3
	mov	r3, r5
	ldr	r4, [sp, #56]                   @ 4-byte Reload
	rors	r3, r4
	eors	r3, r0
	lsrs	r0, r5, #3
	eors	r0, r3
.Ltmp70:
	@DEBUG_VALUE: s0 <- $r0
	mov	r3, r7
	ldr	r4, [sp, #52]                   @ 4-byte Reload
	rors	r3, r4
	lsrs	r4, r7, #10
	ldr	r6, [sp, #64]                   @ 4-byte Reload
.Ltmp71:
	rors	r7, r6
	eors	r7, r3
	eors	r7, r4
.Ltmp72:
	@DEBUG_VALUE: s1 <- $r7
	adds	r0, r0, r1
.Ltmp73:
	ldr	r1, [r2, #48]
	adds	r0, r0, r1
	ldr	r1, [sp, #48]                   @ 4-byte Reload
.Ltmp74:
	@DEBUG_VALUE: sha256_calc_chunk:buff <- [DW_OP_plus_uconst 32] [$r1+0]
	@DEBUG_VALUE: sha256_calc_chunk:i <- [DW_OP_consts 16, DW_OP_div, DW_OP_consts 4, DW_OP_mul, DW_OP_consts 19, DW_OP_plus, DW_OP_stack_value] $r1
	adds	r0, r0, r7
	str	r0, [r2, #76]
.Ltmp75:
	@DEBUG_VALUE: sha256_calc_chunk:i <- [DW_OP_consts 16, DW_OP_div, DW_OP_consts 4, DW_OP_mul, DW_OP_consts 20, DW_OP_plus, DW_OP_stack_value] $r1
	adds	r1, #16
.Ltmp76:
	cmp	r1, #192
	bne	.LBB2_3
.Ltmp77:
@ %bb.4:
	@DEBUG_VALUE: sha256_calc_chunk:tv <- [DW_OP_LLVM_fragment 0 32] undef
	@DEBUG_VALUE: sha256_calc_chunk:tv <- [DW_OP_LLVM_fragment 32 32] undef
	@DEBUG_VALUE: sha256_calc_chunk:tv <- [DW_OP_LLVM_fragment 64 32] undef
	@DEBUG_VALUE: sha256_calc_chunk:tv <- [DW_OP_LLVM_fragment 96 32] undef
	@DEBUG_VALUE: sha256_calc_chunk:tv <- [DW_OP_LLVM_fragment 128 32] undef
	@DEBUG_VALUE: sha256_calc_chunk:tv <- [DW_OP_LLVM_fragment 160 32] undef
	@DEBUG_VALUE: sha256_calc_chunk:tv <- [DW_OP_LLVM_fragment 192 32] undef
	@DEBUG_VALUE: sha256_calc_chunk:tv <- [DW_OP_LLVM_fragment 224 32] undef
	ldr	r0, [sp, #32]                   @ 4-byte Reload
.Ltmp78:
	ldr	r4, [r0, #8]
.Ltmp79:
	@DEBUG_VALUE: sha256_calc_chunk:tv <- [DW_OP_LLVM_fragment 0 32] $r4
	ldr	r1, [r0, #12]
.Ltmp80:
	@DEBUG_VALUE: sha256_calc_chunk:tv <- [DW_OP_LLVM_fragment 32 32] $r1
	str	r1, [sp, #28]                   @ 4-byte Spill
.Ltmp81:
	@DEBUG_VALUE: sha256_calc_chunk:tv <- [DW_OP_plus_uconst 28, DW_OP_LLVM_fragment 32 32] [$sp+0]
	@DEBUG_VALUE: sha256_calc_chunk:tv <- [DW_OP_plus_uconst 28, DW_OP_LLVM_fragment 32 32] [$sp+0]
	ldr	r5, [r0, #16]
.Ltmp82:
	@DEBUG_VALUE: sha256_calc_chunk:tv <- [DW_OP_LLVM_fragment 64 32] $r5
	ldr	r7, [r0, #20]
.Ltmp83:
	@DEBUG_VALUE: sha256_calc_chunk:tv <- [DW_OP_LLVM_fragment 96 32] $r7
	ldr	r6, [r0, #24]
.Ltmp84:
	@DEBUG_VALUE: sha256_calc_chunk:tv <- [DW_OP_LLVM_fragment 128 32] $r6
	ldr	r3, [r0, #28]
.Ltmp85:
	@DEBUG_VALUE: sha256_calc_chunk:tv <- [DW_OP_LLVM_fragment 160 32] $r3
	ldr	r1, [r0, #32]
.Ltmp86:
	@DEBUG_VALUE: sha256_calc_chunk:tv <- [DW_OP_LLVM_fragment 192 32] $r1
	ldr	r0, [r0, #36]
.Ltmp87:
	@DEBUG_VALUE: sha256_calc_chunk:tv <- [DW_OP_LLVM_fragment 224 32] $r0
	movs	r2, #64
	str	r2, [sp, #52]                   @ 4-byte Spill
	movs	r2, #0
.Ltmp88:
	@DEBUG_VALUE: sha256_calc_chunk:i <- 0
	str	r6, [sp, #12]                   @ 4-byte Spill
.Ltmp89:
	@DEBUG_VALUE: sha256_calc_chunk:tv <- [DW_OP_plus_uconst 12, DW_OP_LLVM_fragment 128 32] [$sp+0]
	str	r6, [sp, #56]                   @ 4-byte Spill
	str	r3, [sp, #8]                    @ 4-byte Spill
.Ltmp90:
	@DEBUG_VALUE: sha256_calc_chunk:tv <- [DW_OP_plus_uconst 8, DW_OP_LLVM_fragment 160 32] [$sp+0]
	str	r1, [sp, #4]                    @ 4-byte Spill
.Ltmp91:
	@DEBUG_VALUE: sha256_calc_chunk:tv <- [DW_OP_plus_uconst 4, DW_OP_LLVM_fragment 192 32] [$sp+0]
	str	r1, [sp, #60]                   @ 4-byte Spill
	str	r0, [sp]                        @ 4-byte Spill
.Ltmp92:
	@DEBUG_VALUE: sha256_calc_chunk:tv <- [DW_OP_LLVM_fragment 224 32] [$sp+0]
	str	r0, [sp, #48]                   @ 4-byte Spill
	str	r4, [sp, #24]                   @ 4-byte Spill
.Ltmp93:
	@DEBUG_VALUE: sha256_calc_chunk:tv <- [DW_OP_plus_uconst 28, DW_OP_LLVM_fragment 32 32] [$sp+0]
	@DEBUG_VALUE: sha256_calc_chunk:tv <- [DW_OP_LLVM_fragment 32 32] undef
	@DEBUG_VALUE: sha256_calc_chunk:tv <- [DW_OP_plus_uconst 24, DW_OP_LLVM_fragment 0 32] [$sp+0]
	ldr	r0, [sp, #28]                   @ 4-byte Reload
	str	r5, [sp, #20]                   @ 4-byte Spill
.Ltmp94:
	@DEBUG_VALUE: sha256_calc_chunk:tv <- [DW_OP_plus_uconst 20, DW_OP_LLVM_fragment 64 32] [$sp+0]
	str	r7, [sp, #16]                   @ 4-byte Spill
.Ltmp95:
	@DEBUG_VALUE: sha256_calc_chunk:tv <- [DW_OP_plus_uconst 16, DW_OP_LLVM_fragment 96 32] [$sp+0]
	mov	r1, r7
.Ltmp96:
.LBB2_5:                                @ =>This Inner Loop Header: Depth=1
	str	r1, [sp, #44]                   @ 4-byte Spill
	str	r5, [sp, #64]                   @ 4-byte Spill
	str	r0, [sp, #40]                   @ 4-byte Spill
	mov	r0, r4
	ldr	r5, [sp, #60]                   @ 4-byte Reload
	str	r5, [sp, #36]                   @ 4-byte Spill
	mov	r1, r3
	ldr	r3, [sp, #56]                   @ 4-byte Reload
.Ltmp97:
	@DEBUG_VALUE: sha256_calc_chunk:i <- [DW_OP_plus_uconst 52, DW_OP_deref_size 4, DW_OP_consts 64, DW_OP_minus, DW_OP_consts 18446744073709551615, DW_OP_div, DW_OP_stack_value] $sp
	movs	r6, #6
.Ltmp98:
	mov	r4, r3
	rors	r4, r6
	movs	r7, #11
	mov	r6, r3
	rors	r6, r7
	eors	r6, r4
	movs	r4, #25
	mov	r7, r3
	rors	r7, r4
	eors	r7, r6
.Ltmp99:
	@DEBUG_VALUE: S1 <- $r7
	str	r1, [sp, #60]                   @ 4-byte Spill
	mov	r4, r1
	ands	r4, r3
	mov	r6, r5
	bics	r6, r3
.Ltmp100:
	@DEBUG_VALUE: ch <- undef
	ldr	r1, .LCPI2_0
	ldr	r5, [r1, r2]
	add	r1, sp, #68
	ldr	r1, [r1, r2]
	adds	r4, r7, r4
	ldr	r7, [sp, #48]                   @ 4-byte Reload
.Ltmp101:
	adds	r4, r4, r7
	adds	r4, r4, r6
	adds	r4, r4, r5
	adds	r1, r4, r1
.Ltmp102:
	@DEBUG_VALUE: temp1 <- $r1
	str	r1, [sp, #48]                   @ 4-byte Spill
.Ltmp103:
	@DEBUG_VALUE: temp1 <- [DW_OP_plus_uconst 48] [$sp+0]
	@DEBUG_VALUE: temp1 <- [DW_OP_plus_uconst 48] [$sp+0]
	@DEBUG_VALUE: temp1 <- [DW_OP_plus_uconst 48] [$sp+0]
	movs	r1, #2
	mov	r5, r0
	rors	r5, r1
	movs	r1, #13
	mov	r6, r0
	rors	r6, r1
	eors	r6, r5
	movs	r1, #22
	mov	r5, r0
	rors	r5, r1
	eors	r5, r6
.Ltmp104:
	@DEBUG_VALUE: S0 <- $r5
	ldr	r7, [sp, #64]                   @ 4-byte Reload
	mov	r1, r7
	mov	r4, r2
	ldr	r2, [sp, #40]                   @ 4-byte Reload
	eors	r1, r2
	ands	r1, r0
	mov	r6, r2
	mov	r2, r4
	ands	r7, r6
	eors	r7, r1
.Ltmp105:
	@DEBUG_VALUE: temp2 <- undef
	@DEBUG_VALUE: maj <- $r7
	@DEBUG_VALUE: sha256_calc_chunk:tv <- [DW_OP_plus_uconst 36, DW_OP_LLVM_fragment 224 32] [$sp+0]
	@DEBUG_VALUE: sha256_calc_chunk:tv <- [DW_OP_plus_uconst 60, DW_OP_LLVM_fragment 192 32] [$sp+0]
	@DEBUG_VALUE: sha256_calc_chunk:tv <- [DW_OP_LLVM_fragment 160 32] $r3
	ldr	r1, [sp, #44]                   @ 4-byte Reload
	ldr	r4, [sp, #48]                   @ 4-byte Reload
.Ltmp106:
	@DEBUG_VALUE: temp1 <- $r4
	adds	r1, r1, r4
.Ltmp107:
	@DEBUG_VALUE: sha256_calc_chunk:tv <- [DW_OP_LLVM_fragment 128 32] $r1
	@DEBUG_VALUE: sha256_calc_chunk:tv <- [DW_OP_plus_uconst 64, DW_OP_LLVM_fragment 96 32] [$sp+0]
	@DEBUG_VALUE: sha256_calc_chunk:tv <- [DW_OP_LLVM_fragment 64 32] $r6
	@DEBUG_VALUE: sha256_calc_chunk:tv <- [DW_OP_LLVM_fragment 32 32] $r0
	str	r1, [sp, #56]                   @ 4-byte Spill
.Ltmp108:
	@DEBUG_VALUE: sha256_calc_chunk:tv <- [DW_OP_plus_uconst 56, DW_OP_LLVM_fragment 128 32] [$sp+0]
	@DEBUG_VALUE: sha256_calc_chunk:tv <- [DW_OP_plus_uconst 56, DW_OP_LLVM_fragment 128 32] [$sp+0]
	@DEBUG_VALUE: sha256_calc_chunk:tv <- [DW_OP_plus_uconst 56, DW_OP_LLVM_fragment 128 32] [$sp+0]
	adds	r1, r5, r4
	mov	r5, r6
.Ltmp109:
	@DEBUG_VALUE: sha256_calc_chunk:tv <- [DW_OP_LLVM_fragment 64 32] $r5
	@DEBUG_VALUE: sha256_calc_chunk:tv <- [DW_OP_LLVM_fragment 64 32] $r5
	@DEBUG_VALUE: sha256_calc_chunk:tv <- [DW_OP_LLVM_fragment 64 32] $r5
	adds	r4, r1, r7
.Ltmp110:
	@DEBUG_VALUE: sha256_calc_chunk:tv <- [DW_OP_LLVM_fragment 0 32] $r4
	@DEBUG_VALUE: sha256_calc_chunk:i <- [DW_OP_plus_uconst 52, DW_OP_deref_size 4, DW_OP_consts 64, DW_OP_minus, DW_OP_consts 18446744073709551615, DW_OP_div, DW_OP_consts 1, DW_OP_plus, DW_OP_stack_value] $sp
	ldr	r7, [sp, #36]                   @ 4-byte Reload
.Ltmp111:
	@DEBUG_VALUE: sha256_calc_chunk:tv <- [DW_OP_LLVM_fragment 224 32] $r7
	ldr	r1, [sp, #52]                   @ 4-byte Reload
.Ltmp112:
	@DEBUG_VALUE: sha256_calc_chunk:i <- [DW_OP_consts 64, DW_OP_minus, DW_OP_consts 18446744073709551615, DW_OP_div, DW_OP_consts 1, DW_OP_plus, DW_OP_stack_value] $r1
	subs	r1, r1, #1
.Ltmp113:
	adds	r2, r2, #4
	str	r1, [sp, #52]                   @ 4-byte Spill
.Ltmp114:
	cmp	r1, #0
	str	r7, [sp, #48]                   @ 4-byte Spill
	ldr	r1, [sp, #64]                   @ 4-byte Reload
.Ltmp115:
	@DEBUG_VALUE: sha256_calc_chunk:tv <- [DW_OP_LLVM_fragment 96 32] $r1
	@DEBUG_VALUE: sha256_calc_chunk:tv <- [DW_OP_LLVM_fragment 96 32] $r1
	bne	.LBB2_5
.Ltmp116:
@ %bb.6:
	@DEBUG_VALUE: sha256_calc_chunk:tv <- [DW_OP_LLVM_fragment 96 32] $r1
	@DEBUG_VALUE: sha256_calc_chunk:tv <- [DW_OP_LLVM_fragment 224 32] $r7
	@DEBUG_VALUE: sha256_calc_chunk:tv <- [DW_OP_plus_uconst 56, DW_OP_LLVM_fragment 128 32] [$sp+0]
	@DEBUG_VALUE: sha256_calc_chunk:tv <- [DW_OP_LLVM_fragment 32 32] $r0
	@DEBUG_VALUE: sha256_calc_chunk:tv <- [DW_OP_plus_uconst 60, DW_OP_LLVM_fragment 192 32] [$sp+0]
	@DEBUG_VALUE: sha256_calc_chunk:tv <- [DW_OP_LLVM_fragment 160 32] $r3
	@DEBUG_VALUE: sha256_calc_chunk:tv <- [DW_OP_LLVM_fragment 64 32] $r5
	@DEBUG_VALUE: sha256_calc_chunk:tv <- [DW_OP_LLVM_fragment 0 32] $r4
	mov	r6, r1
.Ltmp117:
	@DEBUG_VALUE: sha256_calc_chunk:tv <- [DW_OP_LLVM_fragment 96 32] $r6
	@DEBUG_VALUE: sha256_calc_chunk:i <- 0
	ldr	r1, [sp, #24]                   @ 4-byte Reload
	adds	r1, r1, r4
.Ltmp118:
	@DEBUG_VALUE: sha256_calc_chunk:i <- 1
	ldr	r2, [sp, #28]                   @ 4-byte Reload
	adds	r0, r2, r0
.Ltmp119:
	@DEBUG_VALUE: sha256_calc_chunk:i <- 2
	ldr	r2, [sp, #20]                   @ 4-byte Reload
	adds	r2, r2, r5
.Ltmp120:
	@DEBUG_VALUE: sha256_calc_chunk:i <- 3
	ldr	r4, [sp, #16]                   @ 4-byte Reload
.Ltmp121:
	adds	r4, r4, r6
.Ltmp122:
	@DEBUG_VALUE: sha256_calc_chunk:i <- 4
	ldr	r5, [sp, #12]                   @ 4-byte Reload
.Ltmp123:
	ldr	r6, [sp, #56]                   @ 4-byte Reload
.Ltmp124:
	adds	r5, r5, r6
.Ltmp125:
	@DEBUG_VALUE: sha256_calc_chunk:i <- 5
	str	r5, [sp, #64]                   @ 4-byte Spill
	ldr	r5, [sp, #8]                    @ 4-byte Reload
	adds	r5, r5, r3
.Ltmp126:
	@DEBUG_VALUE: sha256_calc_chunk:i <- 6
	ldr	r3, [sp, #4]                    @ 4-byte Reload
.Ltmp127:
	ldr	r6, [sp, #60]                   @ 4-byte Reload
	adds	r6, r3, r6
.Ltmp128:
	@DEBUG_VALUE: sha256_calc_chunk:i <- 7
	ldr	r3, [sp]                        @ 4-byte Reload
	adds	r7, r3, r7
.Ltmp129:
	@DEBUG_VALUE: sha256_calc_chunk:i <- 8
	ldr	r3, [sp, #32]                   @ 4-byte Reload
	str	r1, [r3, #8]
	mov	r1, r3
	adds	r1, #12
	stm	r1!, {r0, r2, r4}
	ldr	r0, [sp, #64]                   @ 4-byte Reload
	mov	r1, r3
	adds	r1, #24
	stm	r1!, {r0, r5, r6, r7}
.Ltmp130:
	add	sp, #324
	pop	{r4, r5, r6, r7, pc}
.Ltmp131:
	.p2align	2
@ %bb.7:
.LCPI2_0:
	.long	k
.Lfunc_end2:
	.size	sha256_calc_chunk, .Lfunc_end2-sha256_calc_chunk
	.cfi_endproc
	.cantunwind
	.fnend
                                        @ -- End function
	.section	.text.sha256_finalize,"ax",%progbits
	.hidden	sha256_finalize                 @ -- Begin function sha256_finalize
	.globl	sha256_finalize
	.p2align	1
	.type	sha256_finalize,%function
	.code	16                              @ @sha256_finalize
	.thumb_func
sha256_finalize:
.Lfunc_begin3:
	.fnstart
	.cfi_startproc
@ %bb.0:
	@DEBUG_VALUE: sha256_finalize:buff <- $r0
	.save	{r4, r5, r6, r7, lr}
	push	{r4, r5, r6, r7, lr}
	.cfi_def_cfa_offset 20
	.cfi_offset lr, -4
	.cfi_offset r7, -8
	.cfi_offset r6, -12
	.cfi_offset r5, -16
	.cfi_offset r4, -20
	.pad	#4
	sub	sp, #4
	.cfi_def_cfa_offset 24
	mov	r4, r0
.Ltmp132:
	@DEBUG_VALUE: sha256_finalize:buff <- $r4
	mov	r6, r0
	adds	r6, #96
	mov	r5, r0
	adds	r5, #40
	ldrb	r0, [r6, #8]
	movs	r1, #128
	strb	r1, [r5, r0]
	ldrb	r0, [r6, #8]
	adds	r0, r0, #1
	strb	r0, [r6, #8]
	uxtb	r1, r0
	adds	r0, r5, r1
	movs	r2, #64
	subs	r1, r2, r1
	bl	__aeabi_memclr
.Ltmp133:
	ldrb	r0, [r6, #8]
.Ltmp134:
	cmp	r0, #57
	blo	.LBB3_2
.Ltmp135:
@ %bb.1:
	@DEBUG_VALUE: sha256_finalize:buff <- $r4
	mov	r0, r4
	mov	r1, r5
	bl	sha256_calc_chunk
.Ltmp136:
	movs	r1, #56
	mov	r0, r5
	bl	__aeabi_memclr8
.Ltmp137:
.LBB3_2:
	@DEBUG_VALUE: sha256_finalize:buff <- $r4
	ldr	r1, [r4]
	ldr	r0, [r4, #4]
	lsls	r2, r0, #3
	lsrs	r3, r1, #29
	lsls	r7, r1, #3
.Ltmp138:
	@DEBUG_VALUE: sha256_finalize:size <- [DW_OP_LLVM_fragment 32 32] undef
	@DEBUG_VALUE: sha256_finalize:i <- 8
	@DEBUG_VALUE: sha256_finalize:size <- [DW_OP_LLVM_fragment 0 32] $r7
	strb	r7, [r6, #7]
	lsrs	r7, r1, #5
.Ltmp139:
	@DEBUG_VALUE: sha256_finalize:i <- 7
	@DEBUG_VALUE: sha256_finalize:size <- [DW_OP_LLVM_fragment 0 32] $r7
	strb	r7, [r6, #6]
	lsrs	r7, r1, #13
.Ltmp140:
	@DEBUG_VALUE: sha256_finalize:i <- 6
	@DEBUG_VALUE: sha256_finalize:size <- [DW_OP_LLVM_fragment 0 32] $r7
	strb	r7, [r6, #5]
	lsrs	r1, r1, #21
.Ltmp141:
	@DEBUG_VALUE: sha256_finalize:i <- 5
	@DEBUG_VALUE: sha256_finalize:size <- [DW_OP_LLVM_fragment 0 32] $r1
	strb	r1, [r6, #4]
	adds	r1, r3, r2
.Ltmp142:
	@DEBUG_VALUE: sha256_finalize:size <- [DW_OP_LLVM_fragment 32 32] undef
	@DEBUG_VALUE: sha256_finalize:i <- 4
	@DEBUG_VALUE: sha256_finalize:size <- [DW_OP_LLVM_fragment 0 32] $r1
	strb	r1, [r6, #3]
	lsrs	r1, r0, #5
.Ltmp143:
	@DEBUG_VALUE: sha256_finalize:size <- [DW_OP_LLVM_fragment 32 32] undef
	@DEBUG_VALUE: sha256_finalize:i <- 3
	@DEBUG_VALUE: sha256_finalize:size <- [DW_OP_LLVM_fragment 0 32] $r1
	strb	r1, [r6, #2]
	lsrs	r1, r0, #13
.Ltmp144:
	@DEBUG_VALUE: sha256_finalize:size <- [DW_OP_LLVM_fragment 32 32] undef
	@DEBUG_VALUE: sha256_finalize:i <- 2
	@DEBUG_VALUE: sha256_finalize:size <- [DW_OP_LLVM_fragment 0 32] $r1
	strb	r1, [r6, #1]
	lsrs	r0, r0, #21
.Ltmp145:
	@DEBUG_VALUE: sha256_finalize:size <- [DW_OP_LLVM_fragment 32 32] undef
	@DEBUG_VALUE: sha256_finalize:i <- 1
	@DEBUG_VALUE: sha256_finalize:size <- [DW_OP_LLVM_fragment 0 32] $r0
	strb	r0, [r6]
.Ltmp146:
	@DEBUG_VALUE: sha256_finalize:size <- undef
	@DEBUG_VALUE: sha256_finalize:i <- 0
	mov	r0, r4
	mov	r1, r5
	bl	sha256_calc_chunk
.Ltmp147:
	add	sp, #4
	pop	{r4, r5, r6, r7, pc}
.Ltmp148:
.Lfunc_end3:
	.size	sha256_finalize, .Lfunc_end3-sha256_finalize
	.cfi_endproc
	.cantunwind
	.fnend
                                        @ -- End function
	.section	.text.sha256_read,"ax",%progbits
	.hidden	sha256_read                     @ -- Begin function sha256_read
	.globl	sha256_read
	.p2align	1
	.type	sha256_read,%function
	.code	16                              @ @sha256_read
	.thumb_func
sha256_read:
.Lfunc_begin4:
	.fnstart
	.cfi_startproc
@ %bb.0:
	@DEBUG_VALUE: sha256_read:buff <- $r0
	@DEBUG_VALUE: sha256_read:hash <- $r1
	@DEBUG_VALUE: sha256_read:i <- 0
	mov	r2, r0
	adds	r2, #8
	ldrb	r3, [r0, #11]
	strb	r3, [r1]
	ldrh	r3, [r0, #10]
	strb	r3, [r1, #1]
	ldr	r3, [r0, #8]
	lsrs	r3, r3, #8
	strb	r3, [r1, #2]
	ldr	r3, [r0, #8]
	strb	r3, [r1, #3]
.Ltmp149:
	@DEBUG_VALUE: sha256_read:i <- 1
	ldrb	r3, [r0, #15]
	strb	r3, [r1, #4]
	ldrh	r3, [r0, #14]
	strb	r3, [r1, #5]
	ldr	r3, [r0, #12]
	lsrs	r3, r3, #8
	strb	r3, [r1, #6]
	ldr	r3, [r0, #12]
	strb	r3, [r1, #7]
.Ltmp150:
	@DEBUG_VALUE: sha256_read:i <- 2
	ldrb	r3, [r0, #19]
	strb	r3, [r1, #8]
	ldrh	r3, [r0, #18]
	strb	r3, [r1, #9]
	ldr	r3, [r0, #16]
	lsrs	r3, r3, #8
	strb	r3, [r1, #10]
	ldr	r3, [r0, #16]
	strb	r3, [r1, #11]
.Ltmp151:
	@DEBUG_VALUE: sha256_read:i <- 3
	ldrb	r3, [r0, #23]
	strb	r3, [r1, #12]
	ldrh	r3, [r0, #22]
	strb	r3, [r1, #13]
	ldr	r3, [r0, #20]
	lsrs	r3, r3, #8
	strb	r3, [r1, #14]
	ldr	r3, [r0, #20]
	strb	r3, [r1, #15]
.Ltmp152:
	@DEBUG_VALUE: sha256_read:i <- 4
	ldrb	r3, [r0, #27]
	strb	r3, [r1, #16]
	ldrh	r3, [r0, #26]
	strb	r3, [r1, #17]
	ldr	r3, [r0, #24]
	lsrs	r3, r3, #8
	strb	r3, [r1, #18]
	ldr	r3, [r0, #24]
	strb	r3, [r1, #19]
.Ltmp153:
	@DEBUG_VALUE: sha256_read:i <- 5
	ldrb	r3, [r0, #31]
	strb	r3, [r1, #20]
	ldrh	r3, [r0, #30]
	strb	r3, [r1, #21]
	ldr	r3, [r0, #28]
	lsrs	r3, r3, #8
	strb	r3, [r1, #22]
	ldr	r3, [r0, #28]
	strb	r3, [r1, #23]
.Ltmp154:
	@DEBUG_VALUE: sha256_read:i <- 6
	ldrb	r3, [r2, #27]
	strb	r3, [r1, #24]
	ldrh	r3, [r0, #34]
	strb	r3, [r1, #25]
	ldr	r3, [r0, #32]
	lsrs	r3, r3, #8
	strb	r3, [r1, #26]
	ldr	r3, [r0, #32]
	strb	r3, [r1, #27]
.Ltmp155:
	@DEBUG_VALUE: sha256_read:i <- 7
	ldrb	r2, [r2, #31]
	strb	r2, [r1, #28]
	ldrh	r2, [r0, #38]
	strb	r2, [r1, #29]
	ldr	r2, [r0, #36]
	lsrs	r2, r2, #8
	strb	r2, [r1, #30]
	ldr	r0, [r0, #36]
.Ltmp156:
	@DEBUG_VALUE: sha256_read:buff <- [DW_OP_LLVM_entry_value 1] $r0
	strb	r0, [r1, #31]
.Ltmp157:
	@DEBUG_VALUE: sha256_read:i <- 8
	bx	lr
.Ltmp158:
.Lfunc_end4:
	.size	sha256_read, .Lfunc_end4-sha256_read
	.cfi_endproc
	.cantunwind
	.fnend
                                        @ -- End function
	.section	.text.sha256_read_hex,"ax",%progbits
	.hidden	sha256_read_hex                 @ -- Begin function sha256_read_hex
	.globl	sha256_read_hex
	.p2align	2
	.type	sha256_read_hex,%function
	.code	16                              @ @sha256_read_hex
	.thumb_func
sha256_read_hex:
.Lfunc_begin5:
	.fnstart
	.cfi_startproc
@ %bb.0:
	@DEBUG_VALUE: sha256_read_hex:buff <- $r0
	@DEBUG_VALUE: sha256_read_hex:hex <- $r1
	.save	{r4, r5, r6, r7, lr}
	push	{r4, r5, r6, r7, lr}
	.cfi_def_cfa_offset 20
	.cfi_offset lr, -4
	.cfi_offset r7, -8
	.cfi_offset r6, -12
	.cfi_offset r5, -16
	.cfi_offset r4, -20
	.pad	#36
	sub	sp, #36
	.cfi_def_cfa_offset 56
	str	r1, [sp]                        @ 4-byte Spill
.Ltmp159:
	@DEBUG_VALUE: sha256_read:i <- 0
	@DEBUG_VALUE: sha256_read:hash <- [DW_OP_plus_uconst 4, DW_OP_stack_value] $sp
	@DEBUG_VALUE: sha256_read:buff <- $r0
	@DEBUG_VALUE: sha256_read_hex:hex <- [$sp+0]
	ldr	r3, [r0, #8]
	lsrs	r4, r3, #24
	add	r2, sp, #4
	strb	r4, [r2]
	lsrs	r4, r3, #16
	strb	r4, [r2, #1]
	lsrs	r4, r3, #8
	strb	r4, [r2, #2]
	strb	r3, [r2, #3]
.Ltmp160:
	@DEBUG_VALUE: sha256_read:i <- 1
	ldr	r3, [r0, #12]
	lsrs	r4, r3, #24
	strb	r4, [r2, #4]
	lsrs	r4, r3, #16
	strb	r4, [r2, #5]
	lsrs	r4, r3, #8
	strb	r4, [r2, #6]
	strb	r3, [r2, #7]
.Ltmp161:
	@DEBUG_VALUE: sha256_read:i <- 2
	ldr	r3, [r0, #16]
	lsrs	r4, r3, #24
	strb	r4, [r2, #8]
	lsrs	r4, r3, #16
	strb	r4, [r2, #9]
	lsrs	r4, r3, #8
	strb	r4, [r2, #10]
	strb	r3, [r2, #11]
.Ltmp162:
	@DEBUG_VALUE: sha256_read:i <- 3
	ldr	r3, [r0, #20]
	lsrs	r4, r3, #24
	strb	r4, [r2, #12]
	lsrs	r4, r3, #16
	strb	r4, [r2, #13]
	lsrs	r4, r3, #8
	strb	r4, [r2, #14]
	strb	r3, [r2, #15]
.Ltmp163:
	@DEBUG_VALUE: sha256_read:i <- 4
	ldr	r3, [r0, #24]
	lsrs	r4, r3, #24
	strb	r4, [r2, #16]
	lsrs	r4, r3, #16
	strb	r4, [r2, #17]
	lsrs	r4, r3, #8
	strb	r4, [r2, #18]
	strb	r3, [r2, #19]
.Ltmp164:
	@DEBUG_VALUE: sha256_read:i <- 5
	ldr	r3, [r0, #28]
	lsrs	r4, r3, #24
	strb	r4, [r2, #20]
	lsrs	r4, r3, #16
	strb	r4, [r2, #21]
	lsrs	r4, r3, #8
	strb	r4, [r2, #22]
	strb	r3, [r2, #23]
.Ltmp165:
	@DEBUG_VALUE: sha256_read:i <- 6
	ldr	r3, [r0, #32]
	lsrs	r4, r3, #24
	strb	r4, [r2, #24]
	lsrs	r4, r3, #16
	strb	r4, [r2, #25]
	lsrs	r4, r3, #8
	strb	r4, [r2, #26]
	strb	r3, [r2, #27]
.Ltmp166:
	@DEBUG_VALUE: sha256_read:i <- 7
	ldr	r0, [r0, #36]
.Ltmp167:
	@DEBUG_VALUE: sha256_read_hex:buff <- [DW_OP_LLVM_entry_value 1] $r0
	lsrs	r3, r0, #24
	strb	r3, [r2, #28]
	lsrs	r3, r0, #16
	strb	r3, [r2, #29]
	lsrs	r3, r0, #8
	strb	r3, [r2, #30]
	strb	r0, [r2, #31]
	movs	r0, #0
	@DEBUG_VALUE: bin_to_hex:i <- 0
	@DEBUG_VALUE: bin_to_hex:out <- undef
	@DEBUG_VALUE: bin_to_hex:len <- 32
	@DEBUG_VALUE: bin_to_hex:data <- [DW_OP_plus_uconst 4, DW_OP_stack_value] $sp
.Ltmp168:
	@DEBUG_VALUE: sha256_read:i <- 8
	ldr	r2, .LCPI5_0
	mov	r1, r0
.Ltmp169:
.LBB5_1:                                @ =>This Inner Loop Header: Depth=1
	@DEBUG_VALUE: bin_to_hex:data <- [DW_OP_plus_uconst 4, DW_OP_stack_value] $sp
	@DEBUG_VALUE: bin_to_hex:len <- 32
	@DEBUG_VALUE: sha256_read_hex:buff <- [DW_OP_LLVM_entry_value 1] $r0
	@DEBUG_VALUE: sha256_read_hex:hex <- [$sp+0]
	add	r4, sp, #4
.Ltmp170:
	@DEBUG_VALUE: bin_to_hex:i <- $r1
	adds	r5, r4, r1
	ldrb	r7, [r4, r1]
.Ltmp171:
	@DEBUG_VALUE: c <- undef
	lsrs	r4, r7, #4
	ldrb	r6, [r2, r4]
	ldr	r3, [sp]                        @ 4-byte Reload
	adds	r4, r3, r0
	strb	r6, [r3, r0]
	movs	r6, #15
	ands	r7, r6
	ldrb	r7, [r2, r7]
	strb	r7, [r4, #1]
.Ltmp172:
	@DEBUG_VALUE: bin_to_hex:i <- [DW_OP_constu 1, DW_OP_or, DW_OP_stack_value] $r1
	ldrb	r7, [r5, #1]
	lsrs	r3, r7, #4
	ldrb	r3, [r2, r3]
	strb	r3, [r4, #2]
	ands	r7, r6
	ldrb	r3, [r2, r7]
	strb	r3, [r4, #3]
.Ltmp173:
	@DEBUG_VALUE: bin_to_hex:i <- [DW_OP_constu 2, DW_OP_or, DW_OP_stack_value] $r1
	ldrb	r3, [r5, #2]
	lsrs	r7, r3, #4
	ldrb	r7, [r2, r7]
	strb	r7, [r4, #4]
	ands	r3, r6
	ldrb	r3, [r2, r3]
	strb	r3, [r4, #5]
.Ltmp174:
	@DEBUG_VALUE: bin_to_hex:i <- [DW_OP_constu 3, DW_OP_or, DW_OP_stack_value] $r1
	ldrb	r3, [r5, #3]
	lsrs	r7, r3, #4
	ldrb	r7, [r2, r7]
	strb	r7, [r4, #6]
	ands	r3, r6
	ldrb	r3, [r2, r3]
	strb	r3, [r4, #7]
.Ltmp175:
	@DEBUG_VALUE: bin_to_hex:i <- [DW_OP_constu 4, DW_OP_or, DW_OP_stack_value] $r1
	ldrb	r3, [r5, #4]
	lsrs	r7, r3, #4
	ldrb	r7, [r2, r7]
	strb	r7, [r4, #8]
	ands	r3, r6
	ldrb	r3, [r2, r3]
	strb	r3, [r4, #9]
.Ltmp176:
	@DEBUG_VALUE: bin_to_hex:i <- [DW_OP_constu 5, DW_OP_or, DW_OP_stack_value] $r1
	ldrb	r3, [r5, #5]
	lsrs	r7, r3, #4
	ldrb	r7, [r2, r7]
	strb	r7, [r4, #10]
	ands	r3, r6
	ldrb	r3, [r2, r3]
	strb	r3, [r4, #11]
.Ltmp177:
	@DEBUG_VALUE: bin_to_hex:i <- [DW_OP_constu 6, DW_OP_or, DW_OP_stack_value] $r1
	ldrb	r3, [r5, #6]
	lsrs	r7, r3, #4
	ldrb	r7, [r2, r7]
	strb	r7, [r4, #12]
	ands	r3, r6
	ldrb	r3, [r2, r3]
	strb	r3, [r4, #13]
.Ltmp178:
	@DEBUG_VALUE: bin_to_hex:i <- [DW_OP_constu 7, DW_OP_or, DW_OP_stack_value] $r1
	ldrb	r3, [r5, #7]
	lsrs	r7, r3, #4
	ldrb	r7, [r2, r7]
	strb	r7, [r4, #14]
	ands	r3, r6
	ldrb	r3, [r2, r3]
	strb	r3, [r4, #15]
.Ltmp179:
	@DEBUG_VALUE: bin_to_hex:i <- [DW_OP_constu 8, DW_OP_or, DW_OP_stack_value] $r1
	ldrb	r3, [r5, #8]
	lsrs	r7, r3, #4
	ldrb	r7, [r2, r7]
	strb	r7, [r4, #16]
	ands	r3, r6
	ldrb	r3, [r2, r3]
	strb	r3, [r4, #17]
.Ltmp180:
	@DEBUG_VALUE: bin_to_hex:i <- [DW_OP_constu 9, DW_OP_or, DW_OP_stack_value] $r1
	ldrb	r3, [r5, #9]
	lsrs	r7, r3, #4
	ldrb	r7, [r2, r7]
	strb	r7, [r4, #18]
	ands	r3, r6
	ldrb	r3, [r2, r3]
	strb	r3, [r4, #19]
.Ltmp181:
	@DEBUG_VALUE: bin_to_hex:i <- [DW_OP_constu 10, DW_OP_or, DW_OP_stack_value] $r1
	ldrb	r3, [r5, #10]
	lsrs	r7, r3, #4
	ldrb	r7, [r2, r7]
	strb	r7, [r4, #20]
	ands	r3, r6
	ldrb	r3, [r2, r3]
	strb	r3, [r4, #21]
.Ltmp182:
	@DEBUG_VALUE: bin_to_hex:i <- [DW_OP_constu 11, DW_OP_or, DW_OP_stack_value] $r1
	ldrb	r3, [r5, #11]
	lsrs	r7, r3, #4
	ldrb	r7, [r2, r7]
	strb	r7, [r4, #22]
	ands	r3, r6
	ldrb	r3, [r2, r3]
	strb	r3, [r4, #23]
.Ltmp183:
	@DEBUG_VALUE: bin_to_hex:i <- [DW_OP_constu 12, DW_OP_or, DW_OP_stack_value] $r1
	ldrb	r3, [r5, #12]
	lsrs	r7, r3, #4
	ldrb	r7, [r2, r7]
	strb	r7, [r4, #24]
	ands	r3, r6
	ldrb	r3, [r2, r3]
	strb	r3, [r4, #25]
.Ltmp184:
	@DEBUG_VALUE: bin_to_hex:i <- [DW_OP_constu 13, DW_OP_or, DW_OP_stack_value] $r1
	ldrb	r3, [r5, #13]
	lsrs	r7, r3, #4
	ldrb	r7, [r2, r7]
	strb	r7, [r4, #26]
	ands	r3, r6
	ldrb	r3, [r2, r3]
	strb	r3, [r4, #27]
.Ltmp185:
	@DEBUG_VALUE: bin_to_hex:i <- [DW_OP_constu 14, DW_OP_or, DW_OP_stack_value] $r1
	ldrb	r3, [r5, #14]
	lsrs	r7, r3, #4
	ldrb	r7, [r2, r7]
	strb	r7, [r4, #28]
	ands	r3, r6
	ldrb	r3, [r2, r3]
	strb	r3, [r4, #29]
.Ltmp186:
	@DEBUG_VALUE: bin_to_hex:i <- [DW_OP_constu 15, DW_OP_or, DW_OP_stack_value] $r1
	ldrb	r3, [r5, #15]
	lsrs	r5, r3, #4
	ldrb	r5, [r2, r5]
	strb	r5, [r4, #30]
	ands	r3, r6
	ldrb	r3, [r2, r3]
	strb	r3, [r4, #31]
.Ltmp187:
	adds	r1, #16
.Ltmp188:
	@DEBUG_VALUE: bin_to_hex:i <- $r1
	adds	r0, #32
.Ltmp189:
	cmp	r0, #64
	bne	.LBB5_1
.Ltmp190:
@ %bb.2:
	@DEBUG_VALUE: sha256_read_hex:buff <- [DW_OP_LLVM_entry_value 1] $r0
	@DEBUG_VALUE: sha256_read_hex:hex <- [$sp+0]
	add	sp, #36
	pop	{r4, r5, r6, r7, pc}
.Ltmp191:
	.p2align	2
@ %bb.3:
.LCPI5_0:
	.long	.L.str
.Lfunc_end5:
	.size	sha256_read_hex, .Lfunc_end5-sha256_read_hex
	.cfi_endproc
	.cantunwind
	.fnend
                                        @ -- End function
	.section	.text.sha256_easy_hash,"ax",%progbits
	.hidden	sha256_easy_hash                @ -- Begin function sha256_easy_hash
	.globl	sha256_easy_hash
	.p2align	2
	.type	sha256_easy_hash,%function
	.code	16                              @ @sha256_easy_hash
	.thumb_func
sha256_easy_hash:
.Lfunc_begin6:
	.fnstart
	.cfi_startproc
@ %bb.0:
	@DEBUG_VALUE: sha256_easy_hash:data <- $r0
	@DEBUG_VALUE: sha256_easy_hash:size <- $r1
	@DEBUG_VALUE: sha256_easy_hash:hash <- $r2
	.save	{r4, r5, r6, r7, lr}
	push	{r4, r5, r6, r7, lr}
	.cfi_def_cfa_offset 20
	.cfi_offset lr, -4
	.cfi_offset r7, -8
	.cfi_offset r6, -12
	.cfi_offset r5, -16
	.cfi_offset r4, -20
	.pad	#196
	sub	sp, #196
	.cfi_def_cfa_offset 216
	mov	r4, r2
.Ltmp192:
	@DEBUG_VALUE: sha256_easy_hash:hash <- $r4
	mov	r5, r1
.Ltmp193:
	@DEBUG_VALUE: sha256_easy_hash:size <- $r5
	mov	r6, r0
.Ltmp194:
	@DEBUG_VALUE: sha256_easy_hash:data <- $r6
	add	r1, sp, #16
.Ltmp195:
	adds	r1, #96
.Ltmp196:
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 16, DW_OP_deref] $sp
	ldr	r0, .LCPI6_0
.Ltmp197:
	@DEBUG_VALUE: sha256_init:buff <- [DW_OP_plus_uconst 16, DW_OP_stack_value] $sp
	str	r0, [sp, #24]
	ldr	r0, .LCPI6_1
.Ltmp198:
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 16, DW_OP_plus_uconst 8, DW_OP_deref, DW_OP_LLVM_fragment 64 32] $sp
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 16, DW_OP_plus_uconst 12, DW_OP_deref, DW_OP_LLVM_fragment 96 800] $sp
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 16, DW_OP_deref, DW_OP_LLVM_fragment 0 64] $sp
	str	r0, [sp, #28]
	ldr	r0, .LCPI6_2
.Ltmp199:
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 16, DW_OP_plus_uconst 12, DW_OP_deref, DW_OP_LLVM_fragment 96 32] $sp
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 16, DW_OP_plus_uconst 16, DW_OP_deref, DW_OP_LLVM_fragment 128 768] $sp
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 16, DW_OP_deref, DW_OP_LLVM_fragment 0 96] $sp
	str	r0, [sp, #32]
	ldr	r0, .LCPI6_3
.Ltmp200:
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 16, DW_OP_plus_uconst 16, DW_OP_deref, DW_OP_LLVM_fragment 128 32] $sp
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 16, DW_OP_plus_uconst 20, DW_OP_deref, DW_OP_LLVM_fragment 160 736] $sp
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 16, DW_OP_deref, DW_OP_LLVM_fragment 0 128] $sp
	str	r0, [sp, #36]
	ldr	r0, .LCPI6_4
.Ltmp201:
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 16, DW_OP_plus_uconst 20, DW_OP_deref, DW_OP_LLVM_fragment 160 32] $sp
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 16, DW_OP_plus_uconst 24, DW_OP_deref, DW_OP_LLVM_fragment 192 704] $sp
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 16, DW_OP_deref, DW_OP_LLVM_fragment 0 160] $sp
	str	r0, [sp, #40]
	ldr	r0, .LCPI6_5
.Ltmp202:
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 16, DW_OP_plus_uconst 24, DW_OP_deref, DW_OP_LLVM_fragment 192 32] $sp
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 16, DW_OP_plus_uconst 28, DW_OP_deref, DW_OP_LLVM_fragment 224 672] $sp
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 16, DW_OP_deref, DW_OP_LLVM_fragment 0 192] $sp
	str	r0, [sp, #44]
	ldr	r0, .LCPI6_6
.Ltmp203:
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 16, DW_OP_plus_uconst 28, DW_OP_deref, DW_OP_LLVM_fragment 224 32] $sp
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 16, DW_OP_plus_uconst 32, DW_OP_deref, DW_OP_LLVM_fragment 256 640] $sp
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 16, DW_OP_deref, DW_OP_LLVM_fragment 0 224] $sp
	str	r0, [sp, #48]
	ldr	r0, .LCPI6_7
.Ltmp204:
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 16, DW_OP_plus_uconst 32, DW_OP_deref, DW_OP_LLVM_fragment 256 32] $sp
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 16, DW_OP_plus_uconst 36, DW_OP_deref, DW_OP_LLVM_fragment 288 608] $sp
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 16, DW_OP_deref, DW_OP_LLVM_fragment 0 256] $sp
	str	r0, [sp, #52]
	movs	r7, #0
.Ltmp205:
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 16, DW_OP_plus_uconst 8, DW_OP_deref, DW_OP_LLVM_fragment 64 832] $sp
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_LLVM_fragment 0 64] 0
	strb	r7, [r1, #8]
.Ltmp206:
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 8, DW_OP_deref, DW_OP_stack_value, DW_OP_LLVM_fragment 832 8] $r1
	@DEBUG_VALUE: sha256_update:ptr <- undef
	@DEBUG_VALUE: sha256_update:size <- $r5
	@DEBUG_VALUE: sha256_update:data <- undef
	@DEBUG_VALUE: sha256_update:buff <- [DW_OP_plus_uconst 16, DW_OP_stack_value] $sp
	@DEBUG_VALUE: tmp_chunk <- [DW_OP_plus_uconst 132, DW_OP_deref] $sp
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 16, DW_OP_plus_uconst 105, DW_OP_deref, DW_OP_LLVM_fragment 840 56] $sp
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 16, DW_OP_plus_uconst 8, DW_OP_deref, DW_OP_LLVM_fragment 64 768] $sp
	str	r7, [sp, #20]
	str	r5, [sp, #16]
.Ltmp207:
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 16, DW_OP_deref, DW_OP_LLVM_fragment 0 64] $sp
	cmp	r5, #64
	str	r1, [sp, #8]                    @ 4-byte Spill
.Ltmp208:
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 8, DW_OP_plus_uconst 8, DW_OP_deref, DW_OP_stack_value, DW_OP_LLVM_fragment 832 8] [$sp+0]
	blo	.LBB6_13
.Ltmp209:
@ %bb.1:
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 8, DW_OP_plus_uconst 8, DW_OP_deref, DW_OP_stack_value, DW_OP_LLVM_fragment 832 8] [$sp+0]
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 16, DW_OP_plus_uconst 8, DW_OP_deref, DW_OP_LLVM_fragment 64 768] $sp
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 16, DW_OP_plus_uconst 105, DW_OP_deref, DW_OP_LLVM_fragment 840 56] $sp
	@DEBUG_VALUE: tmp_chunk <- [DW_OP_plus_uconst 132, DW_OP_deref] $sp
	@DEBUG_VALUE: sha256_update:buff <- [DW_OP_plus_uconst 16, DW_OP_stack_value] $sp
	@DEBUG_VALUE: sha256_update:size <- $r5
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 16, DW_OP_deref, DW_OP_LLVM_fragment 0 64] $sp
	@DEBUG_VALUE: sha256_easy_hash:data <- $r6
	@DEBUG_VALUE: sha256_easy_hash:size <- $r5
	@DEBUG_VALUE: sha256_easy_hash:hash <- $r4
	add	r0, sp, #132
	str	r0, [sp]                        @ 4-byte Spill
	movs	r2, #64
.Ltmp210:
	mov	r1, r6
	bl	__aeabi_memcpy
.Ltmp211:
	@DEBUG_VALUE: tmp_chunk <- [DW_OP_plus_uconst 132, DW_OP_deref] $sp
	str	r6, [sp, #12]                   @ 4-byte Spill
.Ltmp212:
	@DEBUG_VALUE: sha256_easy_hash:data <- [DW_OP_plus_uconst 12] [$sp+0]
	adds	r6, #64
.Ltmp213:
	@DEBUG_VALUE: sha256_update:ptr <- $r6
	str	r5, [sp, #4]                    @ 4-byte Spill
.Ltmp214:
	@DEBUG_VALUE: sha256_easy_hash:size <- [DW_OP_plus_uconst 4] [$sp+0]
	subs	r5, #64
.Ltmp215:
	@DEBUG_VALUE: sha256_update:size <- $r5
	ldr	r0, [sp, #8]                    @ 4-byte Reload
.Ltmp216:
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 8, DW_OP_deref, DW_OP_stack_value, DW_OP_LLVM_fragment 832 8] $r0
	strb	r7, [r0, #8]
	add	r0, sp, #16
.Ltmp217:
	ldr	r1, [sp]                        @ 4-byte Reload
	bl	sha256_calc_chunk
.Ltmp218:
	cmp	r5, #64
.Ltmp219:
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 8, DW_OP_deref_size 4, DW_OP_plus_uconst 8, DW_OP_deref, DW_OP_stack_value, DW_OP_LLVM_fragment 832 8] $sp
	blo	.LBB6_13
.Ltmp220:
@ %bb.2:
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 8, DW_OP_deref_size 4, DW_OP_plus_uconst 8, DW_OP_deref, DW_OP_stack_value, DW_OP_LLVM_fragment 832 8] $sp
	@DEBUG_VALUE: sha256_easy_hash:size <- [DW_OP_plus_uconst 4] [$sp+0]
	@DEBUG_VALUE: sha256_update:ptr <- $r6
	@DEBUG_VALUE: sha256_easy_hash:data <- [DW_OP_plus_uconst 12] [$sp+0]
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 16, DW_OP_plus_uconst 8, DW_OP_deref, DW_OP_LLVM_fragment 64 768] $sp
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 16, DW_OP_plus_uconst 105, DW_OP_deref, DW_OP_LLVM_fragment 840 56] $sp
	@DEBUG_VALUE: sha256_update:buff <- [DW_OP_plus_uconst 16, DW_OP_stack_value] $sp
	@DEBUG_VALUE: sha256_update:size <- $r5
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 16, DW_OP_deref, DW_OP_LLVM_fragment 0 64] $sp
	@DEBUG_VALUE: sha256_easy_hash:hash <- $r4
	ldr	r0, [sp, #4]                    @ 4-byte Reload
.Ltmp221:
	@DEBUG_VALUE: sha256_easy_hash:size <- $r0
	subs	r0, #128
.Ltmp222:
	@DEBUG_VALUE: sha256_easy_hash:size <- [DW_OP_LLVM_entry_value 1] $r1
	str	r0, [sp, #4]                    @ 4-byte Spill
	lsrs	r0, r0, #6
	movs	r1, #3
	bl	__aeabi_uidivmod
.Ltmp223:
	adds	r0, r1, #1
	cmp	r0, #3
	beq	.LBB6_4
.Ltmp224:
@ %bb.3:
	@DEBUG_VALUE: sha256_easy_hash:size <- [DW_OP_LLVM_entry_value 1] $r1
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 8, DW_OP_deref_size 4, DW_OP_plus_uconst 8, DW_OP_deref, DW_OP_stack_value, DW_OP_LLVM_fragment 832 8] $sp
	@DEBUG_VALUE: sha256_update:ptr <- $r6
	@DEBUG_VALUE: sha256_easy_hash:data <- [DW_OP_plus_uconst 12] [$sp+0]
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 16, DW_OP_plus_uconst 8, DW_OP_deref, DW_OP_LLVM_fragment 64 768] $sp
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 16, DW_OP_plus_uconst 105, DW_OP_deref, DW_OP_LLVM_fragment 840 56] $sp
	@DEBUG_VALUE: sha256_update:buff <- [DW_OP_plus_uconst 16, DW_OP_stack_value] $sp
	@DEBUG_VALUE: sha256_update:size <- $r5
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 16, DW_OP_deref, DW_OP_LLVM_fragment 0 64] $sp
	@DEBUG_VALUE: sha256_easy_hash:hash <- $r4
	mov	r7, r0
.Ltmp225:
.LBB6_4:
	@DEBUG_VALUE: sha256_easy_hash:size <- [DW_OP_LLVM_entry_value 1] $r1
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 8, DW_OP_deref_size 4, DW_OP_plus_uconst 8, DW_OP_deref, DW_OP_stack_value, DW_OP_LLVM_fragment 832 8] $sp
	@DEBUG_VALUE: sha256_update:ptr <- $r6
	@DEBUG_VALUE: sha256_easy_hash:data <- [DW_OP_plus_uconst 12] [$sp+0]
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 16, DW_OP_plus_uconst 8, DW_OP_deref, DW_OP_LLVM_fragment 64 768] $sp
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 16, DW_OP_plus_uconst 105, DW_OP_deref, DW_OP_LLVM_fragment 840 56] $sp
	@DEBUG_VALUE: sha256_update:buff <- [DW_OP_plus_uconst 16, DW_OP_stack_value] $sp
	@DEBUG_VALUE: sha256_update:size <- $r5
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 16, DW_OP_deref, DW_OP_LLVM_fragment 0 64] $sp
	@DEBUG_VALUE: sha256_easy_hash:hash <- $r4
	cmp	r0, #3
	beq	.LBB6_11
.Ltmp226:
@ %bb.5:
	@DEBUG_VALUE: sha256_easy_hash:size <- [DW_OP_LLVM_entry_value 1] $r1
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 8, DW_OP_deref_size 4, DW_OP_plus_uconst 8, DW_OP_deref, DW_OP_stack_value, DW_OP_LLVM_fragment 832 8] $sp
	@DEBUG_VALUE: sha256_update:ptr <- $r6
	@DEBUG_VALUE: sha256_easy_hash:data <- [DW_OP_plus_uconst 12] [$sp+0]
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 16, DW_OP_plus_uconst 8, DW_OP_deref, DW_OP_LLVM_fragment 64 768] $sp
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 16, DW_OP_plus_uconst 105, DW_OP_deref, DW_OP_LLVM_fragment 840 56] $sp
	@DEBUG_VALUE: sha256_update:buff <- [DW_OP_plus_uconst 16, DW_OP_stack_value] $sp
	@DEBUG_VALUE: sha256_update:size <- $r5
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 16, DW_OP_deref, DW_OP_LLVM_fragment 0 64] $sp
	@DEBUG_VALUE: sha256_easy_hash:hash <- $r4
	str	r4, [sp]                        @ 4-byte Spill
.Ltmp227:
	@DEBUG_VALUE: sha256_easy_hash:hash <- [$sp+0]
	movs	r4, #0
.Ltmp228:
.LBB6_6:                                @ =>This Inner Loop Header: Depth=1
	@DEBUG_VALUE: sha256_easy_hash:hash <- [$sp+0]
	@DEBUG_VALUE: sha256_easy_hash:size <- [DW_OP_LLVM_entry_value 1] $r1
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 8, DW_OP_deref_size 4, DW_OP_plus_uconst 8, DW_OP_deref, DW_OP_stack_value, DW_OP_LLVM_fragment 832 8] $sp
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 16, DW_OP_plus_uconst 8, DW_OP_deref, DW_OP_LLVM_fragment 64 768] $sp
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 16, DW_OP_plus_uconst 105, DW_OP_deref, DW_OP_LLVM_fragment 840 56] $sp
	@DEBUG_VALUE: sha256_update:buff <- [DW_OP_plus_uconst 16, DW_OP_stack_value] $sp
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 16, DW_OP_deref, DW_OP_LLVM_fragment 0 64] $sp
	@DEBUG_VALUE: sha256_update:size <- [DW_OP_LLVM_arg 0, DW_OP_consts 128, DW_OP_div, DW_OP_consts 18446744073709551488, DW_OP_mul, DW_OP_consts 18446744073709551552, DW_OP_LLVM_arg 0, DW_OP_plus, DW_OP_plus, DW_OP_stack_value] undef
	@DEBUG_VALUE: sha256_update:ptr <- [DW_OP_LLVM_arg 0, DW_OP_consts 128, DW_OP_div, DW_OP_consts 128, DW_OP_mul, DW_OP_consts 64, DW_OP_LLVM_arg 1, DW_OP_plus_uconst 12, DW_OP_deref, DW_OP_plus, DW_OP_plus, DW_OP_stack_value] $r4, $sp
	ldr	r0, [sp, #12]                   @ 4-byte Reload
.Ltmp229:
	@DEBUG_VALUE: sha256_easy_hash:data <- $r0
	@DEBUG_VALUE: sha256_update:ptr <- [DW_OP_LLVM_arg 0, DW_OP_consts 128, DW_OP_div, DW_OP_consts 128, DW_OP_mul, DW_OP_consts 64, DW_OP_LLVM_arg 1, DW_OP_plus, DW_OP_plus, DW_OP_stack_value] $r4, $r0
	adds	r6, r0, r4
.Ltmp230:
	@DEBUG_VALUE: sha256_update:ptr <- [DW_OP_LLVM_arg 0, DW_OP_consts 128, DW_OP_div, DW_OP_consts 128, DW_OP_mul, DW_OP_consts 64, DW_OP_LLVM_arg 1, DW_OP_plus_uconst 12, DW_OP_deref, DW_OP_plus, DW_OP_plus, DW_OP_stack_value] $r4, $sp
	mov	r1, r6
	adds	r1, #64
	add	r0, sp, #16
.Ltmp231:
	@DEBUG_VALUE: sha256_easy_hash:data <- [DW_OP_LLVM_entry_value 1] $r0
	bl	sha256_calc_chunk
.Ltmp232:
	@DEBUG_VALUE: sha256_update:ptr <- [DW_OP_LLVM_arg 0, DW_OP_consts 128, DW_OP_div, DW_OP_consts 128, DW_OP_mul, DW_OP_consts 128, DW_OP_LLVM_arg 1, DW_OP_plus_uconst 12, DW_OP_deref, DW_OP_plus, DW_OP_plus, DW_OP_stack_value] $r4, $sp
	@DEBUG_VALUE: sha256_update:size <- [DW_OP_constu 64, DW_OP_minus, DW_OP_stack_value] $r4
	adds	r6, #128
	cmp	r7, #1
	beq	.LBB6_9
.Ltmp233:
@ %bb.7:                                @   in Loop: Header=BB6_6 Depth=1
	@DEBUG_VALUE: sha256_update:size <- [DW_OP_constu 64, DW_OP_minus, DW_OP_stack_value] $r4
	@DEBUG_VALUE: sha256_update:ptr <- [DW_OP_LLVM_arg 0, DW_OP_consts 128, DW_OP_div, DW_OP_consts 128, DW_OP_mul, DW_OP_consts 128, DW_OP_LLVM_arg 1, DW_OP_plus_uconst 12, DW_OP_deref, DW_OP_plus, DW_OP_plus, DW_OP_stack_value] $r4, $sp
	@DEBUG_VALUE: sha256_easy_hash:hash <- [$sp+0]
	@DEBUG_VALUE: sha256_easy_hash:size <- [DW_OP_LLVM_entry_value 1] $r1
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 8, DW_OP_deref_size 4, DW_OP_plus_uconst 8, DW_OP_deref, DW_OP_stack_value, DW_OP_LLVM_fragment 832 8] $sp
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 16, DW_OP_plus_uconst 8, DW_OP_deref, DW_OP_LLVM_fragment 64 768] $sp
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 16, DW_OP_plus_uconst 105, DW_OP_deref, DW_OP_LLVM_fragment 840 56] $sp
	@DEBUG_VALUE: sha256_update:buff <- [DW_OP_plus_uconst 16, DW_OP_stack_value] $sp
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 16, DW_OP_deref, DW_OP_LLVM_fragment 0 64] $sp
	@DEBUG_VALUE: sha256_update:size <- [DW_OP_constu 64, DW_OP_minus, DW_OP_stack_value] $r4
	@DEBUG_VALUE: sha256_update:ptr <- [DW_OP_LLVM_arg 0, DW_OP_consts 128, DW_OP_div, DW_OP_consts 128, DW_OP_mul, DW_OP_consts 128, DW_OP_LLVM_arg 1, DW_OP_plus_uconst 12, DW_OP_deref, DW_OP_plus, DW_OP_plus, DW_OP_stack_value] $r4, $sp
	add	r0, sp, #16
.Ltmp234:
	mov	r1, r6
	bl	sha256_calc_chunk
.Ltmp235:
	@DEBUG_VALUE: sha256_update:ptr <- [DW_OP_LLVM_arg 0, DW_OP_consts 128, DW_OP_div, DW_OP_consts 128, DW_OP_mul, DW_OP_consts 192, DW_OP_LLVM_arg 1, DW_OP_plus_uconst 12, DW_OP_deref, DW_OP_plus, DW_OP_plus, DW_OP_stack_value] $r4, $sp
	@DEBUG_VALUE: sha256_update:size <- [DW_OP_LLVM_arg 0, DW_OP_consts 128, DW_OP_div, DW_OP_consts 18446744073709551488, DW_OP_mul, DW_OP_consts 18446744073709551424, DW_OP_LLVM_arg 0, DW_OP_plus, DW_OP_plus, DW_OP_stack_value] undef
	adds	r4, #128
.Ltmp236:
	subs	r7, r7, #2
	bne	.LBB6_6
.Ltmp237:
@ %bb.8:
	@DEBUG_VALUE: sha256_easy_hash:hash <- [$sp+0]
	@DEBUG_VALUE: sha256_easy_hash:size <- [DW_OP_LLVM_entry_value 1] $r1
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 8, DW_OP_deref_size 4, DW_OP_plus_uconst 8, DW_OP_deref, DW_OP_stack_value, DW_OP_LLVM_fragment 832 8] $sp
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 16, DW_OP_plus_uconst 8, DW_OP_deref, DW_OP_LLVM_fragment 64 768] $sp
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 16, DW_OP_plus_uconst 105, DW_OP_deref, DW_OP_LLVM_fragment 840 56] $sp
	@DEBUG_VALUE: sha256_update:buff <- [DW_OP_plus_uconst 16, DW_OP_stack_value] $sp
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 16, DW_OP_deref, DW_OP_LLVM_fragment 0 64] $sp
	ldr	r0, [sp, #12]                   @ 4-byte Reload
	adds	r6, r0, r4
	adds	r6, #64
	subs	r5, r5, r4
	b	.LBB6_10
.Ltmp238:
.LBB6_9:
	@DEBUG_VALUE: sha256_update:size <- [DW_OP_constu 64, DW_OP_minus, DW_OP_stack_value] $r4
	@DEBUG_VALUE: sha256_update:ptr <- [DW_OP_LLVM_arg 0, DW_OP_consts 128, DW_OP_div, DW_OP_consts 128, DW_OP_mul, DW_OP_consts 128, DW_OP_LLVM_arg 1, DW_OP_plus_uconst 12, DW_OP_deref, DW_OP_plus, DW_OP_plus, DW_OP_stack_value] $r4, $sp
	@DEBUG_VALUE: sha256_easy_hash:hash <- [$sp+0]
	@DEBUG_VALUE: sha256_easy_hash:size <- [DW_OP_LLVM_entry_value 1] $r1
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 8, DW_OP_deref_size 4, DW_OP_plus_uconst 8, DW_OP_deref, DW_OP_stack_value, DW_OP_LLVM_fragment 832 8] $sp
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 16, DW_OP_plus_uconst 8, DW_OP_deref, DW_OP_LLVM_fragment 64 768] $sp
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 16, DW_OP_plus_uconst 105, DW_OP_deref, DW_OP_LLVM_fragment 840 56] $sp
	@DEBUG_VALUE: sha256_update:buff <- [DW_OP_plus_uconst 16, DW_OP_stack_value] $sp
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 16, DW_OP_deref, DW_OP_LLVM_fragment 0 64] $sp
	ldr	r0, [sp, #4]                    @ 4-byte Reload
	subs	r5, r0, r4
.Ltmp239:
.LBB6_10:
	@DEBUG_VALUE: sha256_easy_hash:hash <- [$sp+0]
	@DEBUG_VALUE: sha256_easy_hash:size <- [DW_OP_LLVM_entry_value 1] $r1
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 8, DW_OP_deref_size 4, DW_OP_plus_uconst 8, DW_OP_deref, DW_OP_stack_value, DW_OP_LLVM_fragment 832 8] $sp
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 16, DW_OP_plus_uconst 8, DW_OP_deref, DW_OP_LLVM_fragment 64 768] $sp
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 16, DW_OP_plus_uconst 105, DW_OP_deref, DW_OP_LLVM_fragment 840 56] $sp
	@DEBUG_VALUE: sha256_update:buff <- [DW_OP_plus_uconst 16, DW_OP_stack_value] $sp
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 16, DW_OP_deref, DW_OP_LLVM_fragment 0 64] $sp
	ldr	r4, [sp]                        @ 4-byte Reload
.Ltmp240:
	@DEBUG_VALUE: sha256_easy_hash:hash <- $r4
	@DEBUG_VALUE: sha256_easy_hash:hash <- $r4
.LBB6_11:
	@DEBUG_VALUE: sha256_easy_hash:size <- [DW_OP_LLVM_entry_value 1] $r1
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 8, DW_OP_deref_size 4, DW_OP_plus_uconst 8, DW_OP_deref, DW_OP_stack_value, DW_OP_LLVM_fragment 832 8] $sp
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 16, DW_OP_plus_uconst 8, DW_OP_deref, DW_OP_LLVM_fragment 64 768] $sp
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 16, DW_OP_plus_uconst 105, DW_OP_deref, DW_OP_LLVM_fragment 840 56] $sp
	@DEBUG_VALUE: sha256_update:buff <- [DW_OP_plus_uconst 16, DW_OP_stack_value] $sp
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 16, DW_OP_deref, DW_OP_LLVM_fragment 0 64] $sp
	@DEBUG_VALUE: sha256_easy_hash:hash <- $r4
	ldr	r0, [sp, #4]                    @ 4-byte Reload
	cmp	r0, #128
	blo	.LBB6_13
.Ltmp241:
.LBB6_12:                               @ =>This Inner Loop Header: Depth=1
	@DEBUG_VALUE: sha256_easy_hash:size <- [DW_OP_LLVM_entry_value 1] $r1
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 8, DW_OP_deref_size 4, DW_OP_plus_uconst 8, DW_OP_deref, DW_OP_stack_value, DW_OP_LLVM_fragment 832 8] $sp
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 16, DW_OP_plus_uconst 8, DW_OP_deref, DW_OP_LLVM_fragment 64 768] $sp
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 16, DW_OP_plus_uconst 105, DW_OP_deref, DW_OP_LLVM_fragment 840 56] $sp
	@DEBUG_VALUE: sha256_update:buff <- [DW_OP_plus_uconst 16, DW_OP_stack_value] $sp
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 16, DW_OP_deref, DW_OP_LLVM_fragment 0 64] $sp
	@DEBUG_VALUE: sha256_easy_hash:hash <- $r4
	@DEBUG_VALUE: sha256_update:size <- $r5
	@DEBUG_VALUE: sha256_update:ptr <- $r6
	add	r7, sp, #16
.Ltmp242:
	mov	r0, r7
	mov	r1, r6
	bl	sha256_calc_chunk
.Ltmp243:
	mov	r1, r6
	adds	r1, #64
.Ltmp244:
	@DEBUG_VALUE: sha256_update:ptr <- $r1
	@DEBUG_VALUE: sha256_update:size <- [DW_OP_constu 64, DW_OP_minus, DW_OP_stack_value] $r5
	mov	r0, r7
	bl	sha256_calc_chunk
.Ltmp245:
	@DEBUG_VALUE: sha256_update:ptr <- [DW_OP_plus_uconst 128, DW_OP_stack_value] $r6
	@DEBUG_VALUE: sha256_update:size <- [DW_OP_constu 128, DW_OP_minus, DW_OP_stack_value] $r5
	mov	r1, r6
	adds	r1, #128
	mov	r0, r7
	bl	sha256_calc_chunk
.Ltmp246:
	adds	r6, #192
.Ltmp247:
	@DEBUG_VALUE: sha256_update:ptr <- $r6
	subs	r5, #192
.Ltmp248:
	@DEBUG_VALUE: sha256_update:size <- $r5
	cmp	r5, #63
	bhi	.LBB6_12
.Ltmp249:
.LBB6_13:
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 16, DW_OP_plus_uconst 8, DW_OP_deref, DW_OP_LLVM_fragment 64 768] $sp
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 16, DW_OP_plus_uconst 105, DW_OP_deref, DW_OP_LLVM_fragment 840 56] $sp
	@DEBUG_VALUE: sha256_update:buff <- [DW_OP_plus_uconst 16, DW_OP_stack_value] $sp
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 16, DW_OP_deref, DW_OP_LLVM_fragment 0 64] $sp
	@DEBUG_VALUE: sha256_easy_hash:hash <- $r4
	add	r2, sp, #16
	adds	r2, #40
	ldr	r7, [sp, #8]                    @ 4-byte Reload
	ldrb	r0, [r7, #8]
	adds	r0, r2, r0
	mov	r1, r6
	mov	r6, r2
	mov	r2, r5
	bl	__aeabi_memcpy
.Ltmp250:
	ldrb	r0, [r7, #8]
	adds	r0, r0, r5
	strb	r0, [r7, #8]
.Ltmp251:
	@DEBUG_VALUE: sha256_finalize:buff <- [DW_OP_plus_uconst 16, DW_OP_stack_value] $sp
	uxtb	r0, r0
	movs	r1, #128
	strb	r1, [r6, r0]
	ldrb	r0, [r7, #8]
	adds	r0, r0, #1
	strb	r0, [r7, #8]
	uxtb	r1, r0
	adds	r0, r6, r1
	movs	r2, #64
	subs	r1, r2, r1
	bl	__aeabi_memclr
.Ltmp252:
	ldrb	r0, [r7, #8]
.Ltmp253:
	cmp	r0, #57
.Ltmp254:
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 8, DW_OP_deref, DW_OP_stack_value, DW_OP_LLVM_fragment 832 8] $r7
	blo	.LBB6_15
.Ltmp255:
@ %bb.14:
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 8, DW_OP_deref, DW_OP_stack_value, DW_OP_LLVM_fragment 832 8] $r7
	@DEBUG_VALUE: sha256_finalize:buff <- [DW_OP_plus_uconst 16, DW_OP_stack_value] $sp
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 16, DW_OP_plus_uconst 8, DW_OP_deref, DW_OP_LLVM_fragment 64 768] $sp
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 16, DW_OP_plus_uconst 105, DW_OP_deref, DW_OP_LLVM_fragment 840 56] $sp
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 16, DW_OP_deref, DW_OP_LLVM_fragment 0 64] $sp
	@DEBUG_VALUE: sha256_easy_hash:hash <- $r4
	add	r0, sp, #16
.Ltmp256:
	mov	r1, r6
	bl	sha256_calc_chunk
.Ltmp257:
	movs	r1, #56
	mov	r0, r6
	bl	__aeabi_memclr8
.Ltmp258:
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 16, DW_OP_plus_uconst 40, DW_OP_deref, DW_OP_LLVM_fragment 320 448] $sp
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 16, DW_OP_plus_uconst 96, DW_OP_deref, DW_OP_LLVM_fragment 768 64] $sp
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 16, DW_OP_deref, DW_OP_LLVM_fragment 0 320] $sp
.LBB6_15:
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 8, DW_OP_deref, DW_OP_stack_value, DW_OP_LLVM_fragment 832 8] $r7
	@DEBUG_VALUE: sha256_finalize:buff <- [DW_OP_plus_uconst 16, DW_OP_stack_value] $sp
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 16, DW_OP_plus_uconst 105, DW_OP_deref, DW_OP_LLVM_fragment 840 56] $sp
	@DEBUG_VALUE: sha256_easy_hash:hash <- $r4
	ldr	r0, [sp, #20]
	ldr	r1, [sp, #16]
	lsrs	r2, r1, #29
	lsls	r0, r0, #3
	adds	r0, r0, r2
.Ltmp259:
	@DEBUG_VALUE: sha256_finalize:size <- [DW_OP_LLVM_fragment 32 32] $r0
	lsls	r1, r1, #3
.Ltmp260:
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_LLVM_fragment 776 8] undef
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 16, DW_OP_deref, DW_OP_LLVM_fragment 0 776] $sp
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_LLVM_fragment 784 8] undef
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 16, DW_OP_deref, DW_OP_LLVM_fragment 0 784] $sp
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_LLVM_fragment 792 8] undef
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 16, DW_OP_deref, DW_OP_LLVM_fragment 0 792] $sp
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_LLVM_fragment 800 8] undef
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 16, DW_OP_deref, DW_OP_LLVM_fragment 0 800] $sp
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_LLVM_fragment 808 8] undef
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 16, DW_OP_deref, DW_OP_LLVM_fragment 0 808] $sp
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_LLVM_fragment 816 8] undef
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 16, DW_OP_deref, DW_OP_LLVM_fragment 0 816] $sp
	@DEBUG_VALUE: sha256_finalize:size <- undef
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_LLVM_fragment 824 8] undef
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 16, DW_OP_deref, DW_OP_LLVM_fragment 0 824] $sp
	@DEBUG_VALUE: sha256_finalize:i <- 1
	@DEBUG_VALUE: sha256_finalize:size <- [DW_OP_LLVM_fragment 0 32] $r1
	rev	r1, r1
.Ltmp261:
	rev	r0, r0
.Ltmp262:
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_deref, DW_OP_LLVM_fragment 768 8] $r7
	@DEBUG_VALUE: sha256_easy_hash:buff <- [DW_OP_plus_uconst 16, DW_OP_deref, DW_OP_LLVM_fragment 0 768] $sp
	@DEBUG_VALUE: sha256_finalize:size <- undef
	@DEBUG_VALUE: sha256_finalize:i <- 0
	stm	r7!, {r0, r1}
.Ltmp263:
	add	r0, sp, #16
.Ltmp264:
	mov	r1, r6
	bl	sha256_calc_chunk
.Ltmp265:
	@DEBUG_VALUE: sha256_read:i <- 0
	@DEBUG_VALUE: sha256_read:hash <- $r4
	@DEBUG_VALUE: sha256_read:buff <- [DW_OP_plus_uconst 16, DW_OP_stack_value] $sp
	ldr	r0, [sp, #24]
	lsrs	r1, r0, #24
	strb	r1, [r4]
	lsrs	r1, r0, #16
	strb	r1, [r4, #1]
	lsrs	r1, r0, #8
	strb	r1, [r4, #2]
	strb	r0, [r4, #3]
.Ltmp266:
	@DEBUG_VALUE: sha256_read:i <- 1
	ldr	r0, [sp, #28]
	lsrs	r1, r0, #24
	strb	r1, [r4, #4]
	lsrs	r1, r0, #16
	strb	r1, [r4, #5]
	lsrs	r1, r0, #8
	strb	r1, [r4, #6]
	strb	r0, [r4, #7]
.Ltmp267:
	@DEBUG_VALUE: sha256_read:i <- 2
	ldr	r0, [sp, #32]
	lsrs	r1, r0, #24
	strb	r1, [r4, #8]
	lsrs	r1, r0, #16
	strb	r1, [r4, #9]
	lsrs	r1, r0, #8
	strb	r1, [r4, #10]
	strb	r0, [r4, #11]
.Ltmp268:
	@DEBUG_VALUE: sha256_read:i <- 3
	ldr	r0, [sp, #36]
	lsrs	r1, r0, #24
	strb	r1, [r4, #12]
	lsrs	r1, r0, #16
	strb	r1, [r4, #13]
	lsrs	r1, r0, #8
	strb	r1, [r4, #14]
	strb	r0, [r4, #15]
.Ltmp269:
	@DEBUG_VALUE: sha256_read:i <- 4
	ldr	r0, [sp, #40]
	lsrs	r1, r0, #24
	strb	r1, [r4, #16]
	lsrs	r1, r0, #16
	strb	r1, [r4, #17]
	lsrs	r1, r0, #8
	strb	r1, [r4, #18]
	strb	r0, [r4, #19]
.Ltmp270:
	@DEBUG_VALUE: sha256_read:i <- 5
	ldr	r0, [sp, #44]
	lsrs	r1, r0, #24
	strb	r1, [r4, #20]
	lsrs	r1, r0, #16
	strb	r1, [r4, #21]
	lsrs	r1, r0, #8
	strb	r1, [r4, #22]
	strb	r0, [r4, #23]
.Ltmp271:
	@DEBUG_VALUE: sha256_read:i <- 6
	ldr	r0, [sp, #48]
	lsrs	r1, r0, #24
	strb	r1, [r4, #24]
	lsrs	r1, r0, #16
	strb	r1, [r4, #25]
	lsrs	r1, r0, #8
	strb	r1, [r4, #26]
	strb	r0, [r4, #27]
.Ltmp272:
	@DEBUG_VALUE: sha256_read:i <- 7
	ldr	r0, [sp, #52]
	lsrs	r1, r0, #24
	strb	r1, [r4, #28]
	lsrs	r1, r0, #16
	strb	r1, [r4, #29]
	lsrs	r1, r0, #8
	strb	r1, [r4, #30]
	strb	r0, [r4, #31]
.Ltmp273:
	@DEBUG_VALUE: sha256_read:i <- 8
	add	sp, #196
	pop	{r4, r5, r6, r7, pc}
.Ltmp274:
	.p2align	2
@ %bb.16:
.LCPI6_0:
	.long	1779033703                      @ 0x6a09e667
.LCPI6_1:
	.long	3144134277                      @ 0xbb67ae85
.LCPI6_2:
	.long	1013904242                      @ 0x3c6ef372
.LCPI6_3:
	.long	2773480762                      @ 0xa54ff53a
.LCPI6_4:
	.long	1359893119                      @ 0x510e527f
.LCPI6_5:
	.long	2600822924                      @ 0x9b05688c
.LCPI6_6:
	.long	528734635                       @ 0x1f83d9ab
.LCPI6_7:
	.long	1541459225                      @ 0x5be0cd19
.Lfunc_end6:
	.size	sha256_easy_hash, .Lfunc_end6-sha256_easy_hash
	.cfi_endproc
	.cantunwind
	.fnend
                                        @ -- End function
	.section	.text.sha256_easy_hash_hex,"ax",%progbits
	.hidden	sha256_easy_hash_hex            @ -- Begin function sha256_easy_hash_hex
	.globl	sha256_easy_hash_hex
	.p2align	2
	.type	sha256_easy_hash_hex,%function
	.code	16                              @ @sha256_easy_hash_hex
	.thumb_func
sha256_easy_hash_hex:
.Lfunc_begin7:
	.fnstart
	.cfi_startproc
@ %bb.0:
	@DEBUG_VALUE: sha256_easy_hash_hex:data <- $r0
	@DEBUG_VALUE: sha256_easy_hash_hex:size <- $r1
	@DEBUG_VALUE: sha256_easy_hash_hex:hex <- $r2
	.save	{r4, r5, r6, r7, lr}
	push	{r4, r5, r6, r7, lr}
	.cfi_def_cfa_offset 20
	.cfi_offset lr, -4
	.cfi_offset r7, -8
	.cfi_offset r6, -12
	.cfi_offset r5, -16
	.cfi_offset r4, -20
	.pad	#36
	sub	sp, #36
	.cfi_def_cfa_offset 56
	str	r2, [sp]                        @ 4-byte Spill
.Ltmp275:
	@DEBUG_VALUE: sha256_easy_hash_hex:hex <- [$sp+0]
	add	r2, sp, #4
.Ltmp276:
	bl	sha256_easy_hash
.Ltmp277:
	@DEBUG_VALUE: sha256_easy_hash_hex:size <- [DW_OP_LLVM_entry_value 1] $r1
	@DEBUG_VALUE: sha256_easy_hash_hex:data <- [DW_OP_LLVM_entry_value 1] $r0
	movs	r0, #0
	@DEBUG_VALUE: bin_to_hex:i <- 0
	@DEBUG_VALUE: bin_to_hex:out <- undef
	@DEBUG_VALUE: bin_to_hex:len <- 32
	@DEBUG_VALUE: bin_to_hex:data <- [DW_OP_plus_uconst 4, DW_OP_stack_value] $sp
	ldr	r1, .LCPI7_0
	mov	r2, r0
.Ltmp278:
.LBB7_1:                                @ =>This Inner Loop Header: Depth=1
	@DEBUG_VALUE: bin_to_hex:data <- [DW_OP_plus_uconst 4, DW_OP_stack_value] $sp
	@DEBUG_VALUE: bin_to_hex:len <- 32
	@DEBUG_VALUE: sha256_easy_hash_hex:size <- [DW_OP_LLVM_entry_value 1] $r1
	@DEBUG_VALUE: sha256_easy_hash_hex:data <- [DW_OP_LLVM_entry_value 1] $r0
	@DEBUG_VALUE: sha256_easy_hash_hex:hex <- [$sp+0]
	add	r3, sp, #4
.Ltmp279:
	@DEBUG_VALUE: bin_to_hex:i <- $r2
	adds	r5, r3, r2
	ldrb	r7, [r3, r2]
.Ltmp280:
	@DEBUG_VALUE: c <- undef
	lsrs	r3, r7, #4
	ldrb	r6, [r1, r3]
	ldr	r4, [sp]                        @ 4-byte Reload
	adds	r3, r4, r0
	strb	r6, [r4, r0]
	movs	r6, #15
	ands	r7, r6
	ldrb	r7, [r1, r7]
	strb	r7, [r3, #1]
.Ltmp281:
	@DEBUG_VALUE: bin_to_hex:i <- [DW_OP_constu 1, DW_OP_or, DW_OP_stack_value] $r2
	ldrb	r7, [r5, #1]
	lsrs	r4, r7, #4
	ldrb	r4, [r1, r4]
	strb	r4, [r3, #2]
	ands	r7, r6
	ldrb	r4, [r1, r7]
	strb	r4, [r3, #3]
.Ltmp282:
	@DEBUG_VALUE: bin_to_hex:i <- [DW_OP_constu 2, DW_OP_or, DW_OP_stack_value] $r2
	ldrb	r4, [r5, #2]
	lsrs	r7, r4, #4
	ldrb	r7, [r1, r7]
	strb	r7, [r3, #4]
	ands	r4, r6
	ldrb	r4, [r1, r4]
	strb	r4, [r3, #5]
.Ltmp283:
	@DEBUG_VALUE: bin_to_hex:i <- [DW_OP_constu 3, DW_OP_or, DW_OP_stack_value] $r2
	ldrb	r4, [r5, #3]
	lsrs	r7, r4, #4
	ldrb	r7, [r1, r7]
	strb	r7, [r3, #6]
	ands	r4, r6
	ldrb	r4, [r1, r4]
	strb	r4, [r3, #7]
.Ltmp284:
	@DEBUG_VALUE: bin_to_hex:i <- [DW_OP_constu 4, DW_OP_or, DW_OP_stack_value] $r2
	ldrb	r4, [r5, #4]
	lsrs	r7, r4, #4
	ldrb	r7, [r1, r7]
	strb	r7, [r3, #8]
	ands	r4, r6
	ldrb	r4, [r1, r4]
	strb	r4, [r3, #9]
.Ltmp285:
	@DEBUG_VALUE: bin_to_hex:i <- [DW_OP_constu 5, DW_OP_or, DW_OP_stack_value] $r2
	ldrb	r4, [r5, #5]
	lsrs	r7, r4, #4
	ldrb	r7, [r1, r7]
	strb	r7, [r3, #10]
	ands	r4, r6
	ldrb	r4, [r1, r4]
	strb	r4, [r3, #11]
.Ltmp286:
	@DEBUG_VALUE: bin_to_hex:i <- [DW_OP_constu 6, DW_OP_or, DW_OP_stack_value] $r2
	ldrb	r4, [r5, #6]
	lsrs	r7, r4, #4
	ldrb	r7, [r1, r7]
	strb	r7, [r3, #12]
	ands	r4, r6
	ldrb	r4, [r1, r4]
	strb	r4, [r3, #13]
.Ltmp287:
	@DEBUG_VALUE: bin_to_hex:i <- [DW_OP_constu 7, DW_OP_or, DW_OP_stack_value] $r2
	ldrb	r4, [r5, #7]
	lsrs	r7, r4, #4
	ldrb	r7, [r1, r7]
	strb	r7, [r3, #14]
	ands	r4, r6
	ldrb	r4, [r1, r4]
	strb	r4, [r3, #15]
.Ltmp288:
	@DEBUG_VALUE: bin_to_hex:i <- [DW_OP_constu 8, DW_OP_or, DW_OP_stack_value] $r2
	ldrb	r4, [r5, #8]
	lsrs	r7, r4, #4
	ldrb	r7, [r1, r7]
	strb	r7, [r3, #16]
	ands	r4, r6
	ldrb	r4, [r1, r4]
	strb	r4, [r3, #17]
.Ltmp289:
	@DEBUG_VALUE: bin_to_hex:i <- [DW_OP_constu 9, DW_OP_or, DW_OP_stack_value] $r2
	ldrb	r4, [r5, #9]
	lsrs	r7, r4, #4
	ldrb	r7, [r1, r7]
	strb	r7, [r3, #18]
	ands	r4, r6
	ldrb	r4, [r1, r4]
	strb	r4, [r3, #19]
.Ltmp290:
	@DEBUG_VALUE: bin_to_hex:i <- [DW_OP_constu 10, DW_OP_or, DW_OP_stack_value] $r2
	ldrb	r4, [r5, #10]
	lsrs	r7, r4, #4
	ldrb	r7, [r1, r7]
	strb	r7, [r3, #20]
	ands	r4, r6
	ldrb	r4, [r1, r4]
	strb	r4, [r3, #21]
.Ltmp291:
	@DEBUG_VALUE: bin_to_hex:i <- [DW_OP_constu 11, DW_OP_or, DW_OP_stack_value] $r2
	ldrb	r4, [r5, #11]
	lsrs	r7, r4, #4
	ldrb	r7, [r1, r7]
	strb	r7, [r3, #22]
	ands	r4, r6
	ldrb	r4, [r1, r4]
	strb	r4, [r3, #23]
.Ltmp292:
	@DEBUG_VALUE: bin_to_hex:i <- [DW_OP_constu 12, DW_OP_or, DW_OP_stack_value] $r2
	ldrb	r4, [r5, #12]
	lsrs	r7, r4, #4
	ldrb	r7, [r1, r7]
	strb	r7, [r3, #24]
	ands	r4, r6
	ldrb	r4, [r1, r4]
	strb	r4, [r3, #25]
.Ltmp293:
	@DEBUG_VALUE: bin_to_hex:i <- [DW_OP_constu 13, DW_OP_or, DW_OP_stack_value] $r2
	ldrb	r4, [r5, #13]
	lsrs	r7, r4, #4
	ldrb	r7, [r1, r7]
	strb	r7, [r3, #26]
	ands	r4, r6
	ldrb	r4, [r1, r4]
	strb	r4, [r3, #27]
.Ltmp294:
	@DEBUG_VALUE: bin_to_hex:i <- [DW_OP_constu 14, DW_OP_or, DW_OP_stack_value] $r2
	ldrb	r4, [r5, #14]
	lsrs	r7, r4, #4
	ldrb	r7, [r1, r7]
	strb	r7, [r3, #28]
	ands	r4, r6
	ldrb	r4, [r1, r4]
	strb	r4, [r3, #29]
.Ltmp295:
	@DEBUG_VALUE: bin_to_hex:i <- [DW_OP_constu 15, DW_OP_or, DW_OP_stack_value] $r2
	ldrb	r4, [r5, #15]
	lsrs	r5, r4, #4
	ldrb	r5, [r1, r5]
	strb	r5, [r3, #30]
	ands	r4, r6
	ldrb	r4, [r1, r4]
	strb	r4, [r3, #31]
.Ltmp296:
	adds	r2, #16
.Ltmp297:
	@DEBUG_VALUE: bin_to_hex:i <- $r2
	adds	r0, #32
.Ltmp298:
	cmp	r0, #64
	bne	.LBB7_1
.Ltmp299:
@ %bb.2:
	@DEBUG_VALUE: sha256_easy_hash_hex:size <- [DW_OP_LLVM_entry_value 1] $r1
	@DEBUG_VALUE: sha256_easy_hash_hex:data <- [DW_OP_LLVM_entry_value 1] $r0
	@DEBUG_VALUE: sha256_easy_hash_hex:hex <- [$sp+0]
	add	sp, #36
	pop	{r4, r5, r6, r7, pc}
.Ltmp300:
	.p2align	2
@ %bb.3:
.LCPI7_0:
	.long	.L.str
.Lfunc_end7:
	.size	sha256_easy_hash_hex, .Lfunc_end7-sha256_easy_hash_hex
	.cfi_endproc
	.cantunwind
	.fnend
                                        @ -- End function
	.type	k,%object                       @ @k
	.section	.rodata.k,"a",%progbits
	.p2align	2, 0x0
k:
	.long	1116352408                      @ 0x428a2f98
	.long	1899447441                      @ 0x71374491
	.long	3049323471                      @ 0xb5c0fbcf
	.long	3921009573                      @ 0xe9b5dba5
	.long	961987163                       @ 0x3956c25b
	.long	1508970993                      @ 0x59f111f1
	.long	2453635748                      @ 0x923f82a4
	.long	2870763221                      @ 0xab1c5ed5
	.long	3624381080                      @ 0xd807aa98
	.long	310598401                       @ 0x12835b01
	.long	607225278                       @ 0x243185be
	.long	1426881987                      @ 0x550c7dc3
	.long	1925078388                      @ 0x72be5d74
	.long	2162078206                      @ 0x80deb1fe
	.long	2614888103                      @ 0x9bdc06a7
	.long	3248222580                      @ 0xc19bf174
	.long	3835390401                      @ 0xe49b69c1
	.long	4022224774                      @ 0xefbe4786
	.long	264347078                       @ 0xfc19dc6
	.long	604807628                       @ 0x240ca1cc
	.long	770255983                       @ 0x2de92c6f
	.long	1249150122                      @ 0x4a7484aa
	.long	1555081692                      @ 0x5cb0a9dc
	.long	1996064986                      @ 0x76f988da
	.long	2554220882                      @ 0x983e5152
	.long	2821834349                      @ 0xa831c66d
	.long	2952996808                      @ 0xb00327c8
	.long	3210313671                      @ 0xbf597fc7
	.long	3336571891                      @ 0xc6e00bf3
	.long	3584528711                      @ 0xd5a79147
	.long	113926993                       @ 0x6ca6351
	.long	338241895                       @ 0x14292967
	.long	666307205                       @ 0x27b70a85
	.long	773529912                       @ 0x2e1b2138
	.long	1294757372                      @ 0x4d2c6dfc
	.long	1396182291                      @ 0x53380d13
	.long	1695183700                      @ 0x650a7354
	.long	1986661051                      @ 0x766a0abb
	.long	2177026350                      @ 0x81c2c92e
	.long	2456956037                      @ 0x92722c85
	.long	2730485921                      @ 0xa2bfe8a1
	.long	2820302411                      @ 0xa81a664b
	.long	3259730800                      @ 0xc24b8b70
	.long	3345764771                      @ 0xc76c51a3
	.long	3516065817                      @ 0xd192e819
	.long	3600352804                      @ 0xd6990624
	.long	4094571909                      @ 0xf40e3585
	.long	275423344                       @ 0x106aa070
	.long	430227734                       @ 0x19a4c116
	.long	506948616                       @ 0x1e376c08
	.long	659060556                       @ 0x2748774c
	.long	883997877                       @ 0x34b0bcb5
	.long	958139571                       @ 0x391c0cb3
	.long	1322822218                      @ 0x4ed8aa4a
	.long	1537002063                      @ 0x5b9cca4f
	.long	1747873779                      @ 0x682e6ff3
	.long	1955562222                      @ 0x748f82ee
	.long	2024104815                      @ 0x78a5636f
	.long	2227730452                      @ 0x84c87814
	.long	2361852424                      @ 0x8cc70208
	.long	2428436474                      @ 0x90befffa
	.long	2756734187                      @ 0xa4506ceb
	.long	3204031479                      @ 0xbef9a3f7
	.long	3329325298                      @ 0xc67178f2
	.size	k, 256

	.type	.L.str,%object                  @ @.str
	.section	.rodata.str1.14577331162332807138.1,"aMS",%progbits,1
.L.str:
	.asciz	"0123456789abcdef"
	.size	.L.str, 17

	.section	.debug_loc,"",%progbits
.Ldebug_loc0:
	.long	-1
	.long	.Lfunc_begin1                   @   base address
	.long	.Lfunc_begin1-.Lfunc_begin1
	.long	.Ltmp4-.Lfunc_begin1
	.short	1                               @ Loc expr size
	.byte	80                              @ DW_OP_reg0
	.long	.Ltmp4-.Lfunc_begin1
	.long	.Ltmp5-.Lfunc_begin1
	.short	1                               @ Loc expr size
	.byte	86                              @ DW_OP_reg6
	.long	.Ltmp5-.Lfunc_begin1
	.long	.Lfunc_end1-.Lfunc_begin1
	.short	3                               @ Loc expr size
	.byte	163                             @ DW_OP_entry_value
	.byte	1                               @ 1
	.byte	80                              @ DW_OP_reg0
	.long	0
	.long	0
.Ldebug_loc1:
	.long	-1
	.long	.Lfunc_begin1                   @   base address
	.long	.Lfunc_begin1-.Lfunc_begin1
	.long	.Ltmp3-.Lfunc_begin1
	.short	1                               @ Loc expr size
	.byte	81                              @ DW_OP_reg1
	.long	.Ltmp3-.Lfunc_begin1
	.long	.Ltmp11-.Lfunc_begin1
	.short	1                               @ Loc expr size
	.byte	85                              @ DW_OP_reg5
	.long	.Ltmp11-.Lfunc_begin1
	.long	.Ltmp13-.Lfunc_begin1
	.short	3                               @ Loc expr size
	.byte	163                             @ DW_OP_entry_value
	.byte	1                               @ 1
	.byte	81                              @ DW_OP_reg1
	.long	0
	.long	0
.Ldebug_loc2:
	.long	-1
	.long	.Lfunc_begin1                   @   base address
	.long	.Lfunc_begin1-.Lfunc_begin1
	.long	.Ltmp2-.Lfunc_begin1
	.short	1                               @ Loc expr size
	.byte	82                              @ DW_OP_reg2
	.long	.Ltmp2-.Lfunc_begin1
	.long	.Ltmp20-.Lfunc_begin1
	.short	1                               @ Loc expr size
	.byte	84                              @ DW_OP_reg4
	.long	.Ltmp24-.Lfunc_begin1
	.long	.Ltmp26-.Lfunc_begin1
	.short	1                               @ Loc expr size
	.byte	84                              @ DW_OP_reg4
	.long	.Ltmp29-.Lfunc_begin1
	.long	.Ltmp31-.Lfunc_begin1
	.short	1                               @ Loc expr size
	.byte	84                              @ DW_OP_reg4
	.long	.Ltmp35-.Lfunc_begin1
	.long	.Ltmp36-.Lfunc_begin1
	.short	1                               @ Loc expr size
	.byte	84                              @ DW_OP_reg4
	.long	0
	.long	0
.Ldebug_loc3:
	.long	-1
	.long	.Lfunc_begin1                   @   base address
	.long	.Ltmp11-.Lfunc_begin1
	.long	.Ltmp20-.Lfunc_begin1
	.short	1                               @ Loc expr size
	.byte	85                              @ DW_OP_reg5
	.long	.Ltmp20-.Lfunc_begin1
	.long	.Ltmp22-.Lfunc_begin1
	.short	1                               @ Loc expr size
	.byte	81                              @ DW_OP_reg1
	.long	.Ltmp23-.Lfunc_begin1
	.long	.Ltmp26-.Lfunc_begin1
	.short	1                               @ Loc expr size
	.byte	85                              @ DW_OP_reg5
	.long	.Ltmp26-.Lfunc_begin1
	.long	.Ltmp28-.Lfunc_begin1
	.short	1                               @ Loc expr size
	.byte	81                              @ DW_OP_reg1
	.long	.Ltmp28-.Lfunc_begin1
	.long	.Ltmp31-.Lfunc_begin1
	.short	1                               @ Loc expr size
	.byte	85                              @ DW_OP_reg5
	.long	.Ltmp31-.Lfunc_begin1
	.long	.Ltmp32-.Lfunc_begin1
	.short	1                               @ Loc expr size
	.byte	81                              @ DW_OP_reg1
	.long	.Ltmp34-.Lfunc_begin1
	.long	.Ltmp38-.Lfunc_begin1
	.short	1                               @ Loc expr size
	.byte	85                              @ DW_OP_reg5
	.long	0
	.long	0
.Ldebug_loc4:
	.long	-1
	.long	.Lfunc_begin2                   @   base address
	.long	.Lfunc_begin2-.Lfunc_begin2
	.long	.Ltmp39-.Lfunc_begin2
	.short	1                               @ Loc expr size
	.byte	80                              @ DW_OP_reg0
	.long	.Ltmp39-.Lfunc_begin2
	.long	.Ltmp52-.Lfunc_begin2
	.short	2                               @ Loc expr size
	.byte	125                             @ DW_OP_breg13
	.byte	32                              @ 32
	.long	.Ltmp53-.Lfunc_begin2
	.long	.Ltmp74-.Lfunc_begin2
	.short	5                               @ Loc expr size
	.byte	125                             @ DW_OP_breg13
	.byte	48                              @ 48
	.byte	6                               @ DW_OP_deref
	.byte	35                              @ DW_OP_plus_uconst
	.byte	32                              @ 32
	.long	.Ltmp74-.Lfunc_begin2
	.long	.Ltmp76-.Lfunc_begin2
	.short	2                               @ Loc expr size
	.byte	113                             @ DW_OP_breg1
	.byte	32                              @ 32
	.long	0
	.long	0
.Ldebug_loc5:
	.long	-1
	.long	.Lfunc_begin2                   @   base address
	.long	.Lfunc_begin2-.Lfunc_begin2
	.long	.Ltmp40-.Lfunc_begin2
	.short	1                               @ Loc expr size
	.byte	81                              @ DW_OP_reg1
	.long	0
	.long	0
.Ldebug_loc6:
	.long	-1
	.long	.Lfunc_begin2                   @   base address
	.long	.Ltmp88-.Lfunc_begin2
	.long	.Ltmp96-.Lfunc_begin2
	.short	1                               @ Loc expr size
	.byte	48                              @ DW_OP_lit0
	.long	.Ltmp117-.Lfunc_begin2
	.long	.Ltmp118-.Lfunc_begin2
	.short	1                               @ Loc expr size
	.byte	48                              @ DW_OP_lit0
	.long	.Ltmp118-.Lfunc_begin2
	.long	.Ltmp119-.Lfunc_begin2
	.short	1                               @ Loc expr size
	.byte	49                              @ DW_OP_lit1
	.long	.Ltmp119-.Lfunc_begin2
	.long	.Ltmp120-.Lfunc_begin2
	.short	1                               @ Loc expr size
	.byte	50                              @ DW_OP_lit2
	.long	.Ltmp120-.Lfunc_begin2
	.long	.Ltmp122-.Lfunc_begin2
	.short	1                               @ Loc expr size
	.byte	51                              @ DW_OP_lit3
	.long	.Ltmp122-.Lfunc_begin2
	.long	.Ltmp125-.Lfunc_begin2
	.short	1                               @ Loc expr size
	.byte	52                              @ DW_OP_lit4
	.long	.Ltmp125-.Lfunc_begin2
	.long	.Ltmp126-.Lfunc_begin2
	.short	1                               @ Loc expr size
	.byte	53                              @ DW_OP_lit5
	.long	.Ltmp126-.Lfunc_begin2
	.long	.Ltmp128-.Lfunc_begin2
	.short	1                               @ Loc expr size
	.byte	54                              @ DW_OP_lit6
	.long	.Ltmp128-.Lfunc_begin2
	.long	.Ltmp129-.Lfunc_begin2
	.short	1                               @ Loc expr size
	.byte	55                              @ DW_OP_lit7
	.long	.Ltmp129-.Lfunc_begin2
	.long	.Ltmp131-.Lfunc_begin2
	.short	1                               @ Loc expr size
	.byte	56                              @ DW_OP_lit8
	.long	0
	.long	0
.Ldebug_loc7:
	.long	-1
	.long	.Lfunc_begin2                   @   base address
	.long	.Ltmp56-.Lfunc_begin2
	.long	.Ltmp58-.Lfunc_begin2
	.short	1                               @ Loc expr size
	.byte	80                              @ DW_OP_reg0
	.long	.Ltmp61-.Lfunc_begin2
	.long	.Ltmp63-.Lfunc_begin2
	.short	1                               @ Loc expr size
	.byte	81                              @ DW_OP_reg1
	.long	.Ltmp66-.Lfunc_begin2
	.long	.Ltmp68-.Lfunc_begin2
	.short	1                               @ Loc expr size
	.byte	83                              @ DW_OP_reg3
	.long	.Ltmp70-.Lfunc_begin2
	.long	.Ltmp73-.Lfunc_begin2
	.short	1                               @ Loc expr size
	.byte	80                              @ DW_OP_reg0
	.long	0
	.long	0
.Ldebug_loc8:
	.long	-1
	.long	.Lfunc_begin2                   @   base address
	.long	.Ltmp57-.Lfunc_begin2
	.long	.Ltmp60-.Lfunc_begin2
	.short	1                               @ Loc expr size
	.byte	81                              @ DW_OP_reg1
	.long	.Ltmp62-.Lfunc_begin2
	.long	.Ltmp65-.Lfunc_begin2
	.short	1                               @ Loc expr size
	.byte	83                              @ DW_OP_reg3
	.long	.Ltmp67-.Lfunc_begin2
	.long	.Ltmp71-.Lfunc_begin2
	.short	1                               @ Loc expr size
	.byte	86                              @ DW_OP_reg6
	.long	.Ltmp72-.Lfunc_begin2
	.long	.Ltmp77-.Lfunc_begin2
	.short	1                               @ Loc expr size
	.byte	87                              @ DW_OP_reg7
	.long	0
	.long	0
.Ldebug_loc9:
	.long	-1
	.long	.Lfunc_begin2                   @   base address
	.long	.Ltmp79-.Lfunc_begin2
	.long	.Ltmp80-.Lfunc_begin2
	.short	3                               @ Loc expr size
	.byte	84                              @ DW_OP_reg4
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.long	.Ltmp80-.Lfunc_begin2
	.long	.Ltmp81-.Lfunc_begin2
	.short	6                               @ Loc expr size
	.byte	84                              @ DW_OP_reg4
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	81                              @ DW_OP_reg1
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.long	.Ltmp81-.Lfunc_begin2
	.long	.Ltmp82-.Lfunc_begin2
	.short	7                               @ Loc expr size
	.byte	84                              @ DW_OP_reg4
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	125                             @ DW_OP_breg13
	.byte	28                              @ 28
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.long	.Ltmp82-.Lfunc_begin2
	.long	.Ltmp83-.Lfunc_begin2
	.short	10                              @ Loc expr size
	.byte	84                              @ DW_OP_reg4
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	125                             @ DW_OP_breg13
	.byte	28                              @ 28
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	85                              @ DW_OP_reg5
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.long	.Ltmp83-.Lfunc_begin2
	.long	.Ltmp84-.Lfunc_begin2
	.short	13                              @ Loc expr size
	.byte	84                              @ DW_OP_reg4
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	125                             @ DW_OP_breg13
	.byte	28                              @ 28
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	85                              @ DW_OP_reg5
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	87                              @ DW_OP_reg7
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.long	.Ltmp84-.Lfunc_begin2
	.long	.Ltmp85-.Lfunc_begin2
	.short	16                              @ Loc expr size
	.byte	84                              @ DW_OP_reg4
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	125                             @ DW_OP_breg13
	.byte	28                              @ 28
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	85                              @ DW_OP_reg5
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	87                              @ DW_OP_reg7
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	86                              @ DW_OP_reg6
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.long	.Ltmp85-.Lfunc_begin2
	.long	.Ltmp86-.Lfunc_begin2
	.short	19                              @ Loc expr size
	.byte	84                              @ DW_OP_reg4
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	125                             @ DW_OP_breg13
	.byte	28                              @ 28
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	85                              @ DW_OP_reg5
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	87                              @ DW_OP_reg7
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	86                              @ DW_OP_reg6
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	83                              @ DW_OP_reg3
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.long	.Ltmp86-.Lfunc_begin2
	.long	.Ltmp87-.Lfunc_begin2
	.short	22                              @ Loc expr size
	.byte	84                              @ DW_OP_reg4
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	125                             @ DW_OP_breg13
	.byte	28                              @ 28
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	85                              @ DW_OP_reg5
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	87                              @ DW_OP_reg7
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	86                              @ DW_OP_reg6
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	83                              @ DW_OP_reg3
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	81                              @ DW_OP_reg1
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.long	.Ltmp87-.Lfunc_begin2
	.long	.Ltmp89-.Lfunc_begin2
	.short	25                              @ Loc expr size
	.byte	84                              @ DW_OP_reg4
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	125                             @ DW_OP_breg13
	.byte	28                              @ 28
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	85                              @ DW_OP_reg5
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	87                              @ DW_OP_reg7
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	86                              @ DW_OP_reg6
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	83                              @ DW_OP_reg3
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	81                              @ DW_OP_reg1
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	80                              @ DW_OP_reg0
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.long	.Ltmp89-.Lfunc_begin2
	.long	.Ltmp90-.Lfunc_begin2
	.short	26                              @ Loc expr size
	.byte	84                              @ DW_OP_reg4
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	125                             @ DW_OP_breg13
	.byte	28                              @ 28
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	85                              @ DW_OP_reg5
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	87                              @ DW_OP_reg7
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	125                             @ DW_OP_breg13
	.byte	12                              @ 12
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	83                              @ DW_OP_reg3
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	81                              @ DW_OP_reg1
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	80                              @ DW_OP_reg0
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.long	.Ltmp90-.Lfunc_begin2
	.long	.Ltmp91-.Lfunc_begin2
	.short	27                              @ Loc expr size
	.byte	84                              @ DW_OP_reg4
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	125                             @ DW_OP_breg13
	.byte	28                              @ 28
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	85                              @ DW_OP_reg5
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	87                              @ DW_OP_reg7
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	125                             @ DW_OP_breg13
	.byte	12                              @ 12
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	125                             @ DW_OP_breg13
	.byte	8                               @ 8
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	81                              @ DW_OP_reg1
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	80                              @ DW_OP_reg0
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.long	.Ltmp91-.Lfunc_begin2
	.long	.Ltmp92-.Lfunc_begin2
	.short	28                              @ Loc expr size
	.byte	84                              @ DW_OP_reg4
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	125                             @ DW_OP_breg13
	.byte	28                              @ 28
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	85                              @ DW_OP_reg5
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	87                              @ DW_OP_reg7
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	125                             @ DW_OP_breg13
	.byte	12                              @ 12
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	125                             @ DW_OP_breg13
	.byte	8                               @ 8
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	125                             @ DW_OP_breg13
	.byte	4                               @ 4
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	80                              @ DW_OP_reg0
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.long	.Ltmp92-.Lfunc_begin2
	.long	.Ltmp93-.Lfunc_begin2
	.short	29                              @ Loc expr size
	.byte	84                              @ DW_OP_reg4
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	125                             @ DW_OP_breg13
	.byte	28                              @ 28
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	85                              @ DW_OP_reg5
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	87                              @ DW_OP_reg7
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	125                             @ DW_OP_breg13
	.byte	12                              @ 12
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	125                             @ DW_OP_breg13
	.byte	8                               @ 8
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	125                             @ DW_OP_breg13
	.byte	4                               @ 4
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	125                             @ DW_OP_breg13
	.byte	0                               @ 0
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.long	.Ltmp93-.Lfunc_begin2
	.long	.Ltmp94-.Lfunc_begin2
	.short	28                              @ Loc expr size
	.byte	125                             @ DW_OP_breg13
	.byte	24                              @ 24
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	85                              @ DW_OP_reg5
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	87                              @ DW_OP_reg7
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	125                             @ DW_OP_breg13
	.byte	12                              @ 12
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	125                             @ DW_OP_breg13
	.byte	8                               @ 8
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	125                             @ DW_OP_breg13
	.byte	4                               @ 4
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	125                             @ DW_OP_breg13
	.byte	0                               @ 0
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.long	.Ltmp94-.Lfunc_begin2
	.long	.Ltmp95-.Lfunc_begin2
	.short	29                              @ Loc expr size
	.byte	125                             @ DW_OP_breg13
	.byte	24                              @ 24
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	125                             @ DW_OP_breg13
	.byte	20                              @ 20
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	87                              @ DW_OP_reg7
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	125                             @ DW_OP_breg13
	.byte	12                              @ 12
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	125                             @ DW_OP_breg13
	.byte	8                               @ 8
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	125                             @ DW_OP_breg13
	.byte	4                               @ 4
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	125                             @ DW_OP_breg13
	.byte	0                               @ 0
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.long	.Ltmp95-.Lfunc_begin2
	.long	.Ltmp96-.Lfunc_begin2
	.short	30                              @ Loc expr size
	.byte	125                             @ DW_OP_breg13
	.byte	24                              @ 24
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	125                             @ DW_OP_breg13
	.byte	20                              @ 20
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	125                             @ DW_OP_breg13
	.byte	16                              @ 16
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	125                             @ DW_OP_breg13
	.byte	12                              @ 12
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	125                             @ DW_OP_breg13
	.byte	8                               @ 8
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	125                             @ DW_OP_breg13
	.byte	4                               @ 4
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	125                             @ DW_OP_breg13
	.byte	0                               @ 0
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.long	.Ltmp105-.Lfunc_begin2
	.long	.Ltmp107-.Lfunc_begin2
	.short	13                              @ Loc expr size
	.byte	147                             @ DW_OP_piece
	.byte	20                              @ 20
	.byte	83                              @ DW_OP_reg3
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	125                             @ DW_OP_breg13
	.byte	60                              @ 60
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	125                             @ DW_OP_breg13
	.byte	36                              @ 36
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.long	.Ltmp107-.Lfunc_begin2
	.long	.Ltmp108-.Lfunc_begin2
	.short	27                              @ Loc expr size
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	80                              @ DW_OP_reg0
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	86                              @ DW_OP_reg6
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	125                             @ DW_OP_breg13
	.byte	192                             @ 64
	.byte	0                               @ 
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	81                              @ DW_OP_reg1
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	83                              @ DW_OP_reg3
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	125                             @ DW_OP_breg13
	.byte	60                              @ 60
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	125                             @ DW_OP_breg13
	.byte	36                              @ 36
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.long	.Ltmp108-.Lfunc_begin2
	.long	.Ltmp109-.Lfunc_begin2
	.short	28                              @ Loc expr size
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	80                              @ DW_OP_reg0
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	86                              @ DW_OP_reg6
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	125                             @ DW_OP_breg13
	.byte	192                             @ 64
	.byte	0                               @ 
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	125                             @ DW_OP_breg13
	.byte	56                              @ 56
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	83                              @ DW_OP_reg3
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	125                             @ DW_OP_breg13
	.byte	60                              @ 60
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	125                             @ DW_OP_breg13
	.byte	36                              @ 36
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.long	.Ltmp109-.Lfunc_begin2
	.long	.Ltmp110-.Lfunc_begin2
	.short	28                              @ Loc expr size
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	80                              @ DW_OP_reg0
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	85                              @ DW_OP_reg5
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	125                             @ DW_OP_breg13
	.byte	192                             @ 64
	.byte	0                               @ 
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	125                             @ DW_OP_breg13
	.byte	56                              @ 56
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	83                              @ DW_OP_reg3
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	125                             @ DW_OP_breg13
	.byte	60                              @ 60
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	125                             @ DW_OP_breg13
	.byte	36                              @ 36
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.long	.Ltmp110-.Lfunc_begin2
	.long	.Ltmp111-.Lfunc_begin2
	.short	29                              @ Loc expr size
	.byte	84                              @ DW_OP_reg4
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	80                              @ DW_OP_reg0
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	85                              @ DW_OP_reg5
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	125                             @ DW_OP_breg13
	.byte	192                             @ 64
	.byte	0                               @ 
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	125                             @ DW_OP_breg13
	.byte	56                              @ 56
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	83                              @ DW_OP_reg3
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	125                             @ DW_OP_breg13
	.byte	60                              @ 60
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	125                             @ DW_OP_breg13
	.byte	36                              @ 36
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.long	.Ltmp111-.Lfunc_begin2
	.long	.Ltmp115-.Lfunc_begin2
	.short	28                              @ Loc expr size
	.byte	84                              @ DW_OP_reg4
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	80                              @ DW_OP_reg0
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	85                              @ DW_OP_reg5
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	125                             @ DW_OP_breg13
	.byte	192                             @ 64
	.byte	0                               @ 
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	125                             @ DW_OP_breg13
	.byte	56                              @ 56
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	83                              @ DW_OP_reg3
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	125                             @ DW_OP_breg13
	.byte	60                              @ 60
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	87                              @ DW_OP_reg7
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.long	.Ltmp115-.Lfunc_begin2
	.long	.Ltmp117-.Lfunc_begin2
	.short	26                              @ Loc expr size
	.byte	84                              @ DW_OP_reg4
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	80                              @ DW_OP_reg0
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	85                              @ DW_OP_reg5
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	81                              @ DW_OP_reg1
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	125                             @ DW_OP_breg13
	.byte	56                              @ 56
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	83                              @ DW_OP_reg3
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	125                             @ DW_OP_breg13
	.byte	60                              @ 60
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	87                              @ DW_OP_reg7
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.long	.Ltmp117-.Lfunc_begin2
	.long	.Ltmp119-.Lfunc_begin2
	.short	26                              @ Loc expr size
	.byte	84                              @ DW_OP_reg4
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	80                              @ DW_OP_reg0
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	85                              @ DW_OP_reg5
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	86                              @ DW_OP_reg6
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	125                             @ DW_OP_breg13
	.byte	56                              @ 56
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	83                              @ DW_OP_reg3
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	125                             @ DW_OP_breg13
	.byte	60                              @ 60
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	87                              @ DW_OP_reg7
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.long	.Ltmp119-.Lfunc_begin2
	.long	.Ltmp121-.Lfunc_begin2
	.short	25                              @ Loc expr size
	.byte	84                              @ DW_OP_reg4
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	85                              @ DW_OP_reg5
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	86                              @ DW_OP_reg6
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	125                             @ DW_OP_breg13
	.byte	56                              @ 56
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	83                              @ DW_OP_reg3
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	125                             @ DW_OP_breg13
	.byte	60                              @ 60
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	87                              @ DW_OP_reg7
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.long	.Ltmp121-.Lfunc_begin2
	.long	.Ltmp123-.Lfunc_begin2
	.short	22                              @ Loc expr size
	.byte	147                             @ DW_OP_piece
	.byte	8                               @ 8
	.byte	85                              @ DW_OP_reg5
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	86                              @ DW_OP_reg6
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	125                             @ DW_OP_breg13
	.byte	56                              @ 56
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	83                              @ DW_OP_reg3
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	125                             @ DW_OP_breg13
	.byte	60                              @ 60
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	87                              @ DW_OP_reg7
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.long	.Ltmp123-.Lfunc_begin2
	.long	.Ltmp124-.Lfunc_begin2
	.short	19                              @ Loc expr size
	.byte	147                             @ DW_OP_piece
	.byte	12                              @ 12
	.byte	86                              @ DW_OP_reg6
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	125                             @ DW_OP_breg13
	.byte	56                              @ 56
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	83                              @ DW_OP_reg3
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	125                             @ DW_OP_breg13
	.byte	60                              @ 60
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	87                              @ DW_OP_reg7
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.long	.Ltmp124-.Lfunc_begin2
	.long	.Ltmp127-.Lfunc_begin2
	.short	16                              @ Loc expr size
	.byte	147                             @ DW_OP_piece
	.byte	16                              @ 16
	.byte	125                             @ DW_OP_breg13
	.byte	56                              @ 56
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	83                              @ DW_OP_reg3
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	125                             @ DW_OP_breg13
	.byte	60                              @ 60
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	87                              @ DW_OP_reg7
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.long	.Ltmp127-.Lfunc_begin2
	.long	.Ltmp129-.Lfunc_begin2
	.short	15                              @ Loc expr size
	.byte	147                             @ DW_OP_piece
	.byte	16                              @ 16
	.byte	125                             @ DW_OP_breg13
	.byte	56                              @ 56
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	125                             @ DW_OP_breg13
	.byte	60                              @ 60
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	87                              @ DW_OP_reg7
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.long	.Ltmp129-.Lfunc_begin2
	.long	.Ltmp131-.Lfunc_begin2
	.short	12                              @ Loc expr size
	.byte	147                             @ DW_OP_piece
	.byte	16                              @ 16
	.byte	125                             @ DW_OP_breg13
	.byte	56                              @ 56
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	125                             @ DW_OP_breg13
	.byte	60                              @ 60
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.long	0
	.long	0
.Ldebug_loc10:
	.long	-1
	.long	.Lfunc_begin2                   @   base address
	.long	.Ltmp99-.Lfunc_begin2
	.long	.Ltmp101-.Lfunc_begin2
	.short	1                               @ Loc expr size
	.byte	87                              @ DW_OP_reg7
	.long	0
	.long	0
.Ldebug_loc11:
	.long	-1
	.long	.Lfunc_begin2                   @   base address
	.long	.Ltmp102-.Lfunc_begin2
	.long	.Ltmp103-.Lfunc_begin2
	.short	1                               @ Loc expr size
	.byte	81                              @ DW_OP_reg1
	.long	.Ltmp103-.Lfunc_begin2
	.long	.Ltmp106-.Lfunc_begin2
	.short	2                               @ Loc expr size
	.byte	125                             @ DW_OP_breg13
	.byte	48                              @ 48
	.long	.Ltmp106-.Lfunc_begin2
	.long	.Ltmp110-.Lfunc_begin2
	.short	1                               @ Loc expr size
	.byte	84                              @ DW_OP_reg4
	.long	0
	.long	0
.Ldebug_loc12:
	.long	-1
	.long	.Lfunc_begin2                   @   base address
	.long	.Ltmp104-.Lfunc_begin2
	.long	.Ltmp109-.Lfunc_begin2
	.short	1                               @ Loc expr size
	.byte	85                              @ DW_OP_reg5
	.long	0
	.long	0
.Ldebug_loc13:
	.long	-1
	.long	.Lfunc_begin2                   @   base address
	.long	.Ltmp105-.Lfunc_begin2
	.long	.Ltmp111-.Lfunc_begin2
	.short	1                               @ Loc expr size
	.byte	87                              @ DW_OP_reg7
	.long	0
	.long	0
.Ldebug_loc14:
	.long	-1
	.long	.Lfunc_begin3                   @   base address
	.long	.Lfunc_begin3-.Lfunc_begin3
	.long	.Ltmp132-.Lfunc_begin3
	.short	1                               @ Loc expr size
	.byte	80                              @ DW_OP_reg0
	.long	.Ltmp132-.Lfunc_begin3
	.long	.Ltmp148-.Lfunc_begin3
	.short	1                               @ Loc expr size
	.byte	84                              @ DW_OP_reg4
	.long	0
	.long	0
.Ldebug_loc15:
	.long	-1
	.long	.Lfunc_begin3                   @   base address
	.long	.Ltmp138-.Lfunc_begin3
	.long	.Ltmp141-.Lfunc_begin3
	.short	3                               @ Loc expr size
	.byte	87                              @ DW_OP_reg7
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.long	.Ltmp141-.Lfunc_begin3
	.long	.Ltmp145-.Lfunc_begin3
	.short	3                               @ Loc expr size
	.byte	81                              @ DW_OP_reg1
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.long	.Ltmp145-.Lfunc_begin3
	.long	.Ltmp146-.Lfunc_begin3
	.short	3                               @ Loc expr size
	.byte	80                              @ DW_OP_reg0
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.long	0
	.long	0
.Ldebug_loc16:
	.long	-1
	.long	.Lfunc_begin3                   @   base address
	.long	.Ltmp138-.Lfunc_begin3
	.long	.Ltmp139-.Lfunc_begin3
	.short	2                               @ Loc expr size
	.byte	17                              @ DW_OP_consts
	.byte	8                               @ 8
	.long	.Ltmp139-.Lfunc_begin3
	.long	.Ltmp140-.Lfunc_begin3
	.short	2                               @ Loc expr size
	.byte	17                              @ DW_OP_consts
	.byte	7                               @ 7
	.long	.Ltmp140-.Lfunc_begin3
	.long	.Ltmp141-.Lfunc_begin3
	.short	2                               @ Loc expr size
	.byte	17                              @ DW_OP_consts
	.byte	6                               @ 6
	.long	.Ltmp141-.Lfunc_begin3
	.long	.Ltmp142-.Lfunc_begin3
	.short	2                               @ Loc expr size
	.byte	17                              @ DW_OP_consts
	.byte	5                               @ 5
	.long	.Ltmp142-.Lfunc_begin3
	.long	.Ltmp143-.Lfunc_begin3
	.short	2                               @ Loc expr size
	.byte	17                              @ DW_OP_consts
	.byte	4                               @ 4
	.long	.Ltmp143-.Lfunc_begin3
	.long	.Ltmp144-.Lfunc_begin3
	.short	2                               @ Loc expr size
	.byte	17                              @ DW_OP_consts
	.byte	3                               @ 3
	.long	.Ltmp144-.Lfunc_begin3
	.long	.Ltmp145-.Lfunc_begin3
	.short	2                               @ Loc expr size
	.byte	17                              @ DW_OP_consts
	.byte	2                               @ 2
	.long	.Ltmp145-.Lfunc_begin3
	.long	.Ltmp146-.Lfunc_begin3
	.short	2                               @ Loc expr size
	.byte	17                              @ DW_OP_consts
	.byte	1                               @ 1
	.long	.Ltmp146-.Lfunc_begin3
	.long	.Lfunc_end3-.Lfunc_begin3
	.short	2                               @ Loc expr size
	.byte	17                              @ DW_OP_consts
	.byte	0                               @ 0
	.long	0
	.long	0
.Ldebug_loc17:
	.long	-1
	.long	.Lfunc_begin4                   @   base address
	.long	.Lfunc_begin4-.Lfunc_begin4
	.long	.Ltmp156-.Lfunc_begin4
	.short	1                               @ Loc expr size
	.byte	80                              @ DW_OP_reg0
	.long	.Ltmp156-.Lfunc_begin4
	.long	.Lfunc_end4-.Lfunc_begin4
	.short	3                               @ Loc expr size
	.byte	163                             @ DW_OP_entry_value
	.byte	1                               @ 1
	.byte	80                              @ DW_OP_reg0
	.long	0
	.long	0
.Ldebug_loc18:
	.long	-1
	.long	.Lfunc_begin4                   @   base address
	.long	.Lfunc_begin4-.Lfunc_begin4
	.long	.Ltmp149-.Lfunc_begin4
	.short	1                               @ Loc expr size
	.byte	48                              @ DW_OP_lit0
	.long	.Ltmp149-.Lfunc_begin4
	.long	.Ltmp150-.Lfunc_begin4
	.short	1                               @ Loc expr size
	.byte	49                              @ DW_OP_lit1
	.long	.Ltmp150-.Lfunc_begin4
	.long	.Ltmp151-.Lfunc_begin4
	.short	1                               @ Loc expr size
	.byte	50                              @ DW_OP_lit2
	.long	.Ltmp151-.Lfunc_begin4
	.long	.Ltmp152-.Lfunc_begin4
	.short	1                               @ Loc expr size
	.byte	51                              @ DW_OP_lit3
	.long	.Ltmp152-.Lfunc_begin4
	.long	.Ltmp153-.Lfunc_begin4
	.short	1                               @ Loc expr size
	.byte	52                              @ DW_OP_lit4
	.long	.Ltmp153-.Lfunc_begin4
	.long	.Ltmp154-.Lfunc_begin4
	.short	1                               @ Loc expr size
	.byte	53                              @ DW_OP_lit5
	.long	.Ltmp154-.Lfunc_begin4
	.long	.Ltmp155-.Lfunc_begin4
	.short	1                               @ Loc expr size
	.byte	54                              @ DW_OP_lit6
	.long	.Ltmp155-.Lfunc_begin4
	.long	.Ltmp157-.Lfunc_begin4
	.short	1                               @ Loc expr size
	.byte	55                              @ DW_OP_lit7
	.long	.Ltmp157-.Lfunc_begin4
	.long	.Lfunc_end4-.Lfunc_begin4
	.short	1                               @ Loc expr size
	.byte	56                              @ DW_OP_lit8
	.long	0
	.long	0
.Ldebug_loc19:
	.long	-1
	.long	.Lfunc_begin5                   @   base address
	.long	.Lfunc_begin5-.Lfunc_begin5
	.long	.Ltmp167-.Lfunc_begin5
	.short	1                               @ Loc expr size
	.byte	80                              @ DW_OP_reg0
	.long	.Ltmp167-.Lfunc_begin5
	.long	.Ltmp191-.Lfunc_begin5
	.short	3                               @ Loc expr size
	.byte	163                             @ DW_OP_entry_value
	.byte	1                               @ 1
	.byte	80                              @ DW_OP_reg0
	.long	0
	.long	0
.Ldebug_loc20:
	.long	-1
	.long	.Lfunc_begin5                   @   base address
	.long	.Lfunc_begin5-.Lfunc_begin5
	.long	.Ltmp159-.Lfunc_begin5
	.short	1                               @ Loc expr size
	.byte	81                              @ DW_OP_reg1
	.long	.Ltmp159-.Lfunc_begin5
	.long	.Ltmp191-.Lfunc_begin5
	.short	2                               @ Loc expr size
	.byte	125                             @ DW_OP_breg13
	.byte	0                               @ 0
	.long	0
	.long	0
.Ldebug_loc21:
	.long	-1
	.long	.Lfunc_begin5                   @   base address
	.long	.Ltmp159-.Lfunc_begin5
	.long	.Ltmp160-.Lfunc_begin5
	.short	1                               @ Loc expr size
	.byte	48                              @ DW_OP_lit0
	.long	.Ltmp160-.Lfunc_begin5
	.long	.Ltmp161-.Lfunc_begin5
	.short	1                               @ Loc expr size
	.byte	49                              @ DW_OP_lit1
	.long	.Ltmp161-.Lfunc_begin5
	.long	.Ltmp162-.Lfunc_begin5
	.short	1                               @ Loc expr size
	.byte	50                              @ DW_OP_lit2
	.long	.Ltmp162-.Lfunc_begin5
	.long	.Ltmp163-.Lfunc_begin5
	.short	1                               @ Loc expr size
	.byte	51                              @ DW_OP_lit3
	.long	.Ltmp163-.Lfunc_begin5
	.long	.Ltmp164-.Lfunc_begin5
	.short	1                               @ Loc expr size
	.byte	52                              @ DW_OP_lit4
	.long	.Ltmp164-.Lfunc_begin5
	.long	.Ltmp165-.Lfunc_begin5
	.short	1                               @ Loc expr size
	.byte	53                              @ DW_OP_lit5
	.long	.Ltmp165-.Lfunc_begin5
	.long	.Ltmp166-.Lfunc_begin5
	.short	1                               @ Loc expr size
	.byte	54                              @ DW_OP_lit6
	.long	.Ltmp166-.Lfunc_begin5
	.long	.Ltmp168-.Lfunc_begin5
	.short	1                               @ Loc expr size
	.byte	55                              @ DW_OP_lit7
	.long	.Ltmp168-.Lfunc_begin5
	.long	.Ltmp169-.Lfunc_begin5
	.short	1                               @ Loc expr size
	.byte	56                              @ DW_OP_lit8
	.long	0
	.long	0
.Ldebug_loc22:
	.long	-1
	.long	.Lfunc_begin5                   @   base address
	.long	.Ltmp159-.Lfunc_begin5
	.long	.Ltmp167-.Lfunc_begin5
	.short	1                               @ Loc expr size
	.byte	80                              @ DW_OP_reg0
	.long	0
	.long	0
.Ldebug_loc23:
	.long	-1
	.long	.Lfunc_begin5                   @   base address
	.long	.Ltmp170-.Lfunc_begin5
	.long	.Ltmp172-.Lfunc_begin5
	.short	1                               @ Loc expr size
	.byte	81                              @ DW_OP_reg1
	.long	.Ltmp188-.Lfunc_begin5
	.long	.Ltmp190-.Lfunc_begin5
	.short	1                               @ Loc expr size
	.byte	81                              @ DW_OP_reg1
	.long	0
	.long	0
.Ldebug_loc24:
	.long	-1
	.long	.Lfunc_begin6                   @   base address
	.long	.Lfunc_begin6-.Lfunc_begin6
	.long	.Ltmp194-.Lfunc_begin6
	.short	1                               @ Loc expr size
	.byte	80                              @ DW_OP_reg0
	.long	.Ltmp194-.Lfunc_begin6
	.long	.Ltmp212-.Lfunc_begin6
	.short	1                               @ Loc expr size
	.byte	86                              @ DW_OP_reg6
	.long	.Ltmp212-.Lfunc_begin6
	.long	.Ltmp228-.Lfunc_begin6
	.short	2                               @ Loc expr size
	.byte	125                             @ DW_OP_breg13
	.byte	12                              @ 12
	.long	.Ltmp229-.Lfunc_begin6
	.long	.Ltmp231-.Lfunc_begin6
	.short	1                               @ Loc expr size
	.byte	80                              @ DW_OP_reg0
	.long	.Ltmp231-.Lfunc_begin6
	.long	.Ltmp233-.Lfunc_begin6
	.short	3                               @ Loc expr size
	.byte	163                             @ DW_OP_entry_value
	.byte	1                               @ 1
	.byte	80                              @ DW_OP_reg0
	.long	0
	.long	0
.Ldebug_loc25:
	.long	-1
	.long	.Lfunc_begin6                   @   base address
	.long	.Lfunc_begin6-.Lfunc_begin6
	.long	.Ltmp193-.Lfunc_begin6
	.short	1                               @ Loc expr size
	.byte	81                              @ DW_OP_reg1
	.long	.Ltmp193-.Lfunc_begin6
	.long	.Ltmp214-.Lfunc_begin6
	.short	1                               @ Loc expr size
	.byte	85                              @ DW_OP_reg5
	.long	.Ltmp214-.Lfunc_begin6
	.long	.Ltmp221-.Lfunc_begin6
	.short	2                               @ Loc expr size
	.byte	125                             @ DW_OP_breg13
	.byte	4                               @ 4
	.long	.Ltmp221-.Lfunc_begin6
	.long	.Ltmp222-.Lfunc_begin6
	.short	1                               @ Loc expr size
	.byte	80                              @ DW_OP_reg0
	.long	.Ltmp222-.Lfunc_begin6
	.long	.Ltmp249-.Lfunc_begin6
	.short	3                               @ Loc expr size
	.byte	163                             @ DW_OP_entry_value
	.byte	1                               @ 1
	.byte	81                              @ DW_OP_reg1
	.long	0
	.long	0
.Ldebug_loc26:
	.long	-1
	.long	.Lfunc_begin6                   @   base address
	.long	.Lfunc_begin6-.Lfunc_begin6
	.long	.Ltmp192-.Lfunc_begin6
	.short	1                               @ Loc expr size
	.byte	82                              @ DW_OP_reg2
	.long	.Ltmp192-.Lfunc_begin6
	.long	.Ltmp227-.Lfunc_begin6
	.short	1                               @ Loc expr size
	.byte	84                              @ DW_OP_reg4
	.long	.Ltmp227-.Lfunc_begin6
	.long	.Ltmp240-.Lfunc_begin6
	.short	2                               @ Loc expr size
	.byte	125                             @ DW_OP_breg13
	.byte	0                               @ 0
	.long	.Ltmp240-.Lfunc_begin6
	.long	.Ltmp274-.Lfunc_begin6
	.short	1                               @ Loc expr size
	.byte	84                              @ DW_OP_reg4
	.long	0
	.long	0
.Ldebug_loc27:
	.long	-1
	.long	.Lfunc_begin6                   @   base address
	.long	.Ltmp196-.Lfunc_begin6
	.long	.Ltmp198-.Lfunc_begin6
	.short	2                               @ Loc expr size
	.byte	125                             @ DW_OP_breg13
	.byte	16                              @ 16
	.long	.Ltmp198-.Lfunc_begin6
	.long	.Ltmp199-.Lfunc_begin6
	.short	16                              @ Loc expr size
	.byte	125                             @ DW_OP_breg13
	.byte	16                              @ 16
	.byte	147                             @ DW_OP_piece
	.byte	8                               @ 8
	.byte	125                             @ DW_OP_breg13
	.byte	16                              @ 16
	.byte	35                              @ DW_OP_plus_uconst
	.byte	8                               @ 8
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	125                             @ DW_OP_breg13
	.byte	16                              @ 16
	.byte	35                              @ DW_OP_plus_uconst
	.byte	12                              @ 12
	.byte	147                             @ DW_OP_piece
	.byte	100                             @ 100
	.long	.Ltmp199-.Lfunc_begin6
	.long	.Ltmp200-.Lfunc_begin6
	.short	16                              @ Loc expr size
	.byte	125                             @ DW_OP_breg13
	.byte	16                              @ 16
	.byte	147                             @ DW_OP_piece
	.byte	12                              @ 12
	.byte	125                             @ DW_OP_breg13
	.byte	16                              @ 16
	.byte	35                              @ DW_OP_plus_uconst
	.byte	12                              @ 12
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	125                             @ DW_OP_breg13
	.byte	16                              @ 16
	.byte	35                              @ DW_OP_plus_uconst
	.byte	16                              @ 16
	.byte	147                             @ DW_OP_piece
	.byte	96                              @ 96
	.long	.Ltmp200-.Lfunc_begin6
	.long	.Ltmp201-.Lfunc_begin6
	.short	16                              @ Loc expr size
	.byte	125                             @ DW_OP_breg13
	.byte	16                              @ 16
	.byte	147                             @ DW_OP_piece
	.byte	16                              @ 16
	.byte	125                             @ DW_OP_breg13
	.byte	16                              @ 16
	.byte	35                              @ DW_OP_plus_uconst
	.byte	16                              @ 16
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	125                             @ DW_OP_breg13
	.byte	16                              @ 16
	.byte	35                              @ DW_OP_plus_uconst
	.byte	20                              @ 20
	.byte	147                             @ DW_OP_piece
	.byte	92                              @ 92
	.long	.Ltmp201-.Lfunc_begin6
	.long	.Ltmp202-.Lfunc_begin6
	.short	16                              @ Loc expr size
	.byte	125                             @ DW_OP_breg13
	.byte	16                              @ 16
	.byte	147                             @ DW_OP_piece
	.byte	20                              @ 20
	.byte	125                             @ DW_OP_breg13
	.byte	16                              @ 16
	.byte	35                              @ DW_OP_plus_uconst
	.byte	20                              @ 20
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	125                             @ DW_OP_breg13
	.byte	16                              @ 16
	.byte	35                              @ DW_OP_plus_uconst
	.byte	24                              @ 24
	.byte	147                             @ DW_OP_piece
	.byte	88                              @ 88
	.long	.Ltmp202-.Lfunc_begin6
	.long	.Ltmp203-.Lfunc_begin6
	.short	16                              @ Loc expr size
	.byte	125                             @ DW_OP_breg13
	.byte	16                              @ 16
	.byte	147                             @ DW_OP_piece
	.byte	24                              @ 24
	.byte	125                             @ DW_OP_breg13
	.byte	16                              @ 16
	.byte	35                              @ DW_OP_plus_uconst
	.byte	24                              @ 24
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	125                             @ DW_OP_breg13
	.byte	16                              @ 16
	.byte	35                              @ DW_OP_plus_uconst
	.byte	28                              @ 28
	.byte	147                             @ DW_OP_piece
	.byte	84                              @ 84
	.long	.Ltmp203-.Lfunc_begin6
	.long	.Ltmp204-.Lfunc_begin6
	.short	16                              @ Loc expr size
	.byte	125                             @ DW_OP_breg13
	.byte	16                              @ 16
	.byte	147                             @ DW_OP_piece
	.byte	28                              @ 28
	.byte	125                             @ DW_OP_breg13
	.byte	16                              @ 16
	.byte	35                              @ DW_OP_plus_uconst
	.byte	28                              @ 28
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	125                             @ DW_OP_breg13
	.byte	16                              @ 16
	.byte	35                              @ DW_OP_plus_uconst
	.byte	32                              @ 32
	.byte	147                             @ DW_OP_piece
	.byte	80                              @ 80
	.long	.Ltmp204-.Lfunc_begin6
	.long	.Ltmp205-.Lfunc_begin6
	.short	16                              @ Loc expr size
	.byte	125                             @ DW_OP_breg13
	.byte	16                              @ 16
	.byte	147                             @ DW_OP_piece
	.byte	32                              @ 32
	.byte	125                             @ DW_OP_breg13
	.byte	16                              @ 16
	.byte	35                              @ DW_OP_plus_uconst
	.byte	32                              @ 32
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	125                             @ DW_OP_breg13
	.byte	16                              @ 16
	.byte	35                              @ DW_OP_plus_uconst
	.byte	36                              @ 36
	.byte	147                             @ DW_OP_piece
	.byte	76                              @ 76
	.long	.Ltmp205-.Lfunc_begin6
	.long	.Ltmp206-.Lfunc_begin6
	.short	9                               @ Loc expr size
	.byte	48                              @ DW_OP_lit0
	.byte	147                             @ DW_OP_piece
	.byte	8                               @ 8
	.byte	125                             @ DW_OP_breg13
	.byte	16                              @ 16
	.byte	35                              @ DW_OP_plus_uconst
	.byte	8                               @ 8
	.byte	147                             @ DW_OP_piece
	.byte	104                             @ 104
	.long	.Ltmp206-.Lfunc_begin6
	.long	.Ltmp207-.Lfunc_begin6
	.short	17                              @ Loc expr size
	.byte	48                              @ DW_OP_lit0
	.byte	147                             @ DW_OP_piece
	.byte	8                               @ 8
	.byte	125                             @ DW_OP_breg13
	.byte	16                              @ 16
	.byte	35                              @ DW_OP_plus_uconst
	.byte	8                               @ 8
	.byte	147                             @ DW_OP_piece
	.byte	96                              @ 96
	.byte	147                             @ DW_OP_piece
	.byte	1                               @ 1
	.byte	125                             @ DW_OP_breg13
	.byte	16                              @ 16
	.byte	35                              @ DW_OP_plus_uconst
	.byte	105                             @ 105
	.byte	147                             @ DW_OP_piece
	.byte	7                               @ 7
	.long	.Ltmp207-.Lfunc_begin6
	.long	.Ltmp208-.Lfunc_begin6
	.short	18                              @ Loc expr size
	.byte	125                             @ DW_OP_breg13
	.byte	16                              @ 16
	.byte	147                             @ DW_OP_piece
	.byte	8                               @ 8
	.byte	125                             @ DW_OP_breg13
	.byte	16                              @ 16
	.byte	35                              @ DW_OP_plus_uconst
	.byte	8                               @ 8
	.byte	147                             @ DW_OP_piece
	.byte	96                              @ 96
	.byte	147                             @ DW_OP_piece
	.byte	1                               @ 1
	.byte	125                             @ DW_OP_breg13
	.byte	16                              @ 16
	.byte	35                              @ DW_OP_plus_uconst
	.byte	105                             @ 105
	.byte	147                             @ DW_OP_piece
	.byte	7                               @ 7
	.long	.Ltmp208-.Lfunc_begin6
	.long	.Ltmp216-.Lfunc_begin6
	.short	18                              @ Loc expr size
	.byte	125                             @ DW_OP_breg13
	.byte	16                              @ 16
	.byte	147                             @ DW_OP_piece
	.byte	8                               @ 8
	.byte	125                             @ DW_OP_breg13
	.byte	16                              @ 16
	.byte	35                              @ DW_OP_plus_uconst
	.byte	8                               @ 8
	.byte	147                             @ DW_OP_piece
	.byte	96                              @ 96
	.byte	147                             @ DW_OP_piece
	.byte	1                               @ 1
	.byte	125                             @ DW_OP_breg13
	.byte	16                              @ 16
	.byte	35                              @ DW_OP_plus_uconst
	.byte	105                             @ 105
	.byte	147                             @ DW_OP_piece
	.byte	7                               @ 7
	.long	.Ltmp216-.Lfunc_begin6
	.long	.Ltmp217-.Lfunc_begin6
	.short	18                              @ Loc expr size
	.byte	125                             @ DW_OP_breg13
	.byte	16                              @ 16
	.byte	147                             @ DW_OP_piece
	.byte	8                               @ 8
	.byte	125                             @ DW_OP_breg13
	.byte	16                              @ 16
	.byte	35                              @ DW_OP_plus_uconst
	.byte	8                               @ 8
	.byte	147                             @ DW_OP_piece
	.byte	96                              @ 96
	.byte	147                             @ DW_OP_piece
	.byte	1                               @ 1
	.byte	125                             @ DW_OP_breg13
	.byte	16                              @ 16
	.byte	35                              @ DW_OP_plus_uconst
	.byte	105                             @ 105
	.byte	147                             @ DW_OP_piece
	.byte	7                               @ 7
	.long	.Ltmp217-.Lfunc_begin6
	.long	.Ltmp219-.Lfunc_begin6
	.short	18                              @ Loc expr size
	.byte	125                             @ DW_OP_breg13
	.byte	16                              @ 16
	.byte	147                             @ DW_OP_piece
	.byte	8                               @ 8
	.byte	125                             @ DW_OP_breg13
	.byte	16                              @ 16
	.byte	35                              @ DW_OP_plus_uconst
	.byte	8                               @ 8
	.byte	147                             @ DW_OP_piece
	.byte	96                              @ 96
	.byte	147                             @ DW_OP_piece
	.byte	1                               @ 1
	.byte	125                             @ DW_OP_breg13
	.byte	16                              @ 16
	.byte	35                              @ DW_OP_plus_uconst
	.byte	105                             @ 105
	.byte	147                             @ DW_OP_piece
	.byte	7                               @ 7
	.long	.Ltmp219-.Lfunc_begin6
	.long	.Ltmp249-.Lfunc_begin6
	.short	18                              @ Loc expr size
	.byte	125                             @ DW_OP_breg13
	.byte	16                              @ 16
	.byte	147                             @ DW_OP_piece
	.byte	8                               @ 8
	.byte	125                             @ DW_OP_breg13
	.byte	16                              @ 16
	.byte	35                              @ DW_OP_plus_uconst
	.byte	8                               @ 8
	.byte	147                             @ DW_OP_piece
	.byte	96                              @ 96
	.byte	147                             @ DW_OP_piece
	.byte	1                               @ 1
	.byte	125                             @ DW_OP_breg13
	.byte	16                              @ 16
	.byte	35                              @ DW_OP_plus_uconst
	.byte	105                             @ 105
	.byte	147                             @ DW_OP_piece
	.byte	7                               @ 7
	.long	.Ltmp249-.Lfunc_begin6
	.long	.Ltmp254-.Lfunc_begin6
	.short	18                              @ Loc expr size
	.byte	125                             @ DW_OP_breg13
	.byte	16                              @ 16
	.byte	147                             @ DW_OP_piece
	.byte	8                               @ 8
	.byte	125                             @ DW_OP_breg13
	.byte	16                              @ 16
	.byte	35                              @ DW_OP_plus_uconst
	.byte	8                               @ 8
	.byte	147                             @ DW_OP_piece
	.byte	96                              @ 96
	.byte	147                             @ DW_OP_piece
	.byte	1                               @ 1
	.byte	125                             @ DW_OP_breg13
	.byte	16                              @ 16
	.byte	35                              @ DW_OP_plus_uconst
	.byte	105                             @ 105
	.byte	147                             @ DW_OP_piece
	.byte	7                               @ 7
	.long	.Ltmp254-.Lfunc_begin6
	.long	.Ltmp258-.Lfunc_begin6
	.short	18                              @ Loc expr size
	.byte	125                             @ DW_OP_breg13
	.byte	16                              @ 16
	.byte	147                             @ DW_OP_piece
	.byte	8                               @ 8
	.byte	125                             @ DW_OP_breg13
	.byte	16                              @ 16
	.byte	35                              @ DW_OP_plus_uconst
	.byte	8                               @ 8
	.byte	147                             @ DW_OP_piece
	.byte	96                              @ 96
	.byte	147                             @ DW_OP_piece
	.byte	1                               @ 1
	.byte	125                             @ DW_OP_breg13
	.byte	16                              @ 16
	.byte	35                              @ DW_OP_plus_uconst
	.byte	105                             @ 105
	.byte	147                             @ DW_OP_piece
	.byte	7                               @ 7
	.long	.Ltmp258-.Lfunc_begin6
	.long	.Ltmp260-.Lfunc_begin6
	.short	10                              @ Loc expr size
	.byte	147                             @ DW_OP_piece
	.byte	104                             @ 104
	.byte	147                             @ DW_OP_piece
	.byte	1                               @ 1
	.byte	125                             @ DW_OP_breg13
	.byte	16                              @ 16
	.byte	35                              @ DW_OP_plus_uconst
	.byte	105                             @ 105
	.byte	147                             @ DW_OP_piece
	.byte	7                               @ 7
	.long	.Ltmp260-.Lfunc_begin6
	.long	.Ltmp262-.Lfunc_begin6
	.short	14                              @ Loc expr size
	.byte	125                             @ DW_OP_breg13
	.byte	16                              @ 16
	.byte	147                             @ DW_OP_piece
	.byte	103                             @ 103
	.byte	147                             @ DW_OP_piece
	.byte	1                               @ 1
	.byte	147                             @ DW_OP_piece
	.byte	1                               @ 1
	.byte	125                             @ DW_OP_breg13
	.byte	16                              @ 16
	.byte	35                              @ DW_OP_plus_uconst
	.byte	105                             @ 105
	.byte	147                             @ DW_OP_piece
	.byte	7                               @ 7
	.long	.Ltmp262-.Lfunc_begin6
	.long	.Ltmp263-.Lfunc_begin6
	.short	18                              @ Loc expr size
	.byte	125                             @ DW_OP_breg13
	.byte	16                              @ 16
	.byte	147                             @ DW_OP_piece
	.byte	96                              @ 96
	.byte	119                             @ DW_OP_breg7
	.byte	0                               @ 0
	.byte	147                             @ DW_OP_piece
	.byte	1                               @ 1
	.byte	147                             @ DW_OP_piece
	.byte	7                               @ 7
	.byte	147                             @ DW_OP_piece
	.byte	1                               @ 1
	.byte	125                             @ DW_OP_breg13
	.byte	16                              @ 16
	.byte	35                              @ DW_OP_plus_uconst
	.byte	105                             @ 105
	.byte	147                             @ DW_OP_piece
	.byte	7                               @ 7
	.long	.Ltmp263-.Lfunc_begin6
	.long	.Ltmp274-.Lfunc_begin6
	.short	12                              @ Loc expr size
	.byte	125                             @ DW_OP_breg13
	.byte	16                              @ 16
	.byte	147                             @ DW_OP_piece
	.byte	96                              @ 96
	.byte	147                             @ DW_OP_piece
	.byte	9                               @ 9
	.byte	125                             @ DW_OP_breg13
	.byte	16                              @ 16
	.byte	35                              @ DW_OP_plus_uconst
	.byte	105                             @ 105
	.byte	147                             @ DW_OP_piece
	.byte	7                               @ 7
	.long	0
	.long	0
.Ldebug_loc28:
	.long	-1
	.long	.Lfunc_begin6                   @   base address
	.long	.Ltmp213-.Lfunc_begin6
	.long	.Ltmp228-.Lfunc_begin6
	.short	1                               @ Loc expr size
	.byte	86                              @ DW_OP_reg6
	.long	.Ltmp241-.Lfunc_begin6
	.long	.Ltmp244-.Lfunc_begin6
	.short	1                               @ Loc expr size
	.byte	86                              @ DW_OP_reg6
	.long	.Ltmp244-.Lfunc_begin6
	.long	.Ltmp245-.Lfunc_begin6
	.short	1                               @ Loc expr size
	.byte	81                              @ DW_OP_reg1
	.long	.Ltmp247-.Lfunc_begin6
	.long	.Ltmp249-.Lfunc_begin6
	.short	1                               @ Loc expr size
	.byte	86                              @ DW_OP_reg6
	.long	0
	.long	0
.Ldebug_loc29:
	.long	-1
	.long	.Lfunc_begin6                   @   base address
	.long	.Ltmp206-.Lfunc_begin6
	.long	.Ltmp228-.Lfunc_begin6
	.short	1                               @ Loc expr size
	.byte	85                              @ DW_OP_reg5
	.long	.Ltmp241-.Lfunc_begin6
	.long	.Ltmp244-.Lfunc_begin6
	.short	1                               @ Loc expr size
	.byte	85                              @ DW_OP_reg5
	.long	.Ltmp248-.Lfunc_begin6
	.long	.Ltmp249-.Lfunc_begin6
	.short	1                               @ Loc expr size
	.byte	85                              @ DW_OP_reg5
	.long	0
	.long	0
.Ldebug_loc30:
	.long	-1
	.long	.Lfunc_begin6                   @   base address
	.long	.Ltmp259-.Lfunc_begin6
	.long	.Ltmp260-.Lfunc_begin6
	.short	5                               @ Loc expr size
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	80                              @ DW_OP_reg0
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.long	.Ltmp260-.Lfunc_begin6
	.long	.Ltmp261-.Lfunc_begin6
	.short	3                               @ Loc expr size
	.byte	81                              @ DW_OP_reg1
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.long	0
	.long	0
.Ldebug_loc31:
	.long	-1
	.long	.Lfunc_begin6                   @   base address
	.long	.Ltmp260-.Lfunc_begin6
	.long	.Ltmp262-.Lfunc_begin6
	.short	2                               @ Loc expr size
	.byte	17                              @ DW_OP_consts
	.byte	1                               @ 1
	.long	.Ltmp262-.Lfunc_begin6
	.long	.Ltmp274-.Lfunc_begin6
	.short	2                               @ Loc expr size
	.byte	17                              @ DW_OP_consts
	.byte	0                               @ 0
	.long	0
	.long	0
.Ldebug_loc32:
	.long	-1
	.long	.Lfunc_begin6                   @   base address
	.long	.Ltmp265-.Lfunc_begin6
	.long	.Ltmp266-.Lfunc_begin6
	.short	1                               @ Loc expr size
	.byte	48                              @ DW_OP_lit0
	.long	.Ltmp266-.Lfunc_begin6
	.long	.Ltmp267-.Lfunc_begin6
	.short	1                               @ Loc expr size
	.byte	49                              @ DW_OP_lit1
	.long	.Ltmp267-.Lfunc_begin6
	.long	.Ltmp268-.Lfunc_begin6
	.short	1                               @ Loc expr size
	.byte	50                              @ DW_OP_lit2
	.long	.Ltmp268-.Lfunc_begin6
	.long	.Ltmp269-.Lfunc_begin6
	.short	1                               @ Loc expr size
	.byte	51                              @ DW_OP_lit3
	.long	.Ltmp269-.Lfunc_begin6
	.long	.Ltmp270-.Lfunc_begin6
	.short	1                               @ Loc expr size
	.byte	52                              @ DW_OP_lit4
	.long	.Ltmp270-.Lfunc_begin6
	.long	.Ltmp271-.Lfunc_begin6
	.short	1                               @ Loc expr size
	.byte	53                              @ DW_OP_lit5
	.long	.Ltmp271-.Lfunc_begin6
	.long	.Ltmp272-.Lfunc_begin6
	.short	1                               @ Loc expr size
	.byte	54                              @ DW_OP_lit6
	.long	.Ltmp272-.Lfunc_begin6
	.long	.Ltmp273-.Lfunc_begin6
	.short	1                               @ Loc expr size
	.byte	55                              @ DW_OP_lit7
	.long	.Ltmp273-.Lfunc_begin6
	.long	.Ltmp274-.Lfunc_begin6
	.short	1                               @ Loc expr size
	.byte	56                              @ DW_OP_lit8
	.long	0
	.long	0
.Ldebug_loc33:
	.long	-1
	.long	.Lfunc_begin7                   @   base address
	.long	.Lfunc_begin7-.Lfunc_begin7
	.long	.Ltmp277-.Lfunc_begin7
	.short	1                               @ Loc expr size
	.byte	80                              @ DW_OP_reg0
	.long	.Ltmp277-.Lfunc_begin7
	.long	.Ltmp300-.Lfunc_begin7
	.short	3                               @ Loc expr size
	.byte	163                             @ DW_OP_entry_value
	.byte	1                               @ 1
	.byte	80                              @ DW_OP_reg0
	.long	0
	.long	0
.Ldebug_loc34:
	.long	-1
	.long	.Lfunc_begin7                   @   base address
	.long	.Lfunc_begin7-.Lfunc_begin7
	.long	.Ltmp277-.Lfunc_begin7
	.short	1                               @ Loc expr size
	.byte	81                              @ DW_OP_reg1
	.long	.Ltmp277-.Lfunc_begin7
	.long	.Ltmp300-.Lfunc_begin7
	.short	3                               @ Loc expr size
	.byte	163                             @ DW_OP_entry_value
	.byte	1                               @ 1
	.byte	81                              @ DW_OP_reg1
	.long	0
	.long	0
.Ldebug_loc35:
	.long	-1
	.long	.Lfunc_begin7                   @   base address
	.long	.Lfunc_begin7-.Lfunc_begin7
	.long	.Ltmp275-.Lfunc_begin7
	.short	1                               @ Loc expr size
	.byte	82                              @ DW_OP_reg2
	.long	.Ltmp275-.Lfunc_begin7
	.long	.Ltmp300-.Lfunc_begin7
	.short	2                               @ Loc expr size
	.byte	125                             @ DW_OP_breg13
	.byte	0                               @ 0
	.long	0
	.long	0
.Ldebug_loc36:
	.long	-1
	.long	.Lfunc_begin7                   @   base address
	.long	.Ltmp279-.Lfunc_begin7
	.long	.Ltmp281-.Lfunc_begin7
	.short	1                               @ Loc expr size
	.byte	82                              @ DW_OP_reg2
	.long	.Ltmp297-.Lfunc_begin7
	.long	.Ltmp299-.Lfunc_begin7
	.short	1                               @ Loc expr size
	.byte	82                              @ DW_OP_reg2
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
	.byte	7                               @ Abbreviation Code
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
	.byte	10                              @ Abbreviation Code
	.byte	46                              @ DW_TAG_subprogram
	.byte	1                               @ DW_CHILDREN_yes
	.byte	0                               @ EOM(1)
	.byte	0                               @ EOM(2)
	.byte	11                              @ Abbreviation Code
	.byte	52                              @ DW_TAG_variable
	.byte	0                               @ DW_CHILDREN_no
	.byte	3                               @ DW_AT_name
	.byte	14                              @ DW_FORM_strp
	.byte	73                              @ DW_AT_type
	.byte	19                              @ DW_FORM_ref4
	.byte	58                              @ DW_AT_decl_file
	.byte	11                              @ DW_FORM_data1
	.byte	59                              @ DW_AT_decl_line
	.byte	11                              @ DW_FORM_data1
	.byte	0                               @ EOM(1)
	.byte	0                               @ EOM(2)
	.byte	12                              @ Abbreviation Code
	.byte	15                              @ DW_TAG_pointer_type
	.byte	0                               @ DW_CHILDREN_no
	.byte	73                              @ DW_AT_type
	.byte	19                              @ DW_FORM_ref4
	.byte	0                               @ EOM(1)
	.byte	0                               @ EOM(2)
	.byte	13                              @ Abbreviation Code
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
	.byte	49                              @ DW_AT_abstract_origin
	.byte	19                              @ DW_FORM_ref4
	.byte	0                               @ EOM(1)
	.byte	0                               @ EOM(2)
	.byte	14                              @ Abbreviation Code
	.byte	5                               @ DW_TAG_formal_parameter
	.byte	0                               @ DW_CHILDREN_no
	.byte	2                               @ DW_AT_location
	.byte	10                              @ DW_FORM_block1
	.byte	49                              @ DW_AT_abstract_origin
	.byte	19                              @ DW_FORM_ref4
	.byte	0                               @ EOM(1)
	.byte	0                               @ EOM(2)
	.byte	15                              @ Abbreviation Code
	.byte	5                               @ DW_TAG_formal_parameter
	.byte	0                               @ DW_CHILDREN_no
	.byte	2                               @ DW_AT_location
	.byte	6                               @ DW_FORM_data4
	.byte	49                              @ DW_AT_abstract_origin
	.byte	19                              @ DW_FORM_ref4
	.byte	0                               @ EOM(1)
	.byte	0                               @ EOM(2)
	.byte	16                              @ Abbreviation Code
	.byte	52                              @ DW_TAG_variable
	.byte	0                               @ DW_CHILDREN_no
	.byte	2                               @ DW_AT_location
	.byte	6                               @ DW_FORM_data4
	.byte	49                              @ DW_AT_abstract_origin
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
	.byte	10                              @ DW_FORM_block1
	.byte	49                              @ DW_AT_abstract_origin
	.byte	19                              @ DW_FORM_ref4
	.byte	0                               @ EOM(1)
	.byte	0                               @ EOM(2)
	.byte	19                              @ Abbreviation Code
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
	.byte	20                              @ Abbreviation Code
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
	.byte	0                               @ EOM(1)
	.byte	0                               @ EOM(2)
	.byte	21                              @ Abbreviation Code
	.byte	5                               @ DW_TAG_formal_parameter
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
	.byte	22                              @ Abbreviation Code
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
	.byte	23                              @ Abbreviation Code
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
	.byte	24                              @ Abbreviation Code
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
	.byte	25                              @ Abbreviation Code
	.byte	46                              @ DW_TAG_subprogram
	.byte	1                               @ DW_CHILDREN_yes
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
	.byte	32                              @ DW_AT_inline
	.byte	11                              @ DW_FORM_data1
	.byte	0                               @ EOM(1)
	.byte	0                               @ EOM(2)
	.byte	26                              @ Abbreviation Code
	.byte	5                               @ DW_TAG_formal_parameter
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
	.byte	27                              @ Abbreviation Code
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
	.byte	28                              @ Abbreviation Code
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
	.byte	29                              @ Abbreviation Code
	.byte	46                              @ DW_TAG_subprogram
	.byte	1                               @ DW_CHILDREN_yes
	.byte	3                               @ DW_AT_name
	.byte	14                              @ DW_FORM_strp
	.byte	58                              @ DW_AT_decl_file
	.byte	11                              @ DW_FORM_data1
	.byte	59                              @ DW_AT_decl_line
	.byte	11                              @ DW_FORM_data1
	.byte	39                              @ DW_AT_prototyped
	.byte	12                              @ DW_FORM_flag
	.byte	32                              @ DW_AT_inline
	.byte	11                              @ DW_FORM_data1
	.byte	0                               @ EOM(1)
	.byte	0                               @ EOM(2)
	.byte	30                              @ Abbreviation Code
	.byte	11                              @ DW_TAG_lexical_block
	.byte	1                               @ DW_CHILDREN_yes
	.byte	0                               @ EOM(1)
	.byte	0                               @ EOM(2)
	.byte	31                              @ Abbreviation Code
	.byte	38                              @ DW_TAG_const_type
	.byte	0                               @ DW_CHILDREN_no
	.byte	0                               @ EOM(1)
	.byte	0                               @ EOM(2)
	.byte	32                              @ Abbreviation Code
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
	.byte	33                              @ Abbreviation Code
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
	.byte	34                              @ Abbreviation Code
	.byte	5                               @ DW_TAG_formal_parameter
	.byte	0                               @ DW_CHILDREN_no
	.byte	49                              @ DW_AT_abstract_origin
	.byte	19                              @ DW_FORM_ref4
	.byte	0                               @ EOM(1)
	.byte	0                               @ EOM(2)
	.byte	35                              @ Abbreviation Code
	.byte	5                               @ DW_TAG_formal_parameter
	.byte	0                               @ DW_CHILDREN_no
	.byte	28                              @ DW_AT_const_value
	.byte	15                              @ DW_FORM_udata
	.byte	49                              @ DW_AT_abstract_origin
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
	.byte	1                               @ Abbrev [1] 0xb:0x6a7 DW_TAG_compile_unit
	.long	.Linfo_string0                  @ DW_AT_producer
	.short	29                              @ DW_AT_language
	.long	.Linfo_string1                  @ DW_AT_name
	.long	.Lline_table_start0             @ DW_AT_stmt_list
	.long	.Linfo_string2                  @ DW_AT_comp_dir
	.long	0                               @ DW_AT_low_pc
	.long	.Ldebug_ranges0                 @ DW_AT_ranges
	.byte	2                               @ Abbrev [2] 0x26:0x11 DW_TAG_variable
	.long	.Linfo_string3                  @ DW_AT_name
	.long	55                              @ DW_AT_type
	.byte	3                               @ DW_AT_decl_file
	.byte	43                              @ DW_AT_decl_line
	.byte	5                               @ DW_AT_location
	.byte	3
	.long	k
	.byte	3                               @ Abbrev [3] 0x37:0xc DW_TAG_array_type
	.long	67                              @ DW_AT_type
	.byte	4                               @ Abbrev [4] 0x3c:0x6 DW_TAG_subrange_type
	.long	101                             @ DW_AT_type
	.byte	64                              @ DW_AT_count
	.byte	0                               @ End Of Children Mark
	.byte	5                               @ Abbrev [5] 0x43:0x5 DW_TAG_const_type
	.long	72                              @ DW_AT_type
	.byte	6                               @ Abbrev [6] 0x48:0xb DW_TAG_typedef
	.long	83                              @ DW_AT_type
	.long	.Linfo_string6                  @ DW_AT_name
	.byte	2                               @ DW_AT_decl_file
	.byte	70                              @ DW_AT_decl_line
	.byte	6                               @ Abbrev [6] 0x53:0xb DW_TAG_typedef
	.long	94                              @ DW_AT_type
	.long	.Linfo_string5                  @ DW_AT_name
	.byte	1                               @ DW_AT_decl_file
	.byte	79                              @ DW_AT_decl_line
	.byte	7                               @ Abbrev [7] 0x5e:0x7 DW_TAG_base_type
	.long	.Linfo_string4                  @ DW_AT_name
	.byte	7                               @ DW_AT_encoding
	.byte	4                               @ DW_AT_byte_size
	.byte	8                               @ Abbrev [8] 0x65:0x7 DW_TAG_base_type
	.long	.Linfo_string7                  @ DW_AT_name
	.byte	8                               @ DW_AT_byte_size
	.byte	7                               @ DW_AT_encoding
	.byte	9                               @ Abbrev [9] 0x6c:0xd DW_TAG_variable
	.long	121                             @ DW_AT_type
	.byte	3                               @ DW_AT_decl_file
	.byte	155                             @ DW_AT_decl_line
	.byte	5                               @ DW_AT_location
	.byte	3
	.long	.L.str
	.byte	3                               @ Abbrev [3] 0x79:0xc DW_TAG_array_type
	.long	133                             @ DW_AT_type
	.byte	4                               @ Abbrev [4] 0x7e:0x6 DW_TAG_subrange_type
	.long	101                             @ DW_AT_type
	.byte	17                              @ DW_AT_count
	.byte	0                               @ End Of Children Mark
	.byte	7                               @ Abbrev [7] 0x85:0x7 DW_TAG_base_type
	.long	.Linfo_string8                  @ DW_AT_name
	.byte	8                               @ DW_AT_encoding
	.byte	1                               @ DW_AT_byte_size
	.byte	10                              @ Abbrev [10] 0x8c:0xd DW_TAG_subprogram
	.byte	11                              @ Abbrev [11] 0x8d:0xb DW_TAG_variable
	.long	.Linfo_string9                  @ DW_AT_name
	.long	153                             @ DW_AT_type
	.byte	3                               @ DW_AT_decl_file
	.byte	155                             @ DW_AT_decl_line
	.byte	0                               @ End Of Children Mark
	.byte	5                               @ Abbrev [5] 0x99:0x5 DW_TAG_const_type
	.long	158                             @ DW_AT_type
	.byte	12                              @ Abbrev [12] 0x9e:0x5 DW_TAG_pointer_type
	.long	163                             @ DW_AT_type
	.byte	5                               @ Abbrev [5] 0xa3:0x5 DW_TAG_const_type
	.long	133                             @ DW_AT_type
	.byte	12                              @ Abbrev [12] 0xa8:0x5 DW_TAG_pointer_type
	.long	173                             @ DW_AT_type
	.byte	5                               @ Abbrev [5] 0xad:0x5 DW_TAG_const_type
	.long	178                             @ DW_AT_type
	.byte	6                               @ Abbrev [6] 0xb2:0xb DW_TAG_typedef
	.long	189                             @ DW_AT_type
	.long	.Linfo_string12                 @ DW_AT_name
	.byte	2                               @ DW_AT_decl_file
	.byte	59                              @ DW_AT_decl_line
	.byte	6                               @ Abbrev [6] 0xbd:0xb DW_TAG_typedef
	.long	200                             @ DW_AT_type
	.long	.Linfo_string11                 @ DW_AT_name
	.byte	1                               @ DW_AT_decl_file
	.byte	75                              @ DW_AT_decl_line
	.byte	7                               @ Abbrev [7] 0xc8:0x7 DW_TAG_base_type
	.long	.Linfo_string10                 @ DW_AT_name
	.byte	8                               @ DW_AT_encoding
	.byte	1                               @ DW_AT_byte_size
	.byte	13                              @ Abbrev [13] 0xcf:0x18 DW_TAG_subprogram
	.long	.Lfunc_begin0                   @ DW_AT_low_pc
	.long	.Lfunc_end0                     @ DW_AT_high_pc
	.byte	1                               @ DW_AT_frame_base
	.byte	93
	.byte	20                              @ DW_AT_TI_max_frame_size
	.long	1085                            @ DW_AT_abstract_origin
	.byte	14                              @ Abbrev [14] 0xdf:0x7 DW_TAG_formal_parameter
	.byte	1                               @ DW_AT_location
	.byte	80
	.long	1095                            @ DW_AT_abstract_origin
	.byte	0                               @ End Of Children Mark
	.byte	13                              @ Abbrev [13] 0xe7:0x83 DW_TAG_subprogram
	.long	.Lfunc_begin1                   @ DW_AT_low_pc
	.long	.Lfunc_end1                     @ DW_AT_high_pc
	.byte	1                               @ DW_AT_frame_base
	.byte	93
	.byte	96                              @ DW_AT_TI_max_frame_size
	.long	1112                            @ DW_AT_abstract_origin
	.byte	15                              @ Abbrev [15] 0xf7:0x9 DW_TAG_formal_parameter
	.long	.Ldebug_loc0                    @ DW_AT_location
	.long	1122                            @ DW_AT_abstract_origin
	.byte	15                              @ Abbrev [15] 0x100:0x9 DW_TAG_formal_parameter
	.long	.Ldebug_loc1                    @ DW_AT_location
	.long	1133                            @ DW_AT_abstract_origin
	.byte	15                              @ Abbrev [15] 0x109:0x9 DW_TAG_formal_parameter
	.long	.Ldebug_loc2                    @ DW_AT_location
	.long	1144                            @ DW_AT_abstract_origin
	.byte	16                              @ Abbrev [16] 0x112:0x9 DW_TAG_variable
	.long	.Ldebug_loc3                    @ DW_AT_location
	.long	1155                            @ DW_AT_abstract_origin
	.byte	17                              @ Abbrev [17] 0x11b:0x12 DW_TAG_lexical_block
	.long	.Ltmp8                          @ DW_AT_low_pc
	.long	.Ltmp13                         @ DW_AT_high_pc
	.byte	18                              @ Abbrev [18] 0x124:0x8 DW_TAG_variable
	.byte	2                               @ DW_AT_location
	.byte	145
	.byte	12
	.long	1167                            @ DW_AT_abstract_origin
	.byte	0                               @ End Of Children Mark
	.byte	19                              @ Abbrev [19] 0x12d:0xa DW_TAG_TI_reserved_3
	.long	.Ltmp13                         @ DW_AT_low_pc
	.byte	1                               @ DW_AT_TI_reserved_9
	.long	.Linfo_string13                 @ DW_AT_name
	.byte	19                              @ Abbrev [19] 0x137:0xa DW_TAG_TI_reserved_3
	.long	.Ltmp19                         @ DW_AT_low_pc
	.byte	1                               @ DW_AT_TI_reserved_9
	.long	.Linfo_string13                 @ DW_AT_name
	.byte	19                              @ Abbrev [19] 0x141:0xa DW_TAG_TI_reserved_3
	.long	.Ltmp22                         @ DW_AT_low_pc
	.byte	1                               @ DW_AT_TI_reserved_9
	.long	.Linfo_string13                 @ DW_AT_name
	.byte	19                              @ Abbrev [19] 0x14b:0xa DW_TAG_TI_reserved_3
	.long	.Ltmp30                         @ DW_AT_low_pc
	.byte	1                               @ DW_AT_TI_reserved_9
	.long	.Linfo_string13                 @ DW_AT_name
	.byte	19                              @ Abbrev [19] 0x155:0xa DW_TAG_TI_reserved_3
	.long	.Ltmp32                         @ DW_AT_low_pc
	.byte	1                               @ DW_AT_TI_reserved_9
	.long	.Linfo_string13                 @ DW_AT_name
	.byte	19                              @ Abbrev [19] 0x15f:0xa DW_TAG_TI_reserved_3
	.long	.Ltmp33                         @ DW_AT_low_pc
	.byte	1                               @ DW_AT_TI_reserved_9
	.long	.Linfo_string13                 @ DW_AT_name
	.byte	0                               @ End Of Children Mark
	.byte	20                              @ Abbrev [20] 0x16a:0xe4 DW_TAG_subprogram
	.long	.Lfunc_begin2                   @ DW_AT_low_pc
	.long	.Lfunc_end2                     @ DW_AT_high_pc
	.byte	1                               @ DW_AT_frame_base
	.byte	93
	.short	344                             @ DW_AT_TI_max_frame_size
	.long	.Linfo_string13                 @ DW_AT_name
	.byte	3                               @ DW_AT_decl_file
	.byte	56                              @ DW_AT_decl_line
	.byte	1                               @ DW_AT_prototyped
	.byte	21                              @ Abbrev [21] 0x17e:0xf DW_TAG_formal_parameter
	.long	.Ldebug_loc4                    @ DW_AT_location
	.long	.Linfo_string15                 @ DW_AT_name
	.byte	3                               @ DW_AT_decl_file
	.byte	56                              @ DW_AT_decl_line
	.long	1107                            @ DW_AT_type
	.byte	21                              @ Abbrev [21] 0x18d:0xf DW_TAG_formal_parameter
	.long	.Ldebug_loc5                    @ DW_AT_location
	.long	.Linfo_string43                 @ DW_AT_name
	.byte	3                               @ DW_AT_decl_file
	.byte	56                              @ DW_AT_decl_line
	.long	168                             @ DW_AT_type
	.byte	22                              @ Abbrev [22] 0x19c:0xf DW_TAG_variable
	.byte	3                               @ DW_AT_location
	.byte	145
	.asciz	"\304"
	.long	.Linfo_string42                 @ DW_AT_name
	.byte	3                               @ DW_AT_decl_file
	.byte	57                              @ DW_AT_decl_line
	.long	1689                            @ DW_AT_type
	.byte	23                              @ Abbrev [23] 0x1ab:0xf DW_TAG_variable
	.long	.Ldebug_loc6                    @ DW_AT_location
	.long	.Linfo_string25                 @ DW_AT_name
	.byte	3                               @ DW_AT_decl_file
	.byte	59                              @ DW_AT_decl_line
	.long	72                              @ DW_AT_type
	.byte	23                              @ Abbrev [23] 0x1ba:0xf DW_TAG_variable
	.long	.Ldebug_loc9                    @ DW_AT_location
	.long	.Linfo_string46                 @ DW_AT_name
	.byte	3                               @ DW_AT_decl_file
	.byte	58                              @ DW_AT_decl_line
	.long	836                             @ DW_AT_type
	.byte	17                              @ Abbrev [17] 0x1c9:0x28 DW_TAG_lexical_block
	.long	.Ltmp51                         @ DW_AT_low_pc
	.long	.Ltmp75                         @ DW_AT_high_pc
	.byte	23                              @ Abbrev [23] 0x1d2:0xf DW_TAG_variable
	.long	.Ldebug_loc7                    @ DW_AT_location
	.long	.Linfo_string44                 @ DW_AT_name
	.byte	3                               @ DW_AT_decl_file
	.byte	67                              @ DW_AT_decl_line
	.long	72                              @ DW_AT_type
	.byte	23                              @ Abbrev [23] 0x1e1:0xf DW_TAG_variable
	.long	.Ldebug_loc8                    @ DW_AT_location
	.long	.Linfo_string45                 @ DW_AT_name
	.byte	3                               @ DW_AT_decl_file
	.byte	68                              @ DW_AT_decl_line
	.long	72                              @ DW_AT_type
	.byte	0                               @ End Of Children Mark
	.byte	17                              @ Abbrev [17] 0x1f1:0x5c DW_TAG_lexical_block
	.long	.Ltmp98                         @ DW_AT_low_pc
	.long	.Ltmp112                        @ DW_AT_high_pc
	.byte	23                              @ Abbrev [23] 0x1fa:0xf DW_TAG_variable
	.long	.Ldebug_loc10                   @ DW_AT_location
	.long	.Linfo_string47                 @ DW_AT_name
	.byte	3                               @ DW_AT_decl_file
	.byte	76                              @ DW_AT_decl_line
	.long	72                              @ DW_AT_type
	.byte	23                              @ Abbrev [23] 0x209:0xf DW_TAG_variable
	.long	.Ldebug_loc11                   @ DW_AT_location
	.long	.Linfo_string48                 @ DW_AT_name
	.byte	3                               @ DW_AT_decl_file
	.byte	78                              @ DW_AT_decl_line
	.long	72                              @ DW_AT_type
	.byte	23                              @ Abbrev [23] 0x218:0xf DW_TAG_variable
	.long	.Ldebug_loc12                   @ DW_AT_location
	.long	.Linfo_string49                 @ DW_AT_name
	.byte	3                               @ DW_AT_decl_file
	.byte	79                              @ DW_AT_decl_line
	.long	72                              @ DW_AT_type
	.byte	23                              @ Abbrev [23] 0x227:0xf DW_TAG_variable
	.long	.Ldebug_loc13                   @ DW_AT_location
	.long	.Linfo_string50                 @ DW_AT_name
	.byte	3                               @ DW_AT_decl_file
	.byte	80                              @ DW_AT_decl_line
	.long	72                              @ DW_AT_type
	.byte	24                              @ Abbrev [24] 0x236:0xb DW_TAG_variable
	.long	.Linfo_string51                 @ DW_AT_name
	.byte	3                               @ DW_AT_decl_file
	.byte	77                              @ DW_AT_decl_line
	.long	72                              @ DW_AT_type
	.byte	24                              @ Abbrev [24] 0x241:0xb DW_TAG_variable
	.long	.Linfo_string52                 @ DW_AT_name
	.byte	3                               @ DW_AT_decl_file
	.byte	81                              @ DW_AT_decl_line
	.long	72                              @ DW_AT_type
	.byte	0                               @ End Of Children Mark
	.byte	0                               @ End Of Children Mark
	.byte	13                              @ Abbrev [13] 0x24e:0x40 DW_TAG_subprogram
	.long	.Lfunc_begin3                   @ DW_AT_low_pc
	.long	.Lfunc_end3                     @ DW_AT_high_pc
	.byte	1                               @ DW_AT_frame_base
	.byte	93
	.byte	24                              @ DW_AT_TI_max_frame_size
	.long	1191                            @ DW_AT_abstract_origin
	.byte	15                              @ Abbrev [15] 0x25e:0x9 DW_TAG_formal_parameter
	.long	.Ldebug_loc14                   @ DW_AT_location
	.long	1201                            @ DW_AT_abstract_origin
	.byte	16                              @ Abbrev [16] 0x267:0x9 DW_TAG_variable
	.long	.Ldebug_loc15                   @ DW_AT_location
	.long	1212                            @ DW_AT_abstract_origin
	.byte	16                              @ Abbrev [16] 0x270:0x9 DW_TAG_variable
	.long	.Ldebug_loc16                   @ DW_AT_location
	.long	1223                            @ DW_AT_abstract_origin
	.byte	19                              @ Abbrev [19] 0x279:0xa DW_TAG_TI_reserved_3
	.long	.Ltmp136                        @ DW_AT_low_pc
	.byte	1                               @ DW_AT_TI_reserved_9
	.long	.Linfo_string13                 @ DW_AT_name
	.byte	19                              @ Abbrev [19] 0x283:0xa DW_TAG_TI_reserved_3
	.long	.Ltmp147                        @ DW_AT_low_pc
	.byte	1                               @ DW_AT_TI_reserved_9
	.long	.Linfo_string13                 @ DW_AT_name
	.byte	0                               @ End Of Children Mark
	.byte	13                              @ Abbrev [13] 0x28e:0x2a DW_TAG_subprogram
	.long	.Lfunc_begin4                   @ DW_AT_low_pc
	.long	.Lfunc_end4                     @ DW_AT_high_pc
	.byte	1                               @ DW_AT_frame_base
	.byte	93
	.byte	0                               @ DW_AT_TI_max_frame_size
	.long	696                             @ DW_AT_abstract_origin
	.byte	15                              @ Abbrev [15] 0x29e:0x9 DW_TAG_formal_parameter
	.long	.Ldebug_loc17                   @ DW_AT_location
	.long	706                             @ DW_AT_abstract_origin
	.byte	14                              @ Abbrev [14] 0x2a7:0x7 DW_TAG_formal_parameter
	.byte	1                               @ DW_AT_location
	.byte	81
	.long	717                             @ DW_AT_abstract_origin
	.byte	16                              @ Abbrev [16] 0x2ae:0x9 DW_TAG_variable
	.long	.Ldebug_loc18                   @ DW_AT_location
	.long	728                             @ DW_AT_abstract_origin
	.byte	0                               @ End Of Children Mark
	.byte	25                              @ Abbrev [25] 0x2b8:0x2c DW_TAG_subprogram
	.long	.Linfo_string14                 @ DW_AT_name
	.byte	3                               @ DW_AT_decl_file
	.byte	144                             @ DW_AT_decl_line
	.byte	1                               @ DW_AT_prototyped
	.byte	1                               @ DW_AT_external
	.byte	1                               @ DW_AT_inline
	.byte	26                              @ Abbrev [26] 0x2c2:0xb DW_TAG_formal_parameter
	.long	.Linfo_string15                 @ DW_AT_name
	.byte	3                               @ DW_AT_decl_file
	.byte	144                             @ DW_AT_decl_line
	.long	740                             @ DW_AT_type
	.byte	26                              @ Abbrev [26] 0x2cd:0xb DW_TAG_formal_parameter
	.long	.Linfo_string24                 @ DW_AT_name
	.byte	3                               @ DW_AT_decl_file
	.byte	144                             @ DW_AT_decl_line
	.long	860                             @ DW_AT_type
	.byte	24                              @ Abbrev [24] 0x2d8:0xb DW_TAG_variable
	.long	.Linfo_string25                 @ DW_AT_name
	.byte	3                               @ DW_AT_decl_file
	.byte	145                             @ DW_AT_decl_line
	.long	72                              @ DW_AT_type
	.byte	0                               @ End Of Children Mark
	.byte	12                              @ Abbrev [12] 0x2e4:0x5 DW_TAG_pointer_type
	.long	745                             @ DW_AT_type
	.byte	5                               @ Abbrev [5] 0x2e9:0x5 DW_TAG_const_type
	.long	750                             @ DW_AT_type
	.byte	27                              @ Abbrev [27] 0x2ee:0x39 DW_TAG_structure_type
	.long	.Linfo_string23                 @ DW_AT_name
	.byte	112                             @ DW_AT_byte_size
	.byte	4                               @ DW_AT_decl_file
	.byte	36                              @ DW_AT_decl_line
	.byte	28                              @ Abbrev [28] 0x2f6:0xc DW_TAG_member
	.long	.Linfo_string16                 @ DW_AT_name
	.long	807                             @ DW_AT_type
	.byte	4                               @ DW_AT_decl_file
	.byte	37                              @ DW_AT_decl_line
	.byte	0                               @ DW_AT_data_member_location
	.byte	28                              @ Abbrev [28] 0x302:0xc DW_TAG_member
	.long	.Linfo_string20                 @ DW_AT_name
	.long	836                             @ DW_AT_type
	.byte	4                               @ DW_AT_decl_file
	.byte	38                              @ DW_AT_decl_line
	.byte	8                               @ DW_AT_data_member_location
	.byte	28                              @ Abbrev [28] 0x30e:0xc DW_TAG_member
	.long	.Linfo_string21                 @ DW_AT_name
	.long	848                             @ DW_AT_type
	.byte	4                               @ DW_AT_decl_file
	.byte	39                              @ DW_AT_decl_line
	.byte	40                              @ DW_AT_data_member_location
	.byte	28                              @ Abbrev [28] 0x31a:0xc DW_TAG_member
	.long	.Linfo_string22                 @ DW_AT_name
	.long	178                             @ DW_AT_type
	.byte	4                               @ DW_AT_decl_file
	.byte	40                              @ DW_AT_decl_line
	.byte	104                             @ DW_AT_data_member_location
	.byte	0                               @ End Of Children Mark
	.byte	6                               @ Abbrev [6] 0x327:0xb DW_TAG_typedef
	.long	818                             @ DW_AT_type
	.long	.Linfo_string19                 @ DW_AT_name
	.byte	2                               @ DW_AT_decl_file
	.byte	75                              @ DW_AT_decl_line
	.byte	6                               @ Abbrev [6] 0x332:0xb DW_TAG_typedef
	.long	829                             @ DW_AT_type
	.long	.Linfo_string18                 @ DW_AT_name
	.byte	1                               @ DW_AT_decl_file
	.byte	89                              @ DW_AT_decl_line
	.byte	7                               @ Abbrev [7] 0x33d:0x7 DW_TAG_base_type
	.long	.Linfo_string17                 @ DW_AT_name
	.byte	7                               @ DW_AT_encoding
	.byte	8                               @ DW_AT_byte_size
	.byte	3                               @ Abbrev [3] 0x344:0xc DW_TAG_array_type
	.long	72                              @ DW_AT_type
	.byte	4                               @ Abbrev [4] 0x349:0x6 DW_TAG_subrange_type
	.long	101                             @ DW_AT_type
	.byte	8                               @ DW_AT_count
	.byte	0                               @ End Of Children Mark
	.byte	3                               @ Abbrev [3] 0x350:0xc DW_TAG_array_type
	.long	178                             @ DW_AT_type
	.byte	4                               @ Abbrev [4] 0x355:0x6 DW_TAG_subrange_type
	.long	101                             @ DW_AT_type
	.byte	64                              @ DW_AT_count
	.byte	0                               @ End Of Children Mark
	.byte	12                              @ Abbrev [12] 0x35c:0x5 DW_TAG_pointer_type
	.long	178                             @ DW_AT_type
	.byte	29                              @ Abbrev [29] 0x361:0x43 DW_TAG_subprogram
	.long	.Linfo_string26                 @ DW_AT_name
	.byte	3                               @ DW_AT_decl_file
	.byte	154                             @ DW_AT_decl_line
	.byte	1                               @ DW_AT_prototyped
	.byte	1                               @ DW_AT_inline
	.byte	26                              @ Abbrev [26] 0x36a:0xb DW_TAG_formal_parameter
	.long	.Linfo_string27                 @ DW_AT_name
	.byte	3                               @ DW_AT_decl_file
	.byte	154                             @ DW_AT_decl_line
	.long	932                             @ DW_AT_type
	.byte	26                              @ Abbrev [26] 0x375:0xb DW_TAG_formal_parameter
	.long	.Linfo_string28                 @ DW_AT_name
	.byte	3                               @ DW_AT_decl_file
	.byte	154                             @ DW_AT_decl_line
	.long	72                              @ DW_AT_type
	.byte	26                              @ Abbrev [26] 0x380:0xb DW_TAG_formal_parameter
	.long	.Linfo_string29                 @ DW_AT_name
	.byte	3                               @ DW_AT_decl_file
	.byte	154                             @ DW_AT_decl_line
	.long	938                             @ DW_AT_type
	.byte	24                              @ Abbrev [24] 0x38b:0xb DW_TAG_variable
	.long	.Linfo_string25                 @ DW_AT_name
	.byte	3                               @ DW_AT_decl_file
	.byte	156                             @ DW_AT_decl_line
	.long	72                              @ DW_AT_type
	.byte	30                              @ Abbrev [30] 0x396:0xd DW_TAG_lexical_block
	.byte	24                              @ Abbrev [24] 0x397:0xb DW_TAG_variable
	.long	.Linfo_string30                 @ DW_AT_name
	.byte	3                               @ DW_AT_decl_file
	.byte	158                             @ DW_AT_decl_line
	.long	178                             @ DW_AT_type
	.byte	0                               @ End Of Children Mark
	.byte	0                               @ End Of Children Mark
	.byte	12                              @ Abbrev [12] 0x3a4:0x5 DW_TAG_pointer_type
	.long	937                             @ DW_AT_type
	.byte	31                              @ Abbrev [31] 0x3a9:0x1 DW_TAG_const_type
	.byte	12                              @ Abbrev [12] 0x3aa:0x5 DW_TAG_pointer_type
	.long	133                             @ DW_AT_type
	.byte	32                              @ Abbrev [32] 0x3af:0x8e DW_TAG_subprogram
	.long	.Lfunc_begin5                   @ DW_AT_low_pc
	.long	.Lfunc_end5                     @ DW_AT_high_pc
	.byte	1                               @ DW_AT_frame_base
	.byte	93
	.byte	56                              @ DW_AT_TI_max_frame_size
	.long	.Linfo_string40                 @ DW_AT_name
	.byte	3                               @ DW_AT_decl_file
	.byte	164                             @ DW_AT_decl_line
	.byte	1                               @ DW_AT_prototyped
	.byte	1                               @ DW_AT_external
	.byte	21                              @ Abbrev [21] 0x3c3:0xf DW_TAG_formal_parameter
	.long	.Ldebug_loc19                   @ DW_AT_location
	.long	.Linfo_string15                 @ DW_AT_name
	.byte	3                               @ DW_AT_decl_file
	.byte	164                             @ DW_AT_decl_line
	.long	740                             @ DW_AT_type
	.byte	21                              @ Abbrev [21] 0x3d2:0xf DW_TAG_formal_parameter
	.long	.Ldebug_loc20                   @ DW_AT_location
	.long	.Linfo_string53                 @ DW_AT_name
	.byte	3                               @ DW_AT_decl_file
	.byte	164                             @ DW_AT_decl_line
	.long	938                             @ DW_AT_type
	.byte	22                              @ Abbrev [22] 0x3e1:0xe DW_TAG_variable
	.byte	2                               @ DW_AT_location
	.byte	145
	.byte	4
	.long	.Linfo_string24                 @ DW_AT_name
	.byte	3                               @ DW_AT_decl_file
	.byte	165                             @ DW_AT_decl_line
	.long	1701                            @ DW_AT_type
	.byte	33                              @ Abbrev [33] 0x3ef:0x28 DW_TAG_inlined_subroutine
	.long	696                             @ DW_AT_abstract_origin
	.long	.Ltmp159                        @ DW_AT_low_pc
	.long	.Ltmp169                        @ DW_AT_high_pc
	.byte	3                               @ DW_AT_call_file
	.byte	166                             @ DW_AT_call_line
	.byte	5                               @ DW_AT_call_column
	.byte	15                              @ Abbrev [15] 0x3ff:0x9 DW_TAG_formal_parameter
	.long	.Ldebug_loc22                   @ DW_AT_location
	.long	706                             @ DW_AT_abstract_origin
	.byte	34                              @ Abbrev [34] 0x408:0x5 DW_TAG_formal_parameter
	.long	717                             @ DW_AT_abstract_origin
	.byte	16                              @ Abbrev [16] 0x40d:0x9 DW_TAG_variable
	.long	.Ldebug_loc21                   @ DW_AT_location
	.long	728                             @ DW_AT_abstract_origin
	.byte	0                               @ End Of Children Mark
	.byte	33                              @ Abbrev [33] 0x417:0x25 DW_TAG_inlined_subroutine
	.long	865                             @ DW_AT_abstract_origin
	.long	.Ltmp170                        @ DW_AT_low_pc
	.long	.Ltmp190                        @ DW_AT_high_pc
	.byte	3                               @ DW_AT_call_file
	.byte	167                             @ DW_AT_call_line
	.byte	5                               @ DW_AT_call_column
	.byte	34                              @ Abbrev [34] 0x427:0x5 DW_TAG_formal_parameter
	.long	874                             @ DW_AT_abstract_origin
	.byte	35                              @ Abbrev [35] 0x42c:0x6 DW_TAG_formal_parameter
	.byte	32                              @ DW_AT_const_value
	.long	885                             @ DW_AT_abstract_origin
	.byte	16                              @ Abbrev [16] 0x432:0x9 DW_TAG_variable
	.long	.Ldebug_loc23                   @ DW_AT_location
	.long	907                             @ DW_AT_abstract_origin
	.byte	0                               @ End Of Children Mark
	.byte	0                               @ End Of Children Mark
	.byte	25                              @ Abbrev [25] 0x43d:0x16 DW_TAG_subprogram
	.long	.Linfo_string31                 @ DW_AT_name
	.byte	3                               @ DW_AT_decl_file
	.byte	30                              @ DW_AT_decl_line
	.byte	1                               @ DW_AT_prototyped
	.byte	1                               @ DW_AT_external
	.byte	1                               @ DW_AT_inline
	.byte	26                              @ Abbrev [26] 0x447:0xb DW_TAG_formal_parameter
	.long	.Linfo_string15                 @ DW_AT_name
	.byte	3                               @ DW_AT_decl_file
	.byte	30                              @ DW_AT_decl_line
	.long	1107                            @ DW_AT_type
	.byte	0                               @ End Of Children Mark
	.byte	12                              @ Abbrev [12] 0x453:0x5 DW_TAG_pointer_type
	.long	750                             @ DW_AT_type
	.byte	25                              @ Abbrev [25] 0x458:0x44 DW_TAG_subprogram
	.long	.Linfo_string32                 @ DW_AT_name
	.byte	3                               @ DW_AT_decl_file
	.byte	97                              @ DW_AT_decl_line
	.byte	1                               @ DW_AT_prototyped
	.byte	1                               @ DW_AT_external
	.byte	1                               @ DW_AT_inline
	.byte	26                              @ Abbrev [26] 0x462:0xb DW_TAG_formal_parameter
	.long	.Linfo_string15                 @ DW_AT_name
	.byte	3                               @ DW_AT_decl_file
	.byte	97                              @ DW_AT_decl_line
	.long	1107                            @ DW_AT_type
	.byte	26                              @ Abbrev [26] 0x46d:0xb DW_TAG_formal_parameter
	.long	.Linfo_string27                 @ DW_AT_name
	.byte	3                               @ DW_AT_decl_file
	.byte	97                              @ DW_AT_decl_line
	.long	932                             @ DW_AT_type
	.byte	26                              @ Abbrev [26] 0x478:0xb DW_TAG_formal_parameter
	.long	.Linfo_string33                 @ DW_AT_name
	.byte	3                               @ DW_AT_decl_file
	.byte	97                              @ DW_AT_decl_line
	.long	1180                            @ DW_AT_type
	.byte	24                              @ Abbrev [24] 0x483:0xb DW_TAG_variable
	.long	.Linfo_string35                 @ DW_AT_name
	.byte	3                               @ DW_AT_decl_file
	.byte	98                              @ DW_AT_decl_line
	.long	168                             @ DW_AT_type
	.byte	30                              @ Abbrev [30] 0x48e:0xd DW_TAG_lexical_block
	.byte	24                              @ Abbrev [24] 0x48f:0xb DW_TAG_variable
	.long	.Linfo_string36                 @ DW_AT_name
	.byte	3                               @ DW_AT_decl_file
	.byte	102                             @ DW_AT_decl_line
	.long	848                             @ DW_AT_type
	.byte	0                               @ End Of Children Mark
	.byte	0                               @ End Of Children Mark
	.byte	6                               @ Abbrev [6] 0x49c:0xb DW_TAG_typedef
	.long	94                              @ DW_AT_type
	.long	.Linfo_string34                 @ DW_AT_name
	.byte	5                               @ DW_AT_decl_file
	.byte	18                              @ DW_AT_decl_line
	.byte	25                              @ Abbrev [25] 0x4a7:0x2c DW_TAG_subprogram
	.long	.Linfo_string37                 @ DW_AT_name
	.byte	3                               @ DW_AT_decl_file
	.byte	122                             @ DW_AT_decl_line
	.byte	1                               @ DW_AT_prototyped
	.byte	1                               @ DW_AT_external
	.byte	1                               @ DW_AT_inline
	.byte	26                              @ Abbrev [26] 0x4b1:0xb DW_TAG_formal_parameter
	.long	.Linfo_string15                 @ DW_AT_name
	.byte	3                               @ DW_AT_decl_file
	.byte	122                             @ DW_AT_decl_line
	.long	1107                            @ DW_AT_type
	.byte	24                              @ Abbrev [24] 0x4bc:0xb DW_TAG_variable
	.long	.Linfo_string33                 @ DW_AT_name
	.byte	3                               @ DW_AT_decl_file
	.byte	134                             @ DW_AT_decl_line
	.long	807                             @ DW_AT_type
	.byte	24                              @ Abbrev [24] 0x4c7:0xb DW_TAG_variable
	.long	.Linfo_string25                 @ DW_AT_name
	.byte	3                               @ DW_AT_decl_file
	.byte	135                             @ DW_AT_decl_line
	.long	1235                            @ DW_AT_type
	.byte	0                               @ End Of Children Mark
	.byte	7                               @ Abbrev [7] 0x4d3:0x7 DW_TAG_base_type
	.long	.Linfo_string38                 @ DW_AT_name
	.byte	5                               @ DW_AT_encoding
	.byte	4                               @ DW_AT_byte_size
	.byte	32                              @ Abbrev [32] 0x4da:0x140 DW_TAG_subprogram
	.long	.Lfunc_begin6                   @ DW_AT_low_pc
	.long	.Lfunc_end6                     @ DW_AT_high_pc
	.byte	1                               @ DW_AT_frame_base
	.byte	93
	.byte	216                             @ DW_AT_TI_max_frame_size
	.long	.Linfo_string39                 @ DW_AT_name
	.byte	3                               @ DW_AT_decl_file
	.byte	170                             @ DW_AT_decl_line
	.byte	1                               @ DW_AT_prototyped
	.byte	1                               @ DW_AT_external
	.byte	21                              @ Abbrev [21] 0x4ee:0xf DW_TAG_formal_parameter
	.long	.Ldebug_loc24                   @ DW_AT_location
	.long	.Linfo_string27                 @ DW_AT_name
	.byte	3                               @ DW_AT_decl_file
	.byte	170                             @ DW_AT_decl_line
	.long	932                             @ DW_AT_type
	.byte	21                              @ Abbrev [21] 0x4fd:0xf DW_TAG_formal_parameter
	.long	.Ldebug_loc25                   @ DW_AT_location
	.long	.Linfo_string33                 @ DW_AT_name
	.byte	3                               @ DW_AT_decl_file
	.byte	170                             @ DW_AT_decl_line
	.long	1180                            @ DW_AT_type
	.byte	21                              @ Abbrev [21] 0x50c:0xf DW_TAG_formal_parameter
	.long	.Ldebug_loc26                   @ DW_AT_location
	.long	.Linfo_string24                 @ DW_AT_name
	.byte	3                               @ DW_AT_decl_file
	.byte	170                             @ DW_AT_decl_line
	.long	860                             @ DW_AT_type
	.byte	23                              @ Abbrev [23] 0x51b:0xf DW_TAG_variable
	.long	.Ldebug_loc27                   @ DW_AT_location
	.long	.Linfo_string15                 @ DW_AT_name
	.byte	3                               @ DW_AT_decl_file
	.byte	171                             @ DW_AT_decl_line
	.long	750                             @ DW_AT_type
	.byte	33                              @ Abbrev [33] 0x52a:0x16 DW_TAG_inlined_subroutine
	.long	1085                            @ DW_AT_abstract_origin
	.long	.Ltmp197                        @ DW_AT_low_pc
	.long	.Ltmp206                        @ DW_AT_high_pc
	.byte	3                               @ DW_AT_call_file
	.byte	172                             @ DW_AT_call_line
	.byte	5                               @ DW_AT_call_column
	.byte	34                              @ Abbrev [34] 0x53a:0x5 DW_TAG_formal_parameter
	.long	1095                            @ DW_AT_abstract_origin
	.byte	0                               @ End Of Children Mark
	.byte	33                              @ Abbrev [33] 0x540:0x3b DW_TAG_inlined_subroutine
	.long	1112                            @ DW_AT_abstract_origin
	.long	.Ltmp206                        @ DW_AT_low_pc
	.long	.Ltmp251                        @ DW_AT_high_pc
	.byte	3                               @ DW_AT_call_file
	.byte	173                             @ DW_AT_call_line
	.byte	5                               @ DW_AT_call_column
	.byte	34                              @ Abbrev [34] 0x550:0x5 DW_TAG_formal_parameter
	.long	1122                            @ DW_AT_abstract_origin
	.byte	15                              @ Abbrev [15] 0x555:0x9 DW_TAG_formal_parameter
	.long	.Ldebug_loc29                   @ DW_AT_location
	.long	1144                            @ DW_AT_abstract_origin
	.byte	16                              @ Abbrev [16] 0x55e:0x9 DW_TAG_variable
	.long	.Ldebug_loc28                   @ DW_AT_location
	.long	1155                            @ DW_AT_abstract_origin
	.byte	17                              @ Abbrev [17] 0x567:0x13 DW_TAG_lexical_block
	.long	.Ltmp210                        @ DW_AT_low_pc
	.long	.Ltmp218                        @ DW_AT_high_pc
	.byte	18                              @ Abbrev [18] 0x570:0x9 DW_TAG_variable
	.byte	3                               @ DW_AT_location
	.byte	145
	.ascii	"\204\001"
	.long	1167                            @ DW_AT_abstract_origin
	.byte	0                               @ End Of Children Mark
	.byte	0                               @ End Of Children Mark
	.byte	33                              @ Abbrev [33] 0x57b:0x28 DW_TAG_inlined_subroutine
	.long	1191                            @ DW_AT_abstract_origin
	.long	.Ltmp251                        @ DW_AT_low_pc
	.long	.Ltmp265                        @ DW_AT_high_pc
	.byte	3                               @ DW_AT_call_file
	.byte	174                             @ DW_AT_call_line
	.byte	5                               @ DW_AT_call_column
	.byte	34                              @ Abbrev [34] 0x58b:0x5 DW_TAG_formal_parameter
	.long	1201                            @ DW_AT_abstract_origin
	.byte	16                              @ Abbrev [16] 0x590:0x9 DW_TAG_variable
	.long	.Ldebug_loc30                   @ DW_AT_location
	.long	1212                            @ DW_AT_abstract_origin
	.byte	16                              @ Abbrev [16] 0x599:0x9 DW_TAG_variable
	.long	.Ldebug_loc31                   @ DW_AT_location
	.long	1223                            @ DW_AT_abstract_origin
	.byte	0                               @ End Of Children Mark
	.byte	33                              @ Abbrev [33] 0x5a3:0x26 DW_TAG_inlined_subroutine
	.long	696                             @ DW_AT_abstract_origin
	.long	.Ltmp265                        @ DW_AT_low_pc
	.long	.Ltmp273                        @ DW_AT_high_pc
	.byte	3                               @ DW_AT_call_file
	.byte	175                             @ DW_AT_call_line
	.byte	5                               @ DW_AT_call_column
	.byte	34                              @ Abbrev [34] 0x5b3:0x5 DW_TAG_formal_parameter
	.long	706                             @ DW_AT_abstract_origin
	.byte	14                              @ Abbrev [14] 0x5b8:0x7 DW_TAG_formal_parameter
	.byte	1                               @ DW_AT_location
	.byte	84
	.long	717                             @ DW_AT_abstract_origin
	.byte	16                              @ Abbrev [16] 0x5bf:0x9 DW_TAG_variable
	.long	.Ldebug_loc32                   @ DW_AT_location
	.long	728                             @ DW_AT_abstract_origin
	.byte	0                               @ End Of Children Mark
	.byte	19                              @ Abbrev [19] 0x5c9:0xa DW_TAG_TI_reserved_3
	.long	.Ltmp218                        @ DW_AT_low_pc
	.byte	1                               @ DW_AT_TI_reserved_9
	.long	.Linfo_string13                 @ DW_AT_name
	.byte	19                              @ Abbrev [19] 0x5d3:0xa DW_TAG_TI_reserved_3
	.long	.Ltmp232                        @ DW_AT_low_pc
	.byte	1                               @ DW_AT_TI_reserved_9
	.long	.Linfo_string13                 @ DW_AT_name
	.byte	19                              @ Abbrev [19] 0x5dd:0xa DW_TAG_TI_reserved_3
	.long	.Ltmp235                        @ DW_AT_low_pc
	.byte	1                               @ DW_AT_TI_reserved_9
	.long	.Linfo_string13                 @ DW_AT_name
	.byte	19                              @ Abbrev [19] 0x5e7:0xa DW_TAG_TI_reserved_3
	.long	.Ltmp243                        @ DW_AT_low_pc
	.byte	1                               @ DW_AT_TI_reserved_9
	.long	.Linfo_string13                 @ DW_AT_name
	.byte	19                              @ Abbrev [19] 0x5f1:0xa DW_TAG_TI_reserved_3
	.long	.Ltmp245                        @ DW_AT_low_pc
	.byte	1                               @ DW_AT_TI_reserved_9
	.long	.Linfo_string13                 @ DW_AT_name
	.byte	19                              @ Abbrev [19] 0x5fb:0xa DW_TAG_TI_reserved_3
	.long	.Ltmp246                        @ DW_AT_low_pc
	.byte	1                               @ DW_AT_TI_reserved_9
	.long	.Linfo_string13                 @ DW_AT_name
	.byte	19                              @ Abbrev [19] 0x605:0xa DW_TAG_TI_reserved_3
	.long	.Ltmp257                        @ DW_AT_low_pc
	.byte	1                               @ DW_AT_TI_reserved_9
	.long	.Linfo_string13                 @ DW_AT_name
	.byte	19                              @ Abbrev [19] 0x60f:0xa DW_TAG_TI_reserved_3
	.long	.Ltmp265                        @ DW_AT_low_pc
	.byte	1                               @ DW_AT_TI_reserved_9
	.long	.Linfo_string13                 @ DW_AT_name
	.byte	0                               @ End Of Children Mark
	.byte	32                              @ Abbrev [32] 0x61a:0x7f DW_TAG_subprogram
	.long	.Lfunc_begin7                   @ DW_AT_low_pc
	.long	.Lfunc_end7                     @ DW_AT_high_pc
	.byte	1                               @ DW_AT_frame_base
	.byte	93
	.byte	56                              @ DW_AT_TI_max_frame_size
	.long	.Linfo_string41                 @ DW_AT_name
	.byte	3                               @ DW_AT_decl_file
	.byte	178                             @ DW_AT_decl_line
	.byte	1                               @ DW_AT_prototyped
	.byte	1                               @ DW_AT_external
	.byte	21                              @ Abbrev [21] 0x62e:0xf DW_TAG_formal_parameter
	.long	.Ldebug_loc33                   @ DW_AT_location
	.long	.Linfo_string27                 @ DW_AT_name
	.byte	3                               @ DW_AT_decl_file
	.byte	178                             @ DW_AT_decl_line
	.long	932                             @ DW_AT_type
	.byte	21                              @ Abbrev [21] 0x63d:0xf DW_TAG_formal_parameter
	.long	.Ldebug_loc34                   @ DW_AT_location
	.long	.Linfo_string33                 @ DW_AT_name
	.byte	3                               @ DW_AT_decl_file
	.byte	178                             @ DW_AT_decl_line
	.long	1180                            @ DW_AT_type
	.byte	21                              @ Abbrev [21] 0x64c:0xf DW_TAG_formal_parameter
	.long	.Ldebug_loc35                   @ DW_AT_location
	.long	.Linfo_string53                 @ DW_AT_name
	.byte	3                               @ DW_AT_decl_file
	.byte	178                             @ DW_AT_decl_line
	.long	938                             @ DW_AT_type
	.byte	22                              @ Abbrev [22] 0x65b:0xe DW_TAG_variable
	.byte	2                               @ DW_AT_location
	.byte	145
	.byte	4
	.long	.Linfo_string24                 @ DW_AT_name
	.byte	3                               @ DW_AT_decl_file
	.byte	179                             @ DW_AT_decl_line
	.long	1701                            @ DW_AT_type
	.byte	33                              @ Abbrev [33] 0x669:0x25 DW_TAG_inlined_subroutine
	.long	865                             @ DW_AT_abstract_origin
	.long	.Ltmp279                        @ DW_AT_low_pc
	.long	.Ltmp299                        @ DW_AT_high_pc
	.byte	3                               @ DW_AT_call_file
	.byte	181                             @ DW_AT_call_line
	.byte	5                               @ DW_AT_call_column
	.byte	34                              @ Abbrev [34] 0x679:0x5 DW_TAG_formal_parameter
	.long	874                             @ DW_AT_abstract_origin
	.byte	35                              @ Abbrev [35] 0x67e:0x6 DW_TAG_formal_parameter
	.byte	32                              @ DW_AT_const_value
	.long	885                             @ DW_AT_abstract_origin
	.byte	16                              @ Abbrev [16] 0x684:0x9 DW_TAG_variable
	.long	.Ldebug_loc36                   @ DW_AT_location
	.long	907                             @ DW_AT_abstract_origin
	.byte	0                               @ End Of Children Mark
	.byte	19                              @ Abbrev [19] 0x68e:0xa DW_TAG_TI_reserved_3
	.long	.Ltmp277                        @ DW_AT_low_pc
	.byte	1                               @ DW_AT_TI_reserved_9
	.long	.Linfo_string39                 @ DW_AT_name
	.byte	0                               @ End Of Children Mark
	.byte	3                               @ Abbrev [3] 0x699:0xc DW_TAG_array_type
	.long	72                              @ DW_AT_type
	.byte	4                               @ Abbrev [4] 0x69e:0x6 DW_TAG_subrange_type
	.long	101                             @ DW_AT_type
	.byte	64                              @ DW_AT_count
	.byte	0                               @ End Of Children Mark
	.byte	3                               @ Abbrev [3] 0x6a5:0xc DW_TAG_array_type
	.long	178                             @ DW_AT_type
	.byte	4                               @ Abbrev [4] 0x6aa:0x6 DW_TAG_subrange_type
	.long	101                             @ DW_AT_type
	.byte	32                              @ DW_AT_count
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
	.long	.Lfunc_begin4
	.long	.Lfunc_end4
	.long	.Lfunc_begin5
	.long	.Lfunc_end5
	.long	.Lfunc_begin6
	.long	.Lfunc_end6
	.long	.Lfunc_begin7
	.long	.Lfunc_end7
	.long	0
	.long	0
	.section	.debug_str,"MS",%progbits,1
.Linfo_string0:
	.asciz	"TI clang version 18.1.8 (ssh://git@bitbucket.itg.ti.com/code/llvm-project.git 41ce286cff6db007d382d297353d8bf884b450b7)" @ string offset=0
.Linfo_string1:
	.asciz	"sha256/sha256.c"               @ string offset=120
.Linfo_string2:
	.asciz	"/home/main/Documents/school/Fault-Injection-Finder/targets/timspm0l2228/source" @ string offset=136
.Linfo_string3:
	.asciz	"k"                             @ string offset=215
.Linfo_string4:
	.asciz	"unsigned int"                  @ string offset=217
.Linfo_string5:
	.asciz	"__uint32_t"                    @ string offset=230
.Linfo_string6:
	.asciz	"uint32_t"                      @ string offset=241
.Linfo_string7:
	.asciz	"__ARRAY_SIZE_TYPE__"           @ string offset=250
.Linfo_string8:
	.asciz	"char"                          @ string offset=270
.Linfo_string9:
	.asciz	"lut"                           @ string offset=275
.Linfo_string10:
	.asciz	"unsigned char"                 @ string offset=279
.Linfo_string11:
	.asciz	"__uint8_t"                     @ string offset=293
.Linfo_string12:
	.asciz	"uint8_t"                       @ string offset=303
.Linfo_string13:
	.asciz	"sha256_calc_chunk"             @ string offset=311
.Linfo_string14:
	.asciz	"sha256_read"                   @ string offset=329
.Linfo_string15:
	.asciz	"buff"                          @ string offset=341
.Linfo_string16:
	.asciz	"data_size"                     @ string offset=346
.Linfo_string17:
	.asciz	"unsigned long long"            @ string offset=356
.Linfo_string18:
	.asciz	"__uint64_t"                    @ string offset=375
.Linfo_string19:
	.asciz	"uint64_t"                      @ string offset=386
.Linfo_string20:
	.asciz	"h"                             @ string offset=395
.Linfo_string21:
	.asciz	"last_chunk"                    @ string offset=397
.Linfo_string22:
	.asciz	"chunk_size"                    @ string offset=408
.Linfo_string23:
	.asciz	"sha256_buff"                   @ string offset=419
.Linfo_string24:
	.asciz	"hash"                          @ string offset=431
.Linfo_string25:
	.asciz	"i"                             @ string offset=436
.Linfo_string26:
	.asciz	"bin_to_hex"                    @ string offset=438
.Linfo_string27:
	.asciz	"data"                          @ string offset=449
.Linfo_string28:
	.asciz	"len"                           @ string offset=454
.Linfo_string29:
	.asciz	"out"                           @ string offset=458
.Linfo_string30:
	.asciz	"c"                             @ string offset=462
.Linfo_string31:
	.asciz	"sha256_init"                   @ string offset=464
.Linfo_string32:
	.asciz	"sha256_update"                 @ string offset=476
.Linfo_string33:
	.asciz	"size"                          @ string offset=490
.Linfo_string34:
	.asciz	"size_t"                        @ string offset=495
.Linfo_string35:
	.asciz	"ptr"                           @ string offset=502
.Linfo_string36:
	.asciz	"tmp_chunk"                     @ string offset=506
.Linfo_string37:
	.asciz	"sha256_finalize"               @ string offset=516
.Linfo_string38:
	.asciz	"int"                           @ string offset=532
.Linfo_string39:
	.asciz	"sha256_easy_hash"              @ string offset=536
.Linfo_string40:
	.asciz	"sha256_read_hex"               @ string offset=553
.Linfo_string41:
	.asciz	"sha256_easy_hash_hex"          @ string offset=569
.Linfo_string42:
	.asciz	"w"                             @ string offset=590
.Linfo_string43:
	.asciz	"chunk"                         @ string offset=592
.Linfo_string44:
	.asciz	"s0"                            @ string offset=598
.Linfo_string45:
	.asciz	"s1"                            @ string offset=601
.Linfo_string46:
	.asciz	"tv"                            @ string offset=604
.Linfo_string47:
	.asciz	"S1"                            @ string offset=607
.Linfo_string48:
	.asciz	"temp1"                         @ string offset=610
.Linfo_string49:
	.asciz	"S0"                            @ string offset=616
.Linfo_string50:
	.asciz	"maj"                           @ string offset=619
.Linfo_string51:
	.asciz	"ch"                            @ string offset=623
.Linfo_string52:
	.asciz	"temp2"                         @ string offset=626
.Linfo_string53:
	.asciz	"hex"                           @ string offset=632
	.ident	"TI clang version 18.1.8 (ssh://git@bitbucket.itg.ti.com/code/llvm-project.git 41ce286cff6db007d382d297353d8bf884b450b7)"
	.section	".note.GNU-stack","",%progbits
	.eabi_attribute	30, 1	@ Tag_ABI_optimization_goals
	.section	.debug_line,"",%progbits
.Lline_table_start0:
