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
	.file	"chacha20.c"
	.section	.text.chacha20_init_context,"ax",%progbits
	.hidden	chacha20_init_context           @ -- Begin function chacha20_init_context
	.globl	chacha20_init_context
	.p2align	2
	.type	chacha20_init_context,%function
	.code	16                              @ @chacha20_init_context
	.thumb_func
chacha20_init_context:
.Lfunc_begin0:
	.fnstart
	.cfi_sections .debug_frame
	.cfi_startproc
@ %bb.0:
	@DEBUG_VALUE: chacha20_init_context:ctx <- $r0
	@DEBUG_VALUE: chacha20_init_context:key <- $r1
	@DEBUG_VALUE: chacha20_init_context:nonce <- $r2
	.save	{r4, r5, r6, r7, lr}
	push	{r4, r5, r6, r7, lr}
	.cfi_def_cfa_offset 20
	.cfi_offset lr, -4
	.cfi_offset r7, -8
	.cfi_offset r6, -12
	.cfi_offset r5, -16
	.cfi_offset r4, -20
	.pad	#12
	sub	sp, #12
	.cfi_def_cfa_offset 32
.Ltmp0:
	@DEBUG_VALUE: chacha20_init_context:counter <- [DW_OP_plus_uconst 32] [$sp+0]
	mov	r6, r2
.Ltmp1:
	@DEBUG_VALUE: chacha20_init_context:nonce <- $r6
	mov	r7, r1
.Ltmp2:
	@DEBUG_VALUE: chacha20_init_context:key <- $r7
	mov	r4, r0
.Ltmp3:
	@DEBUG_VALUE: chacha20_init_context:ctx <- $r4
	ldr	r0, [sp, #36]
	str	r0, [sp, #8]                    @ 4-byte Spill
	ldr	r0, [sp, #32]
.Ltmp4:
	@DEBUG_VALUE: pack4:res <- 1797285236
	str	r0, [sp, #4]                    @ 4-byte Spill
	mov	r5, r4
	adds	r5, #100
	movs	r1, #184
	mov	r0, r4
	bl	__aeabi_memclr8
.Ltmp5:
	@DEBUG_VALUE: chacha20_init_block:ctx <- $r4
	@DEBUG_VALUE: chacha20_init_block:key <- $r7
	@DEBUG_VALUE: chacha20_init_block:nonce <- $r6
	mov	r0, r4
	adds	r0, #68
	movs	r2, #32
	mov	r1, r7
	bl	__aeabi_memcpy
.Ltmp6:
	movs	r2, #12
	str	r2, [sp]                        @ 4-byte Spill
	mov	r0, r5
	mov	r1, r6
	bl	__aeabi_memcpy
.Ltmp7:
	ldr	r0, .LCPI0_0
.Ltmp8:
	@DEBUG_VALUE: pack4:res <- 1634760805
	ldr	r1, .LCPI0_1
.Ltmp9:
	@DEBUG_VALUE: pack4:res <- 857760878
	str	r0, [r4, #120]
	str	r1, [r4, #124]
	ldr	r0, .LCPI0_2
.Ltmp10:
	@DEBUG_VALUE: pack4:res <- 2036477234
	str	r0, [r5, #28]
	ldr	r0, .LCPI0_3
	str	r0, [r5, #32]
.Ltmp11:
	@DEBUG_VALUE: pack4:res <- 0
	@DEBUG_VALUE: pack4:a <- $r7
	ldrb	r0, [r7]
.Ltmp12:
	@DEBUG_VALUE: pack4:res <- $r0
	ldrb	r1, [r7, #1]
	lsls	r1, r1, #8
	adds	r0, r1, r0
.Ltmp13:
	@DEBUG_VALUE: pack4:res <- $r0
	ldrb	r1, [r7, #2]
	lsls	r1, r1, #16
	adds	r0, r0, r1
.Ltmp14:
	@DEBUG_VALUE: pack4:res <- $r0
	ldrb	r1, [r7, #3]
	lsls	r1, r1, #24
	adds	r0, r0, r1
.Ltmp15:
	@DEBUG_VALUE: pack4:res <- $r0
	str	r0, [r5, #36]
.Ltmp16:
	@DEBUG_VALUE: pack4:res <- 0
	@DEBUG_VALUE: pack4:a <- [DW_OP_plus_uconst 4, DW_OP_stack_value] $r7
	ldrb	r0, [r7, #4]
.Ltmp17:
	@DEBUG_VALUE: pack4:res <- $r0
	ldrb	r1, [r7, #5]
	lsls	r1, r1, #8
	adds	r0, r1, r0
.Ltmp18:
	@DEBUG_VALUE: pack4:res <- $r0
	ldrb	r1, [r7, #6]
	lsls	r1, r1, #16
	adds	r0, r0, r1
.Ltmp19:
	@DEBUG_VALUE: pack4:res <- $r0
	ldrb	r1, [r7, #7]
	lsls	r1, r1, #24
	adds	r0, r0, r1
.Ltmp20:
	@DEBUG_VALUE: pack4:res <- $r0
	str	r0, [r5, #40]
.Ltmp21:
	@DEBUG_VALUE: pack4:res <- 0
	@DEBUG_VALUE: pack4:a <- [DW_OP_plus_uconst 8, DW_OP_stack_value] $r7
	ldrb	r0, [r7, #8]
.Ltmp22:
	@DEBUG_VALUE: pack4:res <- $r0
	ldrb	r1, [r7, #9]
	lsls	r1, r1, #8
	adds	r0, r1, r0
.Ltmp23:
	@DEBUG_VALUE: pack4:res <- $r0
	ldrb	r1, [r7, #10]
	lsls	r1, r1, #16
	adds	r0, r0, r1
.Ltmp24:
	@DEBUG_VALUE: pack4:res <- $r0
	ldrb	r1, [r7, #11]
	lsls	r1, r1, #24
	adds	r0, r0, r1
.Ltmp25:
	@DEBUG_VALUE: pack4:res <- $r0
	str	r0, [r5, #44]
.Ltmp26:
	@DEBUG_VALUE: pack4:res <- 0
	@DEBUG_VALUE: pack4:a <- [DW_OP_plus_uconst 12, DW_OP_stack_value] $r7
	ldrb	r0, [r7, #12]
.Ltmp27:
	@DEBUG_VALUE: pack4:res <- $r0
	ldrb	r1, [r7, #13]
	lsls	r1, r1, #8
	adds	r0, r1, r0
.Ltmp28:
	@DEBUG_VALUE: pack4:res <- $r0
	ldrb	r1, [r7, #14]
	lsls	r1, r1, #16
	adds	r0, r0, r1
.Ltmp29:
	@DEBUG_VALUE: pack4:res <- $r0
	ldrb	r1, [r7, #15]
	lsls	r1, r1, #24
	adds	r0, r0, r1
.Ltmp30:
	@DEBUG_VALUE: pack4:res <- $r0
	str	r0, [r5, #48]
.Ltmp31:
	@DEBUG_VALUE: pack4:res <- 0
	@DEBUG_VALUE: pack4:a <- [DW_OP_plus_uconst 16, DW_OP_stack_value] $r7
	ldrb	r0, [r7, #16]
.Ltmp32:
	@DEBUG_VALUE: pack4:res <- $r0
	ldrb	r1, [r7, #17]
	lsls	r1, r1, #8
	adds	r0, r1, r0
.Ltmp33:
	@DEBUG_VALUE: pack4:res <- $r0
	ldrb	r1, [r7, #18]
	lsls	r1, r1, #16
	adds	r0, r0, r1
.Ltmp34:
	@DEBUG_VALUE: pack4:res <- $r0
	ldrb	r1, [r7, #19]
	lsls	r1, r1, #24
	adds	r0, r0, r1
.Ltmp35:
	@DEBUG_VALUE: pack4:res <- $r0
	str	r0, [r5, #52]
.Ltmp36:
	@DEBUG_VALUE: pack4:res <- 0
	@DEBUG_VALUE: pack4:a <- [DW_OP_plus_uconst 20, DW_OP_stack_value] $r7
	ldrb	r0, [r7, #20]
.Ltmp37:
	@DEBUG_VALUE: pack4:res <- $r0
	ldrb	r1, [r7, #21]
	lsls	r1, r1, #8
	adds	r0, r1, r0
.Ltmp38:
	@DEBUG_VALUE: pack4:res <- $r0
	ldrb	r1, [r7, #22]
	lsls	r1, r1, #16
	adds	r0, r0, r1
.Ltmp39:
	@DEBUG_VALUE: pack4:res <- $r0
	ldrb	r1, [r7, #23]
	lsls	r1, r1, #24
	adds	r0, r0, r1
.Ltmp40:
	@DEBUG_VALUE: pack4:res <- $r0
	str	r0, [r5, #56]
.Ltmp41:
	@DEBUG_VALUE: pack4:res <- 0
	@DEBUG_VALUE: pack4:a <- [DW_OP_plus_uconst 24, DW_OP_stack_value] $r7
	ldrb	r0, [r7, #24]
.Ltmp42:
	@DEBUG_VALUE: pack4:res <- $r0
	ldrb	r1, [r7, #25]
	lsls	r1, r1, #8
	adds	r0, r1, r0
.Ltmp43:
	@DEBUG_VALUE: pack4:res <- $r0
	ldrb	r1, [r7, #26]
	lsls	r1, r1, #16
	adds	r0, r0, r1
.Ltmp44:
	@DEBUG_VALUE: pack4:res <- $r0
	ldrb	r1, [r7, #27]
	lsls	r1, r1, #24
	adds	r0, r0, r1
.Ltmp45:
	@DEBUG_VALUE: pack4:res <- $r0
	str	r0, [r5, #60]
.Ltmp46:
	@DEBUG_VALUE: pack4:res <- 0
	@DEBUG_VALUE: pack4:a <- [DW_OP_plus_uconst 28, DW_OP_stack_value] $r7
	ldrb	r0, [r7, #28]
.Ltmp47:
	@DEBUG_VALUE: pack4:res <- $r0
	ldrb	r1, [r7, #29]
	lsls	r1, r1, #8
	adds	r0, r1, r0
.Ltmp48:
	@DEBUG_VALUE: pack4:res <- $r0
	ldrb	r1, [r7, #30]
	lsls	r1, r1, #16
	adds	r0, r0, r1
.Ltmp49:
	@DEBUG_VALUE: pack4:res <- $r0
	ldrb	r1, [r7, #31]
	lsls	r1, r1, #24
	adds	r0, r0, r1
.Ltmp50:
	@DEBUG_VALUE: pack4:res <- $r0
	str	r0, [r5, #64]
	movs	r0, #0
	str	r0, [r5, #68]
.Ltmp51:
	@DEBUG_VALUE: pack4:res <- 0
	@DEBUG_VALUE: pack4:a <- $r6
	ldrb	r0, [r6]
.Ltmp52:
	@DEBUG_VALUE: pack4:res <- $r0
	ldrb	r1, [r6, #1]
	lsls	r1, r1, #8
	adds	r0, r1, r0
.Ltmp53:
	@DEBUG_VALUE: pack4:res <- $r0
	ldrb	r1, [r6, #2]
	lsls	r1, r1, #16
	adds	r0, r0, r1
.Ltmp54:
	@DEBUG_VALUE: pack4:res <- $r0
	ldrb	r1, [r6, #3]
	lsls	r1, r1, #24
	adds	r0, r0, r1
.Ltmp55:
	@DEBUG_VALUE: pack4:res <- $r0
	str	r0, [r5, #72]
.Ltmp56:
	@DEBUG_VALUE: pack4:res <- 0
	@DEBUG_VALUE: pack4:a <- [DW_OP_plus_uconst 4, DW_OP_stack_value] $r6
	ldrb	r0, [r6, #4]
.Ltmp57:
	@DEBUG_VALUE: pack4:res <- $r0
	ldrb	r1, [r6, #5]
	lsls	r1, r1, #8
	adds	r0, r1, r0
.Ltmp58:
	@DEBUG_VALUE: pack4:res <- $r0
	ldrb	r1, [r6, #6]
	lsls	r1, r1, #16
	adds	r0, r0, r1
.Ltmp59:
	@DEBUG_VALUE: pack4:res <- $r0
	ldrb	r1, [r6, #7]
	lsls	r1, r1, #24
	adds	r0, r0, r1
.Ltmp60:
	@DEBUG_VALUE: pack4:res <- $r0
	str	r0, [r5, #76]
.Ltmp61:
	@DEBUG_VALUE: pack4:res <- 0
	@DEBUG_VALUE: pack4:a <- [DW_OP_plus_uconst 8, DW_OP_stack_value] $r6
	ldrb	r0, [r6, #8]
.Ltmp62:
	@DEBUG_VALUE: pack4:res <- $r0
	ldrb	r1, [r6, #9]
	lsls	r1, r1, #8
	adds	r0, r1, r0
.Ltmp63:
	@DEBUG_VALUE: pack4:res <- $r0
	ldrb	r1, [r6, #10]
	lsls	r1, r1, #16
	adds	r0, r0, r1
.Ltmp64:
	@DEBUG_VALUE: pack4:res <- $r0
	ldrb	r1, [r6, #11]
	lsls	r1, r1, #24
	adds	r0, r0, r1
.Ltmp65:
	@DEBUG_VALUE: pack4:res <- $r0
	str	r0, [r5, #80]
	mov	r0, r5
	mov	r1, r6
	ldr	r2, [sp]                        @ 4-byte Reload
	bl	__aeabi_memcpy
.Ltmp66:
	ldr	r2, [sp, #4]                    @ 4-byte Reload
.Ltmp67:
	@DEBUG_VALUE: chacha20_block_set_counter:counter <- [DW_OP_plus_uconst 8, DW_OP_LLVM_fragment 32 32] [$sp+0]
	@DEBUG_VALUE: chacha20_block_set_counter:ctx <- $r4
	@DEBUG_VALUE: chacha20_block_set_counter:counter <- [DW_OP_LLVM_fragment 0 32] $r2
	str	r2, [r5, #68]
	movs	r0, #100
.Ltmp68:
	@DEBUG_VALUE: pack4:res <- 0
	@DEBUG_VALUE: pack4:a <- $r5
	ldrb	r0, [r4, r0]
.Ltmp69:
	@DEBUG_VALUE: pack4:res <- $r0
	ldrb	r1, [r5, #1]
	lsls	r1, r1, #8
	adds	r0, r1, r0
.Ltmp70:
	@DEBUG_VALUE: pack4:res <- $r0
	ldrb	r1, [r5, #2]
	lsls	r1, r1, #16
	adds	r0, r0, r1
.Ltmp71:
	@DEBUG_VALUE: pack4:res <- $r0
	ldrb	r1, [r5, #3]
	lsls	r1, r1, #24
	adds	r0, r0, r1
.Ltmp72:
	@DEBUG_VALUE: pack4:res <- $r0
	ldr	r1, [sp, #8]                    @ 4-byte Reload
.Ltmp73:
	@DEBUG_VALUE: chacha20_block_set_counter:counter <- [DW_OP_LLVM_fragment 32 32] $r1
	adds	r0, r0, r1
.Ltmp74:
	str	r0, [r5, #72]
.Ltmp75:
	str	r2, [r4, #112]
	str	r1, [r4, #116]
	movs	r0, #64
	str	r0, [r4, #64]
	add	sp, #12
	pop	{r4, r5, r6, r7, pc}
.Ltmp76:
	.p2align	2
@ %bb.1:
.LCPI0_0:
	.long	1634760805                      @ 0x61707865
.LCPI0_1:
	.long	857760878                       @ 0x3320646e
.LCPI0_2:
	.long	2036477234                      @ 0x79622d32
.LCPI0_3:
	.long	1797285236                      @ 0x6b206574
.Lfunc_end0:
	.size	chacha20_init_context, .Lfunc_end0-chacha20_init_context
	.cfi_endproc
	.cantunwind
	.fnend
                                        @ -- End function
	.section	.text.chacha20_xor,"ax",%progbits
	.hidden	chacha20_xor                    @ -- Begin function chacha20_xor
	.globl	chacha20_xor
	.p2align	1
	.type	chacha20_xor,%function
	.code	16                              @ @chacha20_xor
	.thumb_func
chacha20_xor:
.Lfunc_begin1:
	.fnstart
	.cfi_startproc
@ %bb.0:
	@DEBUG_VALUE: chacha20_xor:ctx <- $r0
	@DEBUG_VALUE: chacha20_xor:bytes <- $r1
	@DEBUG_VALUE: chacha20_xor:n_bytes <- $r2
	@DEBUG_VALUE: chacha20_xor:ctx <- $r0
	.save	{r4, r5, r6, r7, lr}
	push	{r4, r5, r6, r7, lr}
	.cfi_def_cfa_offset 20
	.cfi_offset lr, -4
	.cfi_offset r7, -8
	.cfi_offset r6, -12
	.cfi_offset r5, -16
	.cfi_offset r4, -20
	.pad	#96
	sub	sp, #96
	.cfi_def_cfa_offset 116
.Ltmp77:
	@DEBUG_VALUE: i <- 0
	@DEBUG_VALUE: chacha20_xor:keystream8 <- $r0
	cmp	r2, #0
	bne	.LBB1_1
	b	.LBB1_9
.Ltmp78:
.LBB1_1:
	@DEBUG_VALUE: chacha20_xor:keystream8 <- $r0
	@DEBUG_VALUE: i <- 0
	@DEBUG_VALUE: chacha20_xor:n_bytes <- $r2
	@DEBUG_VALUE: chacha20_xor:bytes <- $r1
	@DEBUG_VALUE: chacha20_xor:ctx <- $r0
	mov	r6, r0
.Ltmp79:
	@DEBUG_VALUE: chacha20_xor:ctx <- $r6
	@DEBUG_VALUE: chacha20_xor:keystream8 <- $r6
	adds	r0, #128
	str	r0, [sp, #8]                    @ 4-byte Spill
	mov	r0, r6
	adds	r0, #120
	str	r0, [sp, #4]                    @ 4-byte Spill
	mov	r0, r6
	adds	r0, #172
	str	r0, [sp]                        @ 4-byte Spill
.Ltmp80:
	ldr	r0, [r6, #64]
	movs	r5, #0
.Ltmp81:
	str	r2, [sp, #20]                   @ 4-byte Spill
	str	r1, [sp, #16]                   @ 4-byte Spill
	str	r6, [sp, #12]                   @ 4-byte Spill
	b	.LBB1_4
.Ltmp82:
.LBB1_2:                                @   in Loop: Header=BB1_4 Depth=1
	@DEBUG_VALUE: i <- [DW_OP_plus_uconst 24] [$sp+0]
	movs	r0, #0
.Ltmp83:
	str	r0, [r6, #64]
	add	r5, sp, #16
	ldm	r5, {r1, r2, r5}                @ 12-byte Folded Reload
.Ltmp84:
.LBB1_3:                                @   in Loop: Header=BB1_4 Depth=1
	ldrb	r0, [r6, r0]
	ldrb	r3, [r1, r5]
	eors	r3, r0
	strb	r3, [r1, r5]
	ldr	r0, [r6, #64]
	adds	r0, r0, #1
	str	r0, [r6, #64]
.Ltmp85:
	adds	r5, r5, #1
.Ltmp86:
	@DEBUG_VALUE: i <- $r5
	cmp	r5, r2
	bne	.LBB1_4
	b	.LBB1_9
.Ltmp87:
.LBB1_4:                                @ =>This Loop Header: Depth=1
                                        @     Child Loop BB1_6 Depth 2
	@DEBUG_VALUE: i <- $r5
	cmp	r0, #64
	blo	.LBB1_3
.Ltmp88:
@ %bb.5:                                @   in Loop: Header=BB1_4 Depth=1
	@DEBUG_VALUE: i <- $r5
	@DEBUG_VALUE: chacha20_block_next:ctx <- $r6
	@DEBUG_VALUE: i <- 0
	str	r5, [sp, #24]                   @ 4-byte Spill
.Ltmp89:
	@DEBUG_VALUE: i <- [DW_OP_plus_uconst 24] [$sp+0]
	@DEBUG_VALUE: i <- [DW_OP_plus_uconst 24] [$sp+0]
	ldr	r0, [sp, #4]                    @ 4-byte Reload
	mov	r1, r6
.Ltmp90:
	@DEBUG_VALUE: chacha20_xor:bytes <- [DW_OP_LLVM_entry_value 1] $r1
	ldm	r0!, {r2, r3, r4, r5}
.Ltmp91:
	@DEBUG_VALUE: chacha20_xor:n_bytes <- [DW_OP_LLVM_entry_value 1] $r2
	stm	r1!, {r2, r3, r4, r5}
	ldm	r0!, {r2, r3, r4, r5}
	stm	r1!, {r2, r3, r4, r5}
	ldm	r0!, {r2, r3, r4, r5}
	stm	r1!, {r2, r3, r4, r5}
	ldm	r0!, {r2, r3, r4, r5}
	stm	r1!, {r2, r3, r4, r5}
.Ltmp92:
	@DEBUG_VALUE: i <- undef
	mov	r3, r6
.Ltmp93:
	@DEBUG_VALUE: chacha20_block_next:ctx <- $r3
	ldr	r0, [r6]
	str	r0, [sp, #52]                   @ 4-byte Spill
	ldr	r0, [r6, #4]
	str	r0, [sp, #56]                   @ 4-byte Spill
	ldr	r0, [r6, #8]
	str	r0, [sp, #48]                   @ 4-byte Spill
	ldr	r0, [r6, #12]
	str	r0, [sp, #44]                   @ 4-byte Spill
	ldr	r5, [r6, #16]
	ldr	r0, [r6, #20]
	str	r0, [sp, #64]                   @ 4-byte Spill
	ldr	r0, [r6, #24]
	str	r0, [sp, #60]                   @ 4-byte Spill
	ldr	r0, [r6, #28]
	str	r0, [sp, #76]                   @ 4-byte Spill
	ldr	r0, [r6, #32]
	str	r0, [sp, #40]                   @ 4-byte Spill
	ldr	r4, [r6, #36]
	ldr	r0, [r6, #40]
	str	r0, [sp, #72]                   @ 4-byte Spill
	ldr	r0, [r6, #44]
	str	r0, [sp, #68]                   @ 4-byte Spill
	ldr	r2, [r6, #48]
	ldr	r1, [r6, #52]
	ldr	r6, [r6, #56]
.Ltmp94:
	@DEBUG_VALUE: chacha20_xor:ctx <- [DW_OP_LLVM_entry_value 1] $r0
	@DEBUG_VALUE: chacha20_block_next:ctx <- [DW_OP_plus_uconst 12] [$sp+0]
	ldr	r3, [r3, #60]
	movs	r0, #10
.Ltmp95:
	str	r0, [sp, #36]                   @ 4-byte Spill
.Ltmp96:
	@DEBUG_VALUE: i <- 0
.LBB1_6:                                @   Parent Loop BB1_4 Depth=1
                                        @ =>  This Inner Loop Header: Depth=2
	@DEBUG_VALUE: chacha20_block_next:ctx <- [DW_OP_plus_uconst 12] [$sp+0]
	@DEBUG_VALUE: i <- [DW_OP_plus_uconst 24] [$sp+0]
	@DEBUG_VALUE: i <- [DW_OP_plus_uconst 36, DW_OP_deref_size 4, DW_OP_consts 10, DW_OP_minus, DW_OP_consts 18446744073709551615, DW_OP_div, DW_OP_stack_value] $sp
	str	r4, [sp, #28]                   @ 4-byte Spill
	ldr	r0, [sp, #52]                   @ 4-byte Reload
	adds	r7, r0, r5
	eors	r2, r7
	movs	r0, #16
.Ltmp97:
	str	r0, [sp, #92]                   @ 4-byte Spill
.Ltmp98:
	@DEBUG_VALUE: rotl32:n <- 16
	@DEBUG_VALUE: rotl32:x <- $r2
	rors	r2, r0
.Ltmp99:
	ldr	r0, [sp, #40]                   @ 4-byte Reload
	adds	r0, r2, r0
	eors	r5, r0
	mov	r4, r0
	movs	r0, #20
.Ltmp100:
	str	r0, [sp, #88]                   @ 4-byte Spill
.Ltmp101:
	@DEBUG_VALUE: rotl32:n <- 12
	@DEBUG_VALUE: rotl32:x <- $r5
	rors	r5, r0
.Ltmp102:
	adds	r0, r5, r7
	str	r0, [sp, #52]                   @ 4-byte Spill
	eors	r2, r0
	movs	r0, #24
.Ltmp103:
	str	r0, [sp, #80]                   @ 4-byte Spill
.Ltmp104:
	@DEBUG_VALUE: rotl32:n <- 8
	@DEBUG_VALUE: rotl32:x <- $r2
	rors	r2, r0
.Ltmp105:
	adds	r0, r2, r4
	str	r0, [sp, #40]                   @ 4-byte Spill
	eors	r5, r0
	movs	r7, #25
.Ltmp106:
	@DEBUG_VALUE: rotl32:n <- 7
	@DEBUG_VALUE: rotl32:x <- $r5
	rors	r5, r7
.Ltmp107:
	str	r7, [sp, #84]                   @ 4-byte Spill
	str	r5, [sp, #32]                   @ 4-byte Spill
	ldr	r5, [sp, #64]                   @ 4-byte Reload
.Ltmp108:
	ldr	r0, [sp, #56]                   @ 4-byte Reload
	adds	r4, r0, r5
	eors	r1, r4
.Ltmp109:
	ldr	r0, [sp, #92]                   @ 4-byte Reload
.Ltmp110:
	@DEBUG_VALUE: rotl32:n <- 16
	@DEBUG_VALUE: rotl32:x <- $r1
	rors	r1, r0
.Ltmp111:
	ldr	r0, [sp, #28]                   @ 4-byte Reload
	adds	r0, r1, r0
	str	r0, [sp, #28]                   @ 4-byte Spill
	eors	r5, r0
.Ltmp112:
	ldr	r0, [sp, #88]                   @ 4-byte Reload
.Ltmp113:
	@DEBUG_VALUE: rotl32:n <- 12
	@DEBUG_VALUE: rotl32:x <- $r5
	rors	r5, r0
.Ltmp114:
	adds	r0, r5, r4
	str	r0, [sp, #56]                   @ 4-byte Spill
	eors	r1, r0
	ldr	r4, [sp, #80]                   @ 4-byte Reload
.Ltmp115:
	@DEBUG_VALUE: rotl32:n <- 8
	@DEBUG_VALUE: rotl32:x <- $r1
	rors	r1, r4
.Ltmp116:
	ldr	r0, [sp, #28]                   @ 4-byte Reload
	adds	r0, r1, r0
	str	r0, [sp, #28]                   @ 4-byte Spill
	eors	r5, r0
.Ltmp117:
	@DEBUG_VALUE: rotl32:n <- 7
	@DEBUG_VALUE: rotl32:x <- $r5
	rors	r5, r7
.Ltmp118:
	ldr	r7, [sp, #60]                   @ 4-byte Reload
.Ltmp119:
	ldr	r0, [sp, #48]                   @ 4-byte Reload
	adds	r0, r0, r7
	str	r0, [sp, #64]                   @ 4-byte Spill
	eors	r6, r0
.Ltmp120:
	ldr	r0, [sp, #92]                   @ 4-byte Reload
.Ltmp121:
	@DEBUG_VALUE: rotl32:n <- 16
	@DEBUG_VALUE: rotl32:x <- $r6
	rors	r6, r0
.Ltmp122:
	ldr	r0, [sp, #72]                   @ 4-byte Reload
	adds	r0, r6, r0
	str	r0, [sp, #72]                   @ 4-byte Spill
	eors	r7, r0
.Ltmp123:
	ldr	r0, [sp, #88]                   @ 4-byte Reload
.Ltmp124:
	@DEBUG_VALUE: rotl32:n <- 12
	@DEBUG_VALUE: rotl32:x <- $r7
	rors	r7, r0
.Ltmp125:
	ldr	r0, [sp, #64]                   @ 4-byte Reload
	adds	r0, r7, r0
	str	r0, [sp, #48]                   @ 4-byte Spill
	eors	r6, r0
.Ltmp126:
	@DEBUG_VALUE: rotl32:n <- 8
	@DEBUG_VALUE: rotl32:x <- $r6
	rors	r6, r4
.Ltmp127:
	ldr	r0, [sp, #72]                   @ 4-byte Reload
	adds	r0, r6, r0
	str	r0, [sp, #72]                   @ 4-byte Spill
	eors	r7, r0
.Ltmp128:
	ldr	r0, [sp, #84]                   @ 4-byte Reload
.Ltmp129:
	@DEBUG_VALUE: rotl32:n <- 7
	@DEBUG_VALUE: rotl32:x <- $r7
	rors	r7, r0
.Ltmp130:
	ldr	r0, [sp, #76]                   @ 4-byte Reload
.Ltmp131:
	ldr	r4, [sp, #44]                   @ 4-byte Reload
	adds	r4, r4, r0
	str	r4, [sp, #64]                   @ 4-byte Spill
	eors	r3, r4
.Ltmp132:
	ldr	r4, [sp, #92]                   @ 4-byte Reload
.Ltmp133:
	@DEBUG_VALUE: rotl32:n <- 16
	@DEBUG_VALUE: rotl32:x <- $r3
	rors	r3, r4
.Ltmp134:
	ldr	r4, [sp, #68]                   @ 4-byte Reload
	adds	r4, r3, r4
	str	r4, [sp, #68]                   @ 4-byte Spill
	eors	r0, r4
.Ltmp135:
	ldr	r4, [sp, #88]                   @ 4-byte Reload
.Ltmp136:
	@DEBUG_VALUE: rotl32:n <- 12
	@DEBUG_VALUE: rotl32:x <- $r0
	rors	r0, r4
.Ltmp137:
	ldr	r4, [sp, #64]                   @ 4-byte Reload
	adds	r4, r0, r4
	str	r4, [sp, #44]                   @ 4-byte Spill
	eors	r3, r4
.Ltmp138:
	ldr	r4, [sp, #80]                   @ 4-byte Reload
.Ltmp139:
	@DEBUG_VALUE: rotl32:n <- 8
	@DEBUG_VALUE: rotl32:x <- $r3
	rors	r3, r4
.Ltmp140:
	ldr	r4, [sp, #68]                   @ 4-byte Reload
	adds	r4, r3, r4
	str	r4, [sp, #76]                   @ 4-byte Spill
	eors	r0, r4
.Ltmp141:
	ldr	r4, [sp, #84]                   @ 4-byte Reload
.Ltmp142:
	@DEBUG_VALUE: rotl32:n <- 7
	@DEBUG_VALUE: rotl32:x <- $r0
	rors	r0, r4
.Ltmp143:
	ldr	r4, [sp, #52]                   @ 4-byte Reload
	adds	r4, r5, r4
	str	r4, [sp, #68]                   @ 4-byte Spill
	eors	r3, r4
.Ltmp144:
	ldr	r4, [sp, #92]                   @ 4-byte Reload
.Ltmp145:
	@DEBUG_VALUE: rotl32:n <- 16
	@DEBUG_VALUE: rotl32:x <- $r3
	rors	r3, r4
.Ltmp146:
	ldr	r4, [sp, #72]                   @ 4-byte Reload
	adds	r4, r3, r4
	str	r4, [sp, #72]                   @ 4-byte Spill
	eors	r5, r4
.Ltmp147:
	ldr	r4, [sp, #88]                   @ 4-byte Reload
.Ltmp148:
	@DEBUG_VALUE: rotl32:n <- 12
	@DEBUG_VALUE: rotl32:x <- $r5
	rors	r5, r4
.Ltmp149:
	ldr	r4, [sp, #68]                   @ 4-byte Reload
	adds	r4, r5, r4
	str	r4, [sp, #52]                   @ 4-byte Spill
	eors	r3, r4
.Ltmp150:
	ldr	r4, [sp, #80]                   @ 4-byte Reload
.Ltmp151:
	@DEBUG_VALUE: rotl32:n <- 8
	@DEBUG_VALUE: rotl32:x <- $r3
	rors	r3, r4
.Ltmp152:
	ldr	r4, [sp, #72]                   @ 4-byte Reload
	adds	r4, r3, r4
	str	r4, [sp, #72]                   @ 4-byte Spill
	eors	r5, r4
.Ltmp153:
	ldr	r4, [sp, #84]                   @ 4-byte Reload
.Ltmp154:
	@DEBUG_VALUE: rotl32:n <- 7
	@DEBUG_VALUE: rotl32:x <- $r5
	rors	r5, r4
.Ltmp155:
	str	r5, [sp, #64]                   @ 4-byte Spill
	ldr	r5, [sp, #32]                   @ 4-byte Reload
.Ltmp156:
	ldr	r4, [sp, #56]                   @ 4-byte Reload
	adds	r4, r7, r4
	str	r4, [sp, #68]                   @ 4-byte Spill
	eors	r2, r4
.Ltmp157:
	ldr	r4, [sp, #92]                   @ 4-byte Reload
.Ltmp158:
	@DEBUG_VALUE: rotl32:n <- 16
	@DEBUG_VALUE: rotl32:x <- $r2
	rors	r2, r4
.Ltmp159:
	ldr	r4, [sp, #76]                   @ 4-byte Reload
	adds	r4, r2, r4
	str	r4, [sp, #76]                   @ 4-byte Spill
	eors	r7, r4
.Ltmp160:
	ldr	r4, [sp, #88]                   @ 4-byte Reload
.Ltmp161:
	@DEBUG_VALUE: rotl32:n <- 12
	@DEBUG_VALUE: rotl32:x <- $r7
	rors	r7, r4
.Ltmp162:
	ldr	r4, [sp, #68]                   @ 4-byte Reload
	adds	r4, r7, r4
	str	r4, [sp, #56]                   @ 4-byte Spill
	eors	r2, r4
.Ltmp163:
	ldr	r4, [sp, #80]                   @ 4-byte Reload
.Ltmp164:
	@DEBUG_VALUE: rotl32:n <- 8
	@DEBUG_VALUE: rotl32:x <- $r2
	rors	r2, r4
.Ltmp165:
	ldr	r4, [sp, #76]                   @ 4-byte Reload
	adds	r4, r2, r4
	str	r4, [sp, #68]                   @ 4-byte Spill
	eors	r7, r4
.Ltmp166:
	ldr	r4, [sp, #84]                   @ 4-byte Reload
.Ltmp167:
	@DEBUG_VALUE: rotl32:n <- 7
	@DEBUG_VALUE: rotl32:x <- $r7
	rors	r7, r4
.Ltmp168:
	str	r7, [sp, #60]                   @ 4-byte Spill
.Ltmp169:
	ldr	r4, [sp, #48]                   @ 4-byte Reload
	adds	r7, r0, r4
	eors	r1, r7
.Ltmp170:
	ldr	r4, [sp, #92]                   @ 4-byte Reload
.Ltmp171:
	@DEBUG_VALUE: rotl32:n <- 16
	@DEBUG_VALUE: rotl32:x <- $r1
	rors	r1, r4
.Ltmp172:
	ldr	r4, [sp, #40]                   @ 4-byte Reload
	adds	r4, r1, r4
	str	r4, [sp, #76]                   @ 4-byte Spill
	eors	r0, r4
.Ltmp173:
	ldr	r4, [sp, #88]                   @ 4-byte Reload
.Ltmp174:
	@DEBUG_VALUE: rotl32:n <- 12
	@DEBUG_VALUE: rotl32:x <- $r0
	rors	r0, r4
.Ltmp175:
	adds	r4, r0, r7
	str	r4, [sp, #48]                   @ 4-byte Spill
	eors	r1, r4
.Ltmp176:
	ldr	r4, [sp, #80]                   @ 4-byte Reload
.Ltmp177:
	@DEBUG_VALUE: rotl32:n <- 8
	@DEBUG_VALUE: rotl32:x <- $r1
	rors	r1, r4
.Ltmp178:
	ldr	r4, [sp, #76]                   @ 4-byte Reload
	adds	r4, r1, r4
	str	r4, [sp, #40]                   @ 4-byte Spill
	eors	r0, r4
.Ltmp179:
	ldr	r4, [sp, #84]                   @ 4-byte Reload
.Ltmp180:
	@DEBUG_VALUE: rotl32:n <- 7
	@DEBUG_VALUE: rotl32:x <- $r0
	rors	r0, r4
.Ltmp181:
	str	r0, [sp, #76]                   @ 4-byte Spill
.Ltmp182:
	ldr	r0, [sp, #44]                   @ 4-byte Reload
	adds	r4, r0, r5
	eors	r6, r4
.Ltmp183:
	ldr	r0, [sp, #92]                   @ 4-byte Reload
.Ltmp184:
	@DEBUG_VALUE: rotl32:n <- 16
	@DEBUG_VALUE: rotl32:x <- $r6
	rors	r6, r0
.Ltmp185:
	ldr	r0, [sp, #28]                   @ 4-byte Reload
	adds	r7, r6, r0
	eors	r5, r7
.Ltmp186:
	ldr	r0, [sp, #88]                   @ 4-byte Reload
.Ltmp187:
	@DEBUG_VALUE: rotl32:n <- 12
	@DEBUG_VALUE: rotl32:x <- $r5
	rors	r5, r0
.Ltmp188:
	adds	r0, r5, r4
	str	r0, [sp, #44]                   @ 4-byte Spill
	eors	r6, r0
.Ltmp189:
	ldr	r0, [sp, #80]                   @ 4-byte Reload
.Ltmp190:
	@DEBUG_VALUE: rotl32:n <- 8
	@DEBUG_VALUE: rotl32:x <- $r6
	rors	r6, r0
.Ltmp191:
	adds	r4, r6, r7
	eors	r5, r4
.Ltmp192:
	ldr	r0, [sp, #84]                   @ 4-byte Reload
.Ltmp193:
	@DEBUG_VALUE: rotl32:n <- 7
	@DEBUG_VALUE: rotl32:x <- $r5
	rors	r5, r0
.Ltmp194:
	@DEBUG_VALUE: i <- [DW_OP_plus_uconst 36, DW_OP_deref_size 4, DW_OP_consts 10, DW_OP_minus, DW_OP_consts 18446744073709551615, DW_OP_div, DW_OP_consts 1, DW_OP_plus, DW_OP_stack_value] $sp
	ldr	r0, [sp, #36]                   @ 4-byte Reload
.Ltmp195:
	@DEBUG_VALUE: i <- [DW_OP_consts 10, DW_OP_minus, DW_OP_consts 18446744073709551615, DW_OP_div, DW_OP_consts 1, DW_OP_plus, DW_OP_stack_value] $r0
	subs	r0, r0, #1
.Ltmp196:
	str	r0, [sp, #36]                   @ 4-byte Spill
	beq	.LBB1_7
	b	.LBB1_6
.Ltmp197:
.LBB1_7:                                @   in Loop: Header=BB1_4 Depth=1
	@DEBUG_VALUE: chacha20_block_next:ctx <- [DW_OP_plus_uconst 12] [$sp+0]
	@DEBUG_VALUE: i <- [DW_OP_plus_uconst 24] [$sp+0]
	ldr	r0, [sp, #12]                   @ 4-byte Reload
.Ltmp198:
	ldr	r7, [sp, #40]                   @ 4-byte Reload
	str	r7, [r0, #32]
	mov	r7, r0
	str	r4, [r0, #36]
	ldr	r0, [sp, #72]                   @ 4-byte Reload
	str	r0, [r7, #40]
	ldr	r0, [sp, #68]                   @ 4-byte Reload
	str	r0, [r7, #44]
	str	r2, [r7, #48]
	str	r1, [r7, #52]
	str	r6, [r7, #56]
	str	r3, [r7, #60]
.Ltmp199:
	@DEBUG_VALUE: i <- 0
	ldr	r1, [r7, #120]
	ldr	r2, [r7, #124]
	ldr	r0, [sp, #52]                   @ 4-byte Reload
	adds	r1, r0, r1
.Ltmp200:
	@DEBUG_VALUE: i <- 1
	str	r1, [r7]
	ldr	r1, [sp, #56]                   @ 4-byte Reload
.Ltmp201:
	str	r1, [r7, #4]
	ldr	r3, [sp, #48]                   @ 4-byte Reload
	str	r3, [r7, #8]
	ldr	r4, [sp, #44]                   @ 4-byte Reload
	str	r4, [r7, #12]
	str	r5, [r7, #16]
	ldr	r0, [sp, #64]                   @ 4-byte Reload
	str	r0, [r7, #20]
	mov	r6, r7
	ldr	r0, [sp, #60]                   @ 4-byte Reload
	str	r0, [r7, #24]
	ldr	r0, [sp, #76]                   @ 4-byte Reload
	str	r0, [r7, #28]
.Ltmp202:
	adds	r0, r1, r2
	@DEBUG_VALUE: i <- 1
	str	r0, [r7, #4]
.Ltmp203:
	@DEBUG_VALUE: i <- 2
	ldr	r2, [sp, #8]                    @ 4-byte Reload
	ldr	r0, [r2]
	adds	r0, r3, r0
	str	r0, [r7, #8]
.Ltmp204:
	@DEBUG_VALUE: i <- 3
	ldr	r0, [r2, #4]
	adds	r0, r4, r0
	str	r0, [r7, #12]
.Ltmp205:
	@DEBUG_VALUE: i <- 4
	ldr	r0, [r2, #8]
	ldr	r1, [r7, #16]
	adds	r0, r1, r0
	str	r0, [r7, #16]
.Ltmp206:
	@DEBUG_VALUE: i <- 5
	ldr	r0, [r2, #12]
	ldr	r1, [r7, #20]
	adds	r0, r1, r0
	str	r0, [r7, #20]
.Ltmp207:
	@DEBUG_VALUE: i <- 6
	ldr	r0, [r2, #16]
	ldr	r1, [r7, #24]
	adds	r0, r1, r0
	str	r0, [r7, #24]
.Ltmp208:
	@DEBUG_VALUE: i <- 7
	ldr	r0, [r2, #20]
	ldr	r1, [r7, #28]
	adds	r0, r1, r0
	str	r0, [r7, #28]
.Ltmp209:
	@DEBUG_VALUE: i <- 8
	ldr	r0, [r2, #24]
	ldr	r1, [r7, #32]
	adds	r0, r1, r0
	str	r0, [r7, #32]
.Ltmp210:
	@DEBUG_VALUE: i <- 9
	ldr	r0, [r2, #28]
	ldr	r1, [r7, #36]
	adds	r0, r1, r0
	str	r0, [r7, #36]
.Ltmp211:
	@DEBUG_VALUE: i <- 10
	ldr	r0, [r2, #32]
	ldr	r1, [r7, #40]
	adds	r0, r1, r0
	str	r0, [r7, #40]
.Ltmp212:
	@DEBUG_VALUE: i <- 11
	ldr	r0, [r2, #36]
	ldr	r1, [r7, #44]
	adds	r0, r1, r0
	str	r0, [r7, #44]
.Ltmp213:
	@DEBUG_VALUE: i <- 12
	ldr	r0, [r2, #40]
	ldr	r1, [r7, #48]
	adds	r0, r1, r0
	str	r0, [r7, #48]
.Ltmp214:
	@DEBUG_VALUE: i <- 13
	ldr	r0, [r2, #44]
	ldr	r1, [r7, #52]
	adds	r0, r1, r0
	str	r0, [r7, #52]
.Ltmp215:
	@DEBUG_VALUE: i <- 14
	ldr	r0, [r2, #48]
	ldr	r1, [r7, #56]
	adds	r0, r1, r0
	str	r0, [r7, #56]
.Ltmp216:
	@DEBUG_VALUE: i <- 15
	ldr	r0, [r2, #52]
	ldr	r1, [r7, #60]
	adds	r0, r1, r0
	str	r0, [r7, #60]
.Ltmp217:
	@DEBUG_VALUE: chacha20_block_next:counter <- [DW_OP_plus_uconst 8, DW_OP_deref_size 4, DW_OP_plus_uconst 40, DW_OP_stack_value] $sp
	@DEBUG_VALUE: i <- 16
	ldr	r0, [r2, #40]
	adds	r0, r0, #1
	str	r0, [r2, #40]
	bhs	.LBB1_8
	b	.LBB1_2
.Ltmp218:
.LBB1_8:                                @   in Loop: Header=BB1_4 Depth=1
	@DEBUG_VALUE: chacha20_block_next:counter <- [DW_OP_plus_uconst 8, DW_OP_deref_size 4, DW_OP_plus_uconst 40, DW_OP_stack_value] $sp
	@DEBUG_VALUE: chacha20_block_next:ctx <- [DW_OP_plus_uconst 12] [$sp+0]
	@DEBUG_VALUE: i <- [DW_OP_plus_uconst 24] [$sp+0]
	ldr	r1, [sp]                        @ 4-byte Reload
.Ltmp219:
	ldr	r0, [r1]
	adds	r0, r0, #1
	str	r0, [r1]
	b	.LBB1_2
.Ltmp220:
.LBB1_9:
	add	sp, #96
	pop	{r4, r5, r6, r7, pc}
.Ltmp221:
.Lfunc_end1:
	.size	chacha20_xor, .Lfunc_end1-chacha20_xor
	.cfi_endproc
	.cantunwind
	.fnend
                                        @ -- End function
	.section	.debug_loc,"",%progbits
.Ldebug_loc0:
	.long	-1
	.long	.Lfunc_begin0                   @   base address
	.long	.Lfunc_begin0-.Lfunc_begin0
	.long	.Ltmp3-.Lfunc_begin0
	.short	1                               @ Loc expr size
	.byte	80                              @ DW_OP_reg0
	.long	.Ltmp3-.Lfunc_begin0
	.long	.Ltmp76-.Lfunc_begin0
	.short	1                               @ Loc expr size
	.byte	84                              @ DW_OP_reg4
	.long	0
	.long	0
.Ldebug_loc1:
	.long	-1
	.long	.Lfunc_begin0                   @   base address
	.long	.Lfunc_begin0-.Lfunc_begin0
	.long	.Ltmp2-.Lfunc_begin0
	.short	1                               @ Loc expr size
	.byte	81                              @ DW_OP_reg1
	.long	.Ltmp2-.Lfunc_begin0
	.long	.Ltmp76-.Lfunc_begin0
	.short	1                               @ Loc expr size
	.byte	87                              @ DW_OP_reg7
	.long	0
	.long	0
.Ldebug_loc2:
	.long	-1
	.long	.Lfunc_begin0                   @   base address
	.long	.Lfunc_begin0-.Lfunc_begin0
	.long	.Ltmp1-.Lfunc_begin0
	.short	1                               @ Loc expr size
	.byte	82                              @ DW_OP_reg2
	.long	.Ltmp1-.Lfunc_begin0
	.long	.Ltmp76-.Lfunc_begin0
	.short	1                               @ Loc expr size
	.byte	86                              @ DW_OP_reg6
	.long	0
	.long	0
.Ldebug_loc3:
	.long	-1
	.long	.Lfunc_begin0                   @   base address
	.long	.Ltmp11-.Lfunc_begin0
	.long	.Ltmp12-.Lfunc_begin0
	.short	1                               @ Loc expr size
	.byte	48                              @ DW_OP_lit0
	.long	.Ltmp12-.Lfunc_begin0
	.long	.Ltmp15-.Lfunc_begin0
	.short	1                               @ Loc expr size
	.byte	80                              @ DW_OP_reg0
	.long	0
	.long	0
.Ldebug_loc4:
	.long	-1
	.long	.Lfunc_begin0                   @   base address
	.long	.Ltmp16-.Lfunc_begin0
	.long	.Ltmp17-.Lfunc_begin0
	.short	1                               @ Loc expr size
	.byte	48                              @ DW_OP_lit0
	.long	.Ltmp17-.Lfunc_begin0
	.long	.Ltmp20-.Lfunc_begin0
	.short	1                               @ Loc expr size
	.byte	80                              @ DW_OP_reg0
	.long	0
	.long	0
.Ldebug_loc5:
	.long	-1
	.long	.Lfunc_begin0                   @   base address
	.long	.Ltmp21-.Lfunc_begin0
	.long	.Ltmp22-.Lfunc_begin0
	.short	1                               @ Loc expr size
	.byte	48                              @ DW_OP_lit0
	.long	.Ltmp22-.Lfunc_begin0
	.long	.Ltmp25-.Lfunc_begin0
	.short	1                               @ Loc expr size
	.byte	80                              @ DW_OP_reg0
	.long	0
	.long	0
.Ldebug_loc6:
	.long	-1
	.long	.Lfunc_begin0                   @   base address
	.long	.Ltmp26-.Lfunc_begin0
	.long	.Ltmp27-.Lfunc_begin0
	.short	1                               @ Loc expr size
	.byte	48                              @ DW_OP_lit0
	.long	.Ltmp27-.Lfunc_begin0
	.long	.Ltmp30-.Lfunc_begin0
	.short	1                               @ Loc expr size
	.byte	80                              @ DW_OP_reg0
	.long	0
	.long	0
.Ldebug_loc7:
	.long	-1
	.long	.Lfunc_begin0                   @   base address
	.long	.Ltmp31-.Lfunc_begin0
	.long	.Ltmp32-.Lfunc_begin0
	.short	1                               @ Loc expr size
	.byte	48                              @ DW_OP_lit0
	.long	.Ltmp32-.Lfunc_begin0
	.long	.Ltmp35-.Lfunc_begin0
	.short	1                               @ Loc expr size
	.byte	80                              @ DW_OP_reg0
	.long	0
	.long	0
.Ldebug_loc8:
	.long	-1
	.long	.Lfunc_begin0                   @   base address
	.long	.Ltmp36-.Lfunc_begin0
	.long	.Ltmp37-.Lfunc_begin0
	.short	1                               @ Loc expr size
	.byte	48                              @ DW_OP_lit0
	.long	.Ltmp37-.Lfunc_begin0
	.long	.Ltmp40-.Lfunc_begin0
	.short	1                               @ Loc expr size
	.byte	80                              @ DW_OP_reg0
	.long	0
	.long	0
.Ldebug_loc9:
	.long	-1
	.long	.Lfunc_begin0                   @   base address
	.long	.Ltmp41-.Lfunc_begin0
	.long	.Ltmp42-.Lfunc_begin0
	.short	1                               @ Loc expr size
	.byte	48                              @ DW_OP_lit0
	.long	.Ltmp42-.Lfunc_begin0
	.long	.Ltmp45-.Lfunc_begin0
	.short	1                               @ Loc expr size
	.byte	80                              @ DW_OP_reg0
	.long	0
	.long	0
.Ldebug_loc10:
	.long	-1
	.long	.Lfunc_begin0                   @   base address
	.long	.Ltmp46-.Lfunc_begin0
	.long	.Ltmp47-.Lfunc_begin0
	.short	1                               @ Loc expr size
	.byte	48                              @ DW_OP_lit0
	.long	.Ltmp47-.Lfunc_begin0
	.long	.Ltmp50-.Lfunc_begin0
	.short	1                               @ Loc expr size
	.byte	80                              @ DW_OP_reg0
	.long	0
	.long	0
.Ldebug_loc11:
	.long	-1
	.long	.Lfunc_begin0                   @   base address
	.long	.Ltmp51-.Lfunc_begin0
	.long	.Ltmp52-.Lfunc_begin0
	.short	1                               @ Loc expr size
	.byte	48                              @ DW_OP_lit0
	.long	.Ltmp52-.Lfunc_begin0
	.long	.Ltmp55-.Lfunc_begin0
	.short	1                               @ Loc expr size
	.byte	80                              @ DW_OP_reg0
	.long	0
	.long	0
.Ldebug_loc12:
	.long	-1
	.long	.Lfunc_begin0                   @   base address
	.long	.Ltmp56-.Lfunc_begin0
	.long	.Ltmp57-.Lfunc_begin0
	.short	1                               @ Loc expr size
	.byte	48                              @ DW_OP_lit0
	.long	.Ltmp57-.Lfunc_begin0
	.long	.Ltmp60-.Lfunc_begin0
	.short	1                               @ Loc expr size
	.byte	80                              @ DW_OP_reg0
	.long	0
	.long	0
.Ldebug_loc13:
	.long	-1
	.long	.Lfunc_begin0                   @   base address
	.long	.Ltmp61-.Lfunc_begin0
	.long	.Ltmp62-.Lfunc_begin0
	.short	1                               @ Loc expr size
	.byte	48                              @ DW_OP_lit0
	.long	.Ltmp62-.Lfunc_begin0
	.long	.Ltmp65-.Lfunc_begin0
	.short	1                               @ Loc expr size
	.byte	80                              @ DW_OP_reg0
	.long	0
	.long	0
.Ldebug_loc14:
	.long	-1
	.long	.Lfunc_begin0                   @   base address
	.long	.Ltmp67-.Lfunc_begin0
	.long	.Ltmp73-.Lfunc_begin0
	.short	7                               @ Loc expr size
	.byte	82                              @ DW_OP_reg2
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	125                             @ DW_OP_breg13
	.byte	8                               @ 8
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.long	.Ltmp73-.Lfunc_begin0
	.long	.Ltmp76-.Lfunc_begin0
	.short	6                               @ Loc expr size
	.byte	82                              @ DW_OP_reg2
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.byte	81                              @ DW_OP_reg1
	.byte	147                             @ DW_OP_piece
	.byte	4                               @ 4
	.long	0
	.long	0
.Ldebug_loc15:
	.long	-1
	.long	.Lfunc_begin0                   @   base address
	.long	.Ltmp68-.Lfunc_begin0
	.long	.Ltmp69-.Lfunc_begin0
	.short	1                               @ Loc expr size
	.byte	48                              @ DW_OP_lit0
	.long	.Ltmp69-.Lfunc_begin0
	.long	.Ltmp74-.Lfunc_begin0
	.short	1                               @ Loc expr size
	.byte	80                              @ DW_OP_reg0
	.long	0
	.long	0
.Ldebug_loc16:
	.long	-1
	.long	.Lfunc_begin1                   @   base address
	.long	.Lfunc_begin1-.Lfunc_begin1
	.long	.Ltmp79-.Lfunc_begin1
	.short	1                               @ Loc expr size
	.byte	80                              @ DW_OP_reg0
	.long	.Ltmp79-.Lfunc_begin1
	.long	.Ltmp82-.Lfunc_begin1
	.short	1                               @ Loc expr size
	.byte	86                              @ DW_OP_reg6
	.long	.Ltmp94-.Lfunc_begin1
	.long	.Ltmp96-.Lfunc_begin1
	.short	3                               @ Loc expr size
	.byte	163                             @ DW_OP_entry_value
	.byte	1                               @ 1
	.byte	80                              @ DW_OP_reg0
	.long	0
	.long	0
.Ldebug_loc17:
	.long	-1
	.long	.Lfunc_begin1                   @   base address
	.long	.Lfunc_begin1-.Lfunc_begin1
	.long	.Ltmp82-.Lfunc_begin1
	.short	1                               @ Loc expr size
	.byte	81                              @ DW_OP_reg1
	.long	.Ltmp90-.Lfunc_begin1
	.long	.Ltmp96-.Lfunc_begin1
	.short	3                               @ Loc expr size
	.byte	163                             @ DW_OP_entry_value
	.byte	1                               @ 1
	.byte	81                              @ DW_OP_reg1
	.long	0
	.long	0
.Ldebug_loc18:
	.long	-1
	.long	.Lfunc_begin1                   @   base address
	.long	.Lfunc_begin1-.Lfunc_begin1
	.long	.Ltmp82-.Lfunc_begin1
	.short	1                               @ Loc expr size
	.byte	82                              @ DW_OP_reg2
	.long	.Ltmp91-.Lfunc_begin1
	.long	.Ltmp96-.Lfunc_begin1
	.short	3                               @ Loc expr size
	.byte	163                             @ DW_OP_entry_value
	.byte	1                               @ 1
	.byte	82                              @ DW_OP_reg2
	.long	0
	.long	0
.Ldebug_loc19:
	.long	-1
	.long	.Lfunc_begin1                   @   base address
	.long	.Ltmp77-.Lfunc_begin1
	.long	.Ltmp82-.Lfunc_begin1
	.short	1                               @ Loc expr size
	.byte	48                              @ DW_OP_lit0
	.long	.Ltmp82-.Lfunc_begin1
	.long	.Ltmp84-.Lfunc_begin1
	.short	2                               @ Loc expr size
	.byte	125                             @ DW_OP_breg13
	.byte	24                              @ 24
	.long	.Ltmp86-.Lfunc_begin1
	.long	.Ltmp89-.Lfunc_begin1
	.short	1                               @ Loc expr size
	.byte	85                              @ DW_OP_reg5
	.long	.Ltmp89-.Lfunc_begin1
	.long	.Ltmp220-.Lfunc_begin1
	.short	2                               @ Loc expr size
	.byte	125                             @ DW_OP_breg13
	.byte	24                              @ 24
	.long	0
	.long	0
.Ldebug_loc20:
	.long	-1
	.long	.Lfunc_begin1                   @   base address
	.long	.Ltmp77-.Lfunc_begin1
	.long	.Ltmp79-.Lfunc_begin1
	.short	1                               @ Loc expr size
	.byte	80                              @ DW_OP_reg0
	.long	.Ltmp79-.Lfunc_begin1
	.long	.Ltmp82-.Lfunc_begin1
	.short	1                               @ Loc expr size
	.byte	86                              @ DW_OP_reg6
	.long	0
	.long	0
.Ldebug_loc21:
	.long	-1
	.long	.Lfunc_begin1                   @   base address
	.long	.Ltmp88-.Lfunc_begin1
	.long	.Ltmp93-.Lfunc_begin1
	.short	1                               @ Loc expr size
	.byte	86                              @ DW_OP_reg6
	.long	.Ltmp93-.Lfunc_begin1
	.long	.Ltmp94-.Lfunc_begin1
	.short	1                               @ Loc expr size
	.byte	83                              @ DW_OP_reg3
	.long	.Ltmp94-.Lfunc_begin1
	.long	.Ltmp220-.Lfunc_begin1
	.short	2                               @ Loc expr size
	.byte	125                             @ DW_OP_breg13
	.byte	12                              @ 12
	.long	0
	.long	0
.Ldebug_loc22:
	.long	-1
	.long	.Lfunc_begin1                   @   base address
	.long	.Ltmp88-.Lfunc_begin1
	.long	.Ltmp92-.Lfunc_begin1
	.short	2                               @ Loc expr size
	.byte	17                              @ DW_OP_consts
	.byte	0                               @ 0
	.long	0
	.long	0
.Ldebug_loc23:
	.long	-1
	.long	.Lfunc_begin1                   @   base address
	.long	.Ltmp98-.Lfunc_begin1
	.long	.Ltmp197-.Lfunc_begin1
	.short	2                               @ Loc expr size
	.byte	17                              @ DW_OP_consts
	.byte	16                              @ 16
	.long	0
	.long	0
.Ldebug_loc24:
	.long	-1
	.long	.Lfunc_begin1                   @   base address
	.long	.Ltmp98-.Lfunc_begin1
	.long	.Ltmp99-.Lfunc_begin1
	.short	1                               @ Loc expr size
	.byte	82                              @ DW_OP_reg2
	.long	0
	.long	0
.Ldebug_loc25:
	.long	-1
	.long	.Lfunc_begin1                   @   base address
	.long	.Ltmp101-.Lfunc_begin1
	.long	.Ltmp197-.Lfunc_begin1
	.short	2                               @ Loc expr size
	.byte	17                              @ DW_OP_consts
	.byte	12                              @ 12
	.long	0
	.long	0
.Ldebug_loc26:
	.long	-1
	.long	.Lfunc_begin1                   @   base address
	.long	.Ltmp101-.Lfunc_begin1
	.long	.Ltmp102-.Lfunc_begin1
	.short	1                               @ Loc expr size
	.byte	85                              @ DW_OP_reg5
	.long	0
	.long	0
.Ldebug_loc27:
	.long	-1
	.long	.Lfunc_begin1                   @   base address
	.long	.Ltmp104-.Lfunc_begin1
	.long	.Ltmp197-.Lfunc_begin1
	.short	2                               @ Loc expr size
	.byte	17                              @ DW_OP_consts
	.byte	8                               @ 8
	.long	0
	.long	0
.Ldebug_loc28:
	.long	-1
	.long	.Lfunc_begin1                   @   base address
	.long	.Ltmp104-.Lfunc_begin1
	.long	.Ltmp105-.Lfunc_begin1
	.short	1                               @ Loc expr size
	.byte	82                              @ DW_OP_reg2
	.long	0
	.long	0
.Ldebug_loc29:
	.long	-1
	.long	.Lfunc_begin1                   @   base address
	.long	.Ltmp106-.Lfunc_begin1
	.long	.Ltmp107-.Lfunc_begin1
	.short	1                               @ Loc expr size
	.byte	85                              @ DW_OP_reg5
	.long	0
	.long	0
.Ldebug_loc30:
	.long	-1
	.long	.Lfunc_begin1                   @   base address
	.long	.Ltmp110-.Lfunc_begin1
	.long	.Ltmp197-.Lfunc_begin1
	.short	2                               @ Loc expr size
	.byte	17                              @ DW_OP_consts
	.byte	16                              @ 16
	.long	0
	.long	0
.Ldebug_loc31:
	.long	-1
	.long	.Lfunc_begin1                   @   base address
	.long	.Ltmp110-.Lfunc_begin1
	.long	.Ltmp111-.Lfunc_begin1
	.short	1                               @ Loc expr size
	.byte	81                              @ DW_OP_reg1
	.long	0
	.long	0
.Ldebug_loc32:
	.long	-1
	.long	.Lfunc_begin1                   @   base address
	.long	.Ltmp113-.Lfunc_begin1
	.long	.Ltmp197-.Lfunc_begin1
	.short	2                               @ Loc expr size
	.byte	17                              @ DW_OP_consts
	.byte	12                              @ 12
	.long	0
	.long	0
.Ldebug_loc33:
	.long	-1
	.long	.Lfunc_begin1                   @   base address
	.long	.Ltmp113-.Lfunc_begin1
	.long	.Ltmp114-.Lfunc_begin1
	.short	1                               @ Loc expr size
	.byte	85                              @ DW_OP_reg5
	.long	0
	.long	0
.Ldebug_loc34:
	.long	-1
	.long	.Lfunc_begin1                   @   base address
	.long	.Ltmp117-.Lfunc_begin1
	.long	.Ltmp118-.Lfunc_begin1
	.short	1                               @ Loc expr size
	.byte	85                              @ DW_OP_reg5
	.long	0
	.long	0
.Ldebug_loc35:
	.long	-1
	.long	.Lfunc_begin1                   @   base address
	.long	.Ltmp121-.Lfunc_begin1
	.long	.Ltmp197-.Lfunc_begin1
	.short	2                               @ Loc expr size
	.byte	17                              @ DW_OP_consts
	.byte	16                              @ 16
	.long	0
	.long	0
.Ldebug_loc36:
	.long	-1
	.long	.Lfunc_begin1                   @   base address
	.long	.Ltmp121-.Lfunc_begin1
	.long	.Ltmp122-.Lfunc_begin1
	.short	1                               @ Loc expr size
	.byte	86                              @ DW_OP_reg6
	.long	0
	.long	0
.Ldebug_loc37:
	.long	-1
	.long	.Lfunc_begin1                   @   base address
	.long	.Ltmp124-.Lfunc_begin1
	.long	.Ltmp197-.Lfunc_begin1
	.short	2                               @ Loc expr size
	.byte	17                              @ DW_OP_consts
	.byte	12                              @ 12
	.long	0
	.long	0
.Ldebug_loc38:
	.long	-1
	.long	.Lfunc_begin1                   @   base address
	.long	.Ltmp124-.Lfunc_begin1
	.long	.Ltmp125-.Lfunc_begin1
	.short	1                               @ Loc expr size
	.byte	87                              @ DW_OP_reg7
	.long	0
	.long	0
.Ldebug_loc39:
	.long	-1
	.long	.Lfunc_begin1                   @   base address
	.long	.Ltmp129-.Lfunc_begin1
	.long	.Ltmp197-.Lfunc_begin1
	.short	2                               @ Loc expr size
	.byte	17                              @ DW_OP_consts
	.byte	7                               @ 7
	.long	0
	.long	0
.Ldebug_loc40:
	.long	-1
	.long	.Lfunc_begin1                   @   base address
	.long	.Ltmp129-.Lfunc_begin1
	.long	.Ltmp130-.Lfunc_begin1
	.short	1                               @ Loc expr size
	.byte	87                              @ DW_OP_reg7
	.long	0
	.long	0
.Ldebug_loc41:
	.long	-1
	.long	.Lfunc_begin1                   @   base address
	.long	.Ltmp133-.Lfunc_begin1
	.long	.Ltmp197-.Lfunc_begin1
	.short	2                               @ Loc expr size
	.byte	17                              @ DW_OP_consts
	.byte	16                              @ 16
	.long	0
	.long	0
.Ldebug_loc42:
	.long	-1
	.long	.Lfunc_begin1                   @   base address
	.long	.Ltmp133-.Lfunc_begin1
	.long	.Ltmp134-.Lfunc_begin1
	.short	1                               @ Loc expr size
	.byte	83                              @ DW_OP_reg3
	.long	0
	.long	0
.Ldebug_loc43:
	.long	-1
	.long	.Lfunc_begin1                   @   base address
	.long	.Ltmp136-.Lfunc_begin1
	.long	.Ltmp197-.Lfunc_begin1
	.short	2                               @ Loc expr size
	.byte	17                              @ DW_OP_consts
	.byte	12                              @ 12
	.long	0
	.long	0
.Ldebug_loc44:
	.long	-1
	.long	.Lfunc_begin1                   @   base address
	.long	.Ltmp136-.Lfunc_begin1
	.long	.Ltmp137-.Lfunc_begin1
	.short	1                               @ Loc expr size
	.byte	80                              @ DW_OP_reg0
	.long	0
	.long	0
.Ldebug_loc45:
	.long	-1
	.long	.Lfunc_begin1                   @   base address
	.long	.Ltmp139-.Lfunc_begin1
	.long	.Ltmp197-.Lfunc_begin1
	.short	2                               @ Loc expr size
	.byte	17                              @ DW_OP_consts
	.byte	8                               @ 8
	.long	0
	.long	0
.Ldebug_loc46:
	.long	-1
	.long	.Lfunc_begin1                   @   base address
	.long	.Ltmp139-.Lfunc_begin1
	.long	.Ltmp140-.Lfunc_begin1
	.short	1                               @ Loc expr size
	.byte	83                              @ DW_OP_reg3
	.long	0
	.long	0
.Ldebug_loc47:
	.long	-1
	.long	.Lfunc_begin1                   @   base address
	.long	.Ltmp142-.Lfunc_begin1
	.long	.Ltmp197-.Lfunc_begin1
	.short	2                               @ Loc expr size
	.byte	17                              @ DW_OP_consts
	.byte	7                               @ 7
	.long	0
	.long	0
.Ldebug_loc48:
	.long	-1
	.long	.Lfunc_begin1                   @   base address
	.long	.Ltmp142-.Lfunc_begin1
	.long	.Ltmp143-.Lfunc_begin1
	.short	1                               @ Loc expr size
	.byte	80                              @ DW_OP_reg0
	.long	0
	.long	0
.Ldebug_loc49:
	.long	-1
	.long	.Lfunc_begin1                   @   base address
	.long	.Ltmp145-.Lfunc_begin1
	.long	.Ltmp197-.Lfunc_begin1
	.short	2                               @ Loc expr size
	.byte	17                              @ DW_OP_consts
	.byte	16                              @ 16
	.long	0
	.long	0
.Ldebug_loc50:
	.long	-1
	.long	.Lfunc_begin1                   @   base address
	.long	.Ltmp145-.Lfunc_begin1
	.long	.Ltmp146-.Lfunc_begin1
	.short	1                               @ Loc expr size
	.byte	83                              @ DW_OP_reg3
	.long	0
	.long	0
.Ldebug_loc51:
	.long	-1
	.long	.Lfunc_begin1                   @   base address
	.long	.Ltmp148-.Lfunc_begin1
	.long	.Ltmp197-.Lfunc_begin1
	.short	2                               @ Loc expr size
	.byte	17                              @ DW_OP_consts
	.byte	12                              @ 12
	.long	0
	.long	0
.Ldebug_loc52:
	.long	-1
	.long	.Lfunc_begin1                   @   base address
	.long	.Ltmp148-.Lfunc_begin1
	.long	.Ltmp149-.Lfunc_begin1
	.short	1                               @ Loc expr size
	.byte	85                              @ DW_OP_reg5
	.long	0
	.long	0
.Ldebug_loc53:
	.long	-1
	.long	.Lfunc_begin1                   @   base address
	.long	.Ltmp151-.Lfunc_begin1
	.long	.Ltmp197-.Lfunc_begin1
	.short	2                               @ Loc expr size
	.byte	17                              @ DW_OP_consts
	.byte	8                               @ 8
	.long	0
	.long	0
.Ldebug_loc54:
	.long	-1
	.long	.Lfunc_begin1                   @   base address
	.long	.Ltmp151-.Lfunc_begin1
	.long	.Ltmp152-.Lfunc_begin1
	.short	1                               @ Loc expr size
	.byte	83                              @ DW_OP_reg3
	.long	0
	.long	0
.Ldebug_loc55:
	.long	-1
	.long	.Lfunc_begin1                   @   base address
	.long	.Ltmp154-.Lfunc_begin1
	.long	.Ltmp197-.Lfunc_begin1
	.short	2                               @ Loc expr size
	.byte	17                              @ DW_OP_consts
	.byte	7                               @ 7
	.long	0
	.long	0
.Ldebug_loc56:
	.long	-1
	.long	.Lfunc_begin1                   @   base address
	.long	.Ltmp154-.Lfunc_begin1
	.long	.Ltmp155-.Lfunc_begin1
	.short	1                               @ Loc expr size
	.byte	85                              @ DW_OP_reg5
	.long	0
	.long	0
.Ldebug_loc57:
	.long	-1
	.long	.Lfunc_begin1                   @   base address
	.long	.Ltmp158-.Lfunc_begin1
	.long	.Ltmp197-.Lfunc_begin1
	.short	2                               @ Loc expr size
	.byte	17                              @ DW_OP_consts
	.byte	16                              @ 16
	.long	0
	.long	0
.Ldebug_loc58:
	.long	-1
	.long	.Lfunc_begin1                   @   base address
	.long	.Ltmp158-.Lfunc_begin1
	.long	.Ltmp159-.Lfunc_begin1
	.short	1                               @ Loc expr size
	.byte	82                              @ DW_OP_reg2
	.long	0
	.long	0
.Ldebug_loc59:
	.long	-1
	.long	.Lfunc_begin1                   @   base address
	.long	.Ltmp161-.Lfunc_begin1
	.long	.Ltmp197-.Lfunc_begin1
	.short	2                               @ Loc expr size
	.byte	17                              @ DW_OP_consts
	.byte	12                              @ 12
	.long	0
	.long	0
.Ldebug_loc60:
	.long	-1
	.long	.Lfunc_begin1                   @   base address
	.long	.Ltmp161-.Lfunc_begin1
	.long	.Ltmp162-.Lfunc_begin1
	.short	1                               @ Loc expr size
	.byte	87                              @ DW_OP_reg7
	.long	0
	.long	0
.Ldebug_loc61:
	.long	-1
	.long	.Lfunc_begin1                   @   base address
	.long	.Ltmp164-.Lfunc_begin1
	.long	.Ltmp197-.Lfunc_begin1
	.short	2                               @ Loc expr size
	.byte	17                              @ DW_OP_consts
	.byte	8                               @ 8
	.long	0
	.long	0
.Ldebug_loc62:
	.long	-1
	.long	.Lfunc_begin1                   @   base address
	.long	.Ltmp164-.Lfunc_begin1
	.long	.Ltmp165-.Lfunc_begin1
	.short	1                               @ Loc expr size
	.byte	82                              @ DW_OP_reg2
	.long	0
	.long	0
.Ldebug_loc63:
	.long	-1
	.long	.Lfunc_begin1                   @   base address
	.long	.Ltmp167-.Lfunc_begin1
	.long	.Ltmp197-.Lfunc_begin1
	.short	2                               @ Loc expr size
	.byte	17                              @ DW_OP_consts
	.byte	7                               @ 7
	.long	0
	.long	0
.Ldebug_loc64:
	.long	-1
	.long	.Lfunc_begin1                   @   base address
	.long	.Ltmp167-.Lfunc_begin1
	.long	.Ltmp168-.Lfunc_begin1
	.short	1                               @ Loc expr size
	.byte	87                              @ DW_OP_reg7
	.long	0
	.long	0
.Ldebug_loc65:
	.long	-1
	.long	.Lfunc_begin1                   @   base address
	.long	.Ltmp171-.Lfunc_begin1
	.long	.Ltmp197-.Lfunc_begin1
	.short	2                               @ Loc expr size
	.byte	17                              @ DW_OP_consts
	.byte	16                              @ 16
	.long	0
	.long	0
.Ldebug_loc66:
	.long	-1
	.long	.Lfunc_begin1                   @   base address
	.long	.Ltmp171-.Lfunc_begin1
	.long	.Ltmp172-.Lfunc_begin1
	.short	1                               @ Loc expr size
	.byte	81                              @ DW_OP_reg1
	.long	0
	.long	0
.Ldebug_loc67:
	.long	-1
	.long	.Lfunc_begin1                   @   base address
	.long	.Ltmp174-.Lfunc_begin1
	.long	.Ltmp197-.Lfunc_begin1
	.short	2                               @ Loc expr size
	.byte	17                              @ DW_OP_consts
	.byte	12                              @ 12
	.long	0
	.long	0
.Ldebug_loc68:
	.long	-1
	.long	.Lfunc_begin1                   @   base address
	.long	.Ltmp174-.Lfunc_begin1
	.long	.Ltmp175-.Lfunc_begin1
	.short	1                               @ Loc expr size
	.byte	80                              @ DW_OP_reg0
	.long	0
	.long	0
.Ldebug_loc69:
	.long	-1
	.long	.Lfunc_begin1                   @   base address
	.long	.Ltmp177-.Lfunc_begin1
	.long	.Ltmp197-.Lfunc_begin1
	.short	2                               @ Loc expr size
	.byte	17                              @ DW_OP_consts
	.byte	8                               @ 8
	.long	0
	.long	0
.Ldebug_loc70:
	.long	-1
	.long	.Lfunc_begin1                   @   base address
	.long	.Ltmp177-.Lfunc_begin1
	.long	.Ltmp178-.Lfunc_begin1
	.short	1                               @ Loc expr size
	.byte	81                              @ DW_OP_reg1
	.long	0
	.long	0
.Ldebug_loc71:
	.long	-1
	.long	.Lfunc_begin1                   @   base address
	.long	.Ltmp180-.Lfunc_begin1
	.long	.Ltmp197-.Lfunc_begin1
	.short	2                               @ Loc expr size
	.byte	17                              @ DW_OP_consts
	.byte	7                               @ 7
	.long	0
	.long	0
.Ldebug_loc72:
	.long	-1
	.long	.Lfunc_begin1                   @   base address
	.long	.Ltmp180-.Lfunc_begin1
	.long	.Ltmp181-.Lfunc_begin1
	.short	1                               @ Loc expr size
	.byte	80                              @ DW_OP_reg0
	.long	0
	.long	0
.Ldebug_loc73:
	.long	-1
	.long	.Lfunc_begin1                   @   base address
	.long	.Ltmp184-.Lfunc_begin1
	.long	.Ltmp197-.Lfunc_begin1
	.short	2                               @ Loc expr size
	.byte	17                              @ DW_OP_consts
	.byte	16                              @ 16
	.long	0
	.long	0
.Ldebug_loc74:
	.long	-1
	.long	.Lfunc_begin1                   @   base address
	.long	.Ltmp184-.Lfunc_begin1
	.long	.Ltmp185-.Lfunc_begin1
	.short	1                               @ Loc expr size
	.byte	86                              @ DW_OP_reg6
	.long	0
	.long	0
.Ldebug_loc75:
	.long	-1
	.long	.Lfunc_begin1                   @   base address
	.long	.Ltmp187-.Lfunc_begin1
	.long	.Ltmp197-.Lfunc_begin1
	.short	2                               @ Loc expr size
	.byte	17                              @ DW_OP_consts
	.byte	12                              @ 12
	.long	0
	.long	0
.Ldebug_loc76:
	.long	-1
	.long	.Lfunc_begin1                   @   base address
	.long	.Ltmp187-.Lfunc_begin1
	.long	.Ltmp188-.Lfunc_begin1
	.short	1                               @ Loc expr size
	.byte	85                              @ DW_OP_reg5
	.long	0
	.long	0
.Ldebug_loc77:
	.long	-1
	.long	.Lfunc_begin1                   @   base address
	.long	.Ltmp190-.Lfunc_begin1
	.long	.Ltmp197-.Lfunc_begin1
	.short	2                               @ Loc expr size
	.byte	17                              @ DW_OP_consts
	.byte	8                               @ 8
	.long	0
	.long	0
.Ldebug_loc78:
	.long	-1
	.long	.Lfunc_begin1                   @   base address
	.long	.Ltmp190-.Lfunc_begin1
	.long	.Ltmp191-.Lfunc_begin1
	.short	1                               @ Loc expr size
	.byte	86                              @ DW_OP_reg6
	.long	0
	.long	0
.Ldebug_loc79:
	.long	-1
	.long	.Lfunc_begin1                   @   base address
	.long	.Ltmp193-.Lfunc_begin1
	.long	.Ltmp197-.Lfunc_begin1
	.short	2                               @ Loc expr size
	.byte	17                              @ DW_OP_consts
	.byte	7                               @ 7
	.long	0
	.long	0
.Ldebug_loc80:
	.long	-1
	.long	.Lfunc_begin1                   @   base address
	.long	.Ltmp193-.Lfunc_begin1
	.long	.Ltmp194-.Lfunc_begin1
	.short	1                               @ Loc expr size
	.byte	85                              @ DW_OP_reg5
	.long	0
	.long	0
.Ldebug_loc81:
	.long	-1
	.long	.Lfunc_begin1                   @   base address
	.long	.Ltmp199-.Lfunc_begin1
	.long	.Ltmp200-.Lfunc_begin1
	.short	2                               @ Loc expr size
	.byte	17                              @ DW_OP_consts
	.byte	0                               @ 0
	.long	.Ltmp200-.Lfunc_begin1
	.long	.Ltmp203-.Lfunc_begin1
	.short	2                               @ Loc expr size
	.byte	17                              @ DW_OP_consts
	.byte	1                               @ 1
	.long	.Ltmp203-.Lfunc_begin1
	.long	.Ltmp204-.Lfunc_begin1
	.short	2                               @ Loc expr size
	.byte	17                              @ DW_OP_consts
	.byte	2                               @ 2
	.long	.Ltmp204-.Lfunc_begin1
	.long	.Ltmp205-.Lfunc_begin1
	.short	2                               @ Loc expr size
	.byte	17                              @ DW_OP_consts
	.byte	3                               @ 3
	.long	.Ltmp205-.Lfunc_begin1
	.long	.Ltmp206-.Lfunc_begin1
	.short	2                               @ Loc expr size
	.byte	17                              @ DW_OP_consts
	.byte	4                               @ 4
	.long	.Ltmp206-.Lfunc_begin1
	.long	.Ltmp207-.Lfunc_begin1
	.short	2                               @ Loc expr size
	.byte	17                              @ DW_OP_consts
	.byte	5                               @ 5
	.long	.Ltmp207-.Lfunc_begin1
	.long	.Ltmp208-.Lfunc_begin1
	.short	2                               @ Loc expr size
	.byte	17                              @ DW_OP_consts
	.byte	6                               @ 6
	.long	.Ltmp208-.Lfunc_begin1
	.long	.Ltmp209-.Lfunc_begin1
	.short	2                               @ Loc expr size
	.byte	17                              @ DW_OP_consts
	.byte	7                               @ 7
	.long	.Ltmp209-.Lfunc_begin1
	.long	.Ltmp210-.Lfunc_begin1
	.short	2                               @ Loc expr size
	.byte	17                              @ DW_OP_consts
	.byte	8                               @ 8
	.long	.Ltmp210-.Lfunc_begin1
	.long	.Ltmp211-.Lfunc_begin1
	.short	2                               @ Loc expr size
	.byte	17                              @ DW_OP_consts
	.byte	9                               @ 9
	.long	.Ltmp211-.Lfunc_begin1
	.long	.Ltmp212-.Lfunc_begin1
	.short	2                               @ Loc expr size
	.byte	17                              @ DW_OP_consts
	.byte	10                              @ 10
	.long	.Ltmp212-.Lfunc_begin1
	.long	.Ltmp213-.Lfunc_begin1
	.short	2                               @ Loc expr size
	.byte	17                              @ DW_OP_consts
	.byte	11                              @ 11
	.long	.Ltmp213-.Lfunc_begin1
	.long	.Ltmp214-.Lfunc_begin1
	.short	2                               @ Loc expr size
	.byte	17                              @ DW_OP_consts
	.byte	12                              @ 12
	.long	.Ltmp214-.Lfunc_begin1
	.long	.Ltmp215-.Lfunc_begin1
	.short	2                               @ Loc expr size
	.byte	17                              @ DW_OP_consts
	.byte	13                              @ 13
	.long	.Ltmp215-.Lfunc_begin1
	.long	.Ltmp216-.Lfunc_begin1
	.short	2                               @ Loc expr size
	.byte	17                              @ DW_OP_consts
	.byte	14                              @ 14
	.long	.Ltmp216-.Lfunc_begin1
	.long	.Ltmp217-.Lfunc_begin1
	.short	2                               @ Loc expr size
	.byte	17                              @ DW_OP_consts
	.byte	15                              @ 15
	.long	.Ltmp217-.Lfunc_begin1
	.long	.Ltmp218-.Lfunc_begin1
	.short	2                               @ Loc expr size
	.byte	17                              @ DW_OP_consts
	.byte	16                              @ 16
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
	.byte	73                              @ DW_AT_type
	.byte	19                              @ DW_FORM_ref4
	.byte	58                              @ DW_AT_decl_file
	.byte	11                              @ DW_FORM_data1
	.byte	59                              @ DW_AT_decl_line
	.byte	11                              @ DW_FORM_data1
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
	.byte	15                              @ DW_TAG_pointer_type
	.byte	0                               @ DW_CHILDREN_no
	.byte	73                              @ DW_AT_type
	.byte	19                              @ DW_FORM_ref4
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
	.byte	11                              @ DW_FORM_data1
	.byte	39                              @ DW_AT_prototyped
	.byte	12                              @ DW_FORM_flag
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
	.byte	11                              @ DW_FORM_data1
	.byte	73                              @ DW_AT_type
	.byte	19                              @ DW_FORM_ref4
	.byte	0                               @ EOM(1)
	.byte	0                               @ EOM(2)
	.byte	11                              @ Abbreviation Code
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
	.byte	12                              @ Abbreviation Code
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
	.byte	13                              @ Abbreviation Code
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
	.byte	32                              @ DW_AT_inline
	.byte	11                              @ DW_FORM_data1
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
	.byte	39                              @ DW_AT_prototyped
	.byte	12                              @ DW_FORM_flag
	.byte	63                              @ DW_AT_external
	.byte	12                              @ DW_FORM_flag
	.byte	0                               @ EOM(1)
	.byte	0                               @ EOM(2)
	.byte	17                              @ Abbreviation Code
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
	.byte	18                              @ Abbreviation Code
	.byte	5                               @ DW_TAG_formal_parameter
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
	.byte	2                               @ DW_AT_location
	.byte	10                              @ DW_FORM_block1
	.byte	49                              @ DW_AT_abstract_origin
	.byte	19                              @ DW_FORM_ref4
	.byte	0                               @ EOM(1)
	.byte	0                               @ EOM(2)
	.byte	21                              @ Abbreviation Code
	.byte	52                              @ DW_TAG_variable
	.byte	0                               @ DW_CHILDREN_no
	.byte	2                               @ DW_AT_location
	.byte	6                               @ DW_FORM_data4
	.byte	49                              @ DW_AT_abstract_origin
	.byte	19                              @ DW_FORM_ref4
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
	.byte	5                               @ DW_TAG_formal_parameter
	.byte	0                               @ DW_CHILDREN_no
	.byte	2                               @ DW_AT_location
	.byte	6                               @ DW_FORM_data4
	.byte	49                              @ DW_AT_abstract_origin
	.byte	19                              @ DW_FORM_ref4
	.byte	0                               @ EOM(1)
	.byte	0                               @ EOM(2)
	.byte	24                              @ Abbreviation Code
	.byte	11                              @ DW_TAG_lexical_block
	.byte	1                               @ DW_CHILDREN_yes
	.byte	0                               @ EOM(1)
	.byte	0                               @ EOM(2)
	.byte	25                              @ Abbreviation Code
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
	.byte	26                              @ Abbreviation Code
	.byte	11                              @ DW_TAG_lexical_block
	.byte	1                               @ DW_CHILDREN_yes
	.byte	17                              @ DW_AT_low_pc
	.byte	1                               @ DW_FORM_addr
	.byte	18                              @ DW_AT_high_pc
	.byte	1                               @ DW_FORM_addr
	.byte	0                               @ EOM(1)
	.byte	0                               @ EOM(2)
	.byte	27                              @ Abbreviation Code
	.byte	52                              @ DW_TAG_variable
	.byte	0                               @ DW_CHILDREN_no
	.byte	49                              @ DW_AT_abstract_origin
	.byte	19                              @ DW_FORM_ref4
	.byte	0                               @ EOM(1)
	.byte	0                               @ EOM(2)
	.byte	28                              @ Abbreviation Code
	.byte	11                              @ DW_TAG_lexical_block
	.byte	1                               @ DW_CHILDREN_yes
	.byte	85                              @ DW_AT_ranges
	.byte	6                               @ DW_FORM_data4
	.byte	0                               @ EOM(1)
	.byte	0                               @ EOM(2)
	.byte	29                              @ Abbreviation Code
	.byte	5                               @ DW_TAG_formal_parameter
	.byte	0                               @ DW_CHILDREN_no
	.byte	28                              @ DW_AT_const_value
	.byte	13                              @ DW_FORM_sdata
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
	.byte	1                               @ Abbrev [1] 0xb:0x930 DW_TAG_compile_unit
	.long	.Linfo_string0                  @ DW_AT_producer
	.short	29                              @ DW_AT_language
	.long	.Linfo_string1                  @ DW_AT_name
	.long	.Lline_table_start0             @ DW_AT_stmt_list
	.long	.Linfo_string2                  @ DW_AT_comp_dir
	.long	0                               @ DW_AT_low_pc
	.long	.Ldebug_ranges2                 @ DW_AT_ranges
	.byte	2                               @ Abbrev [2] 0x26:0x7 DW_TAG_variable
	.long	45                              @ DW_AT_type
	.byte	1                               @ DW_AT_decl_file
	.byte	24                              @ DW_AT_decl_line
	.byte	3                               @ Abbrev [3] 0x2d:0xc DW_TAG_array_type
	.long	57                              @ DW_AT_type
	.byte	4                               @ Abbrev [4] 0x32:0x6 DW_TAG_subrange_type
	.long	64                              @ DW_AT_type
	.byte	17                              @ DW_AT_count
	.byte	0                               @ End Of Children Mark
	.byte	5                               @ Abbrev [5] 0x39:0x7 DW_TAG_base_type
	.long	.Linfo_string3                  @ DW_AT_name
	.byte	8                               @ DW_AT_encoding
	.byte	1                               @ DW_AT_byte_size
	.byte	6                               @ Abbrev [6] 0x40:0x7 DW_TAG_base_type
	.long	.Linfo_string4                  @ DW_AT_name
	.byte	8                               @ DW_AT_byte_size
	.byte	7                               @ DW_AT_encoding
	.byte	7                               @ Abbrev [7] 0x47:0x5 DW_TAG_pointer_type
	.long	76                              @ DW_AT_type
	.byte	8                               @ Abbrev [8] 0x4c:0xb DW_TAG_typedef
	.long	87                              @ DW_AT_type
	.long	.Linfo_string7                  @ DW_AT_name
	.byte	3                               @ DW_AT_decl_file
	.byte	59                              @ DW_AT_decl_line
	.byte	8                               @ Abbrev [8] 0x57:0xb DW_TAG_typedef
	.long	98                              @ DW_AT_type
	.long	.Linfo_string6                  @ DW_AT_name
	.byte	2                               @ DW_AT_decl_file
	.byte	75                              @ DW_AT_decl_line
	.byte	5                               @ Abbrev [5] 0x62:0x7 DW_TAG_base_type
	.long	.Linfo_string5                  @ DW_AT_name
	.byte	8                               @ DW_AT_encoding
	.byte	1                               @ DW_AT_byte_size
	.byte	8                               @ Abbrev [8] 0x69:0xb DW_TAG_typedef
	.long	116                             @ DW_AT_type
	.long	.Linfo_string10                 @ DW_AT_name
	.byte	3                               @ DW_AT_decl_file
	.byte	70                              @ DW_AT_decl_line
	.byte	8                               @ Abbrev [8] 0x74:0xb DW_TAG_typedef
	.long	127                             @ DW_AT_type
	.long	.Linfo_string9                  @ DW_AT_name
	.byte	2                               @ DW_AT_decl_file
	.byte	79                              @ DW_AT_decl_line
	.byte	5                               @ Abbrev [5] 0x7f:0x7 DW_TAG_base_type
	.long	.Linfo_string8                  @ DW_AT_name
	.byte	7                               @ DW_AT_encoding
	.byte	4                               @ DW_AT_byte_size
	.byte	9                               @ Abbrev [9] 0x86:0x36 DW_TAG_subprogram
	.long	.Linfo_string11                 @ DW_AT_name
	.byte	1                               @ DW_AT_decl_file
	.byte	19                              @ DW_AT_decl_line
	.byte	1                               @ DW_AT_prototyped
	.byte	1                               @ DW_AT_inline
	.byte	10                              @ Abbrev [10] 0x8f:0xb DW_TAG_formal_parameter
	.long	.Linfo_string12                 @ DW_AT_name
	.byte	1                               @ DW_AT_decl_file
	.byte	19                              @ DW_AT_decl_line
	.long	188                             @ DW_AT_type
	.byte	10                              @ Abbrev [10] 0x9a:0xb DW_TAG_formal_parameter
	.long	.Linfo_string16                 @ DW_AT_name
	.byte	1                               @ DW_AT_decl_file
	.byte	19                              @ DW_AT_decl_line
	.long	71                              @ DW_AT_type
	.byte	10                              @ Abbrev [10] 0xa5:0xb DW_TAG_formal_parameter
	.long	.Linfo_string17                 @ DW_AT_name
	.byte	1                               @ DW_AT_decl_file
	.byte	19                              @ DW_AT_decl_line
	.long	71                              @ DW_AT_type
	.byte	11                              @ Abbrev [11] 0xb0:0xb DW_TAG_variable
	.long	.Linfo_string24                 @ DW_AT_name
	.byte	1                               @ DW_AT_decl_file
	.byte	24                              @ DW_AT_decl_line
	.long	350                             @ DW_AT_type
	.byte	0                               @ End Of Children Mark
	.byte	7                               @ Abbrev [7] 0xbc:0x5 DW_TAG_pointer_type
	.long	193                             @ DW_AT_type
	.byte	12                              @ Abbrev [12] 0xc1:0x51 DW_TAG_structure_type
	.long	.Linfo_string23                 @ DW_AT_name
	.byte	184                             @ DW_AT_byte_size
	.byte	4                               @ DW_AT_decl_file
	.byte	12                              @ DW_AT_decl_line
	.byte	13                              @ Abbrev [13] 0xc9:0xc DW_TAG_member
	.long	.Linfo_string13                 @ DW_AT_name
	.long	274                             @ DW_AT_type
	.byte	4                               @ DW_AT_decl_file
	.byte	14                              @ DW_AT_decl_line
	.byte	0                               @ DW_AT_data_member_location
	.byte	13                              @ Abbrev [13] 0xd5:0xc DW_TAG_member
	.long	.Linfo_string14                 @ DW_AT_name
	.long	286                             @ DW_AT_type
	.byte	4                               @ DW_AT_decl_file
	.byte	15                              @ DW_AT_decl_line
	.byte	64                              @ DW_AT_data_member_location
	.byte	13                              @ Abbrev [13] 0xe1:0xc DW_TAG_member
	.long	.Linfo_string16                 @ DW_AT_name
	.long	297                             @ DW_AT_type
	.byte	4                               @ DW_AT_decl_file
	.byte	17                              @ DW_AT_decl_line
	.byte	68                              @ DW_AT_data_member_location
	.byte	13                              @ Abbrev [13] 0xed:0xc DW_TAG_member
	.long	.Linfo_string17                 @ DW_AT_name
	.long	309                             @ DW_AT_type
	.byte	4                               @ DW_AT_decl_file
	.byte	18                              @ DW_AT_decl_line
	.byte	100                             @ DW_AT_data_member_location
	.byte	13                              @ Abbrev [13] 0xf9:0xc DW_TAG_member
	.long	.Linfo_string18                 @ DW_AT_name
	.long	321                             @ DW_AT_type
	.byte	4                               @ DW_AT_decl_file
	.byte	19                              @ DW_AT_decl_line
	.byte	112                             @ DW_AT_data_member_location
	.byte	13                              @ Abbrev [13] 0x105:0xc DW_TAG_member
	.long	.Linfo_string22                 @ DW_AT_name
	.long	274                             @ DW_AT_type
	.byte	4                               @ DW_AT_decl_file
	.byte	21                              @ DW_AT_decl_line
	.byte	120                             @ DW_AT_data_member_location
	.byte	0                               @ End Of Children Mark
	.byte	3                               @ Abbrev [3] 0x112:0xc DW_TAG_array_type
	.long	105                             @ DW_AT_type
	.byte	4                               @ Abbrev [4] 0x117:0x6 DW_TAG_subrange_type
	.long	64                              @ DW_AT_type
	.byte	16                              @ DW_AT_count
	.byte	0                               @ End Of Children Mark
	.byte	8                               @ Abbrev [8] 0x11e:0xb DW_TAG_typedef
	.long	127                             @ DW_AT_type
	.long	.Linfo_string15                 @ DW_AT_name
	.byte	5                               @ DW_AT_decl_file
	.byte	66                              @ DW_AT_decl_line
	.byte	3                               @ Abbrev [3] 0x129:0xc DW_TAG_array_type
	.long	76                              @ DW_AT_type
	.byte	4                               @ Abbrev [4] 0x12e:0x6 DW_TAG_subrange_type
	.long	64                              @ DW_AT_type
	.byte	32                              @ DW_AT_count
	.byte	0                               @ End Of Children Mark
	.byte	3                               @ Abbrev [3] 0x135:0xc DW_TAG_array_type
	.long	76                              @ DW_AT_type
	.byte	4                               @ Abbrev [4] 0x13a:0x6 DW_TAG_subrange_type
	.long	64                              @ DW_AT_type
	.byte	12                              @ DW_AT_count
	.byte	0                               @ End Of Children Mark
	.byte	8                               @ Abbrev [8] 0x141:0xb DW_TAG_typedef
	.long	332                             @ DW_AT_type
	.long	.Linfo_string21                 @ DW_AT_name
	.byte	3                               @ DW_AT_decl_file
	.byte	75                              @ DW_AT_decl_line
	.byte	8                               @ Abbrev [8] 0x14c:0xb DW_TAG_typedef
	.long	343                             @ DW_AT_type
	.long	.Linfo_string20                 @ DW_AT_name
	.byte	2                               @ DW_AT_decl_file
	.byte	89                              @ DW_AT_decl_line
	.byte	5                               @ Abbrev [5] 0x157:0x7 DW_TAG_base_type
	.long	.Linfo_string19                 @ DW_AT_name
	.byte	7                               @ DW_AT_encoding
	.byte	8                               @ DW_AT_byte_size
	.byte	7                               @ Abbrev [7] 0x15e:0x5 DW_TAG_pointer_type
	.long	355                             @ DW_AT_type
	.byte	14                              @ Abbrev [14] 0x163:0x5 DW_TAG_const_type
	.long	76                              @ DW_AT_type
	.byte	15                              @ Abbrev [15] 0x168:0x24 DW_TAG_subprogram
	.long	.Linfo_string25                 @ DW_AT_name
	.byte	1                               @ DW_AT_decl_file
	.byte	9                               @ DW_AT_decl_line
	.byte	1                               @ DW_AT_prototyped
	.long	105                             @ DW_AT_type
	.byte	1                               @ DW_AT_inline
	.byte	10                              @ Abbrev [10] 0x175:0xb DW_TAG_formal_parameter
	.long	.Linfo_string26                 @ DW_AT_name
	.byte	1                               @ DW_AT_decl_file
	.byte	9                               @ DW_AT_decl_line
	.long	350                             @ DW_AT_type
	.byte	11                              @ Abbrev [11] 0x180:0xb DW_TAG_variable
	.long	.Linfo_string27                 @ DW_AT_name
	.byte	1                               @ DW_AT_decl_file
	.byte	11                              @ DW_AT_decl_line
	.long	105                             @ DW_AT_type
	.byte	0                               @ End Of Children Mark
	.byte	9                               @ Abbrev [9] 0x18c:0x20 DW_TAG_subprogram
	.long	.Linfo_string28                 @ DW_AT_name
	.byte	1                               @ DW_AT_decl_file
	.byte	46                              @ DW_AT_decl_line
	.byte	1                               @ DW_AT_prototyped
	.byte	1                               @ DW_AT_inline
	.byte	10                              @ Abbrev [10] 0x195:0xb DW_TAG_formal_parameter
	.long	.Linfo_string12                 @ DW_AT_name
	.byte	1                               @ DW_AT_decl_file
	.byte	46                              @ DW_AT_decl_line
	.long	188                             @ DW_AT_type
	.byte	10                              @ Abbrev [10] 0x1a0:0xb DW_TAG_formal_parameter
	.long	.Linfo_string18                 @ DW_AT_name
	.byte	1                               @ DW_AT_decl_file
	.byte	46                              @ DW_AT_decl_line
	.long	321                             @ DW_AT_type
	.byte	0                               @ End Of Children Mark
	.byte	16                              @ Abbrev [16] 0x1ac:0x211 DW_TAG_subprogram
	.long	.Lfunc_begin0                   @ DW_AT_low_pc
	.long	.Lfunc_end0                     @ DW_AT_high_pc
	.byte	1                               @ DW_AT_frame_base
	.byte	93
	.byte	32                              @ DW_AT_TI_max_frame_size
	.long	.Linfo_string35                 @ DW_AT_name
	.byte	1                               @ DW_AT_decl_file
	.byte	93                              @ DW_AT_decl_line
	.byte	1                               @ DW_AT_prototyped
	.byte	1                               @ DW_AT_external
	.byte	17                              @ Abbrev [17] 0x1c0:0xf DW_TAG_formal_parameter
	.long	.Ldebug_loc0                    @ DW_AT_location
	.long	.Linfo_string12                 @ DW_AT_name
	.byte	1                               @ DW_AT_decl_file
	.byte	93                              @ DW_AT_decl_line
	.long	188                             @ DW_AT_type
	.byte	17                              @ Abbrev [17] 0x1cf:0xf DW_TAG_formal_parameter
	.long	.Ldebug_loc1                    @ DW_AT_location
	.long	.Linfo_string16                 @ DW_AT_name
	.byte	1                               @ DW_AT_decl_file
	.byte	93                              @ DW_AT_decl_line
	.long	71                              @ DW_AT_type
	.byte	17                              @ Abbrev [17] 0x1de:0xf DW_TAG_formal_parameter
	.long	.Ldebug_loc2                    @ DW_AT_location
	.long	.Linfo_string17                 @ DW_AT_name
	.byte	1                               @ DW_AT_decl_file
	.byte	93                              @ DW_AT_decl_line
	.long	71                              @ DW_AT_type
	.byte	18                              @ Abbrev [18] 0x1ed:0xe DW_TAG_formal_parameter
	.byte	2                               @ DW_AT_location
	.byte	145
	.byte	32
	.long	.Linfo_string18                 @ DW_AT_name
	.byte	1                               @ DW_AT_decl_file
	.byte	93                              @ DW_AT_decl_line
	.long	321                             @ DW_AT_type
	.byte	19                              @ Abbrev [19] 0x1fb:0x17f DW_TAG_inlined_subroutine
	.long	134                             @ DW_AT_abstract_origin
	.long	.Ltmp5                          @ DW_AT_low_pc
	.long	.Ltmp67                         @ DW_AT_high_pc
	.byte	1                               @ DW_AT_call_file
	.byte	97                              @ DW_AT_call_line
	.byte	2                               @ DW_AT_call_column
	.byte	20                              @ Abbrev [20] 0x20b:0x7 DW_TAG_formal_parameter
	.byte	1                               @ DW_AT_location
	.byte	84
	.long	143                             @ DW_AT_abstract_origin
	.byte	20                              @ Abbrev [20] 0x212:0x7 DW_TAG_formal_parameter
	.byte	1                               @ DW_AT_location
	.byte	87
	.long	154                             @ DW_AT_abstract_origin
	.byte	20                              @ Abbrev [20] 0x219:0x7 DW_TAG_formal_parameter
	.byte	1                               @ DW_AT_location
	.byte	86
	.long	165                             @ DW_AT_abstract_origin
	.byte	19                              @ Abbrev [19] 0x220:0x21 DW_TAG_inlined_subroutine
	.long	360                             @ DW_AT_abstract_origin
	.long	.Ltmp11                         @ DW_AT_low_pc
	.long	.Ltmp15                         @ DW_AT_high_pc
	.byte	1                               @ DW_AT_call_file
	.byte	29                              @ DW_AT_call_line
	.byte	18                              @ DW_AT_call_column
	.byte	20                              @ Abbrev [20] 0x230:0x7 DW_TAG_formal_parameter
	.byte	1                               @ DW_AT_location
	.byte	87
	.long	373                             @ DW_AT_abstract_origin
	.byte	21                              @ Abbrev [21] 0x237:0x9 DW_TAG_variable
	.long	.Ldebug_loc3                    @ DW_AT_location
	.long	384                             @ DW_AT_abstract_origin
	.byte	0                               @ End Of Children Mark
	.byte	19                              @ Abbrev [19] 0x241:0x1f DW_TAG_inlined_subroutine
	.long	360                             @ DW_AT_abstract_origin
	.long	.Ltmp16                         @ DW_AT_low_pc
	.long	.Ltmp20                         @ DW_AT_high_pc
	.byte	1                               @ DW_AT_call_file
	.byte	30                              @ DW_AT_call_line
	.byte	18                              @ DW_AT_call_column
	.byte	22                              @ Abbrev [22] 0x251:0x5 DW_TAG_formal_parameter
	.long	373                             @ DW_AT_abstract_origin
	.byte	21                              @ Abbrev [21] 0x256:0x9 DW_TAG_variable
	.long	.Ldebug_loc4                    @ DW_AT_location
	.long	384                             @ DW_AT_abstract_origin
	.byte	0                               @ End Of Children Mark
	.byte	19                              @ Abbrev [19] 0x260:0x1f DW_TAG_inlined_subroutine
	.long	360                             @ DW_AT_abstract_origin
	.long	.Ltmp21                         @ DW_AT_low_pc
	.long	.Ltmp25                         @ DW_AT_high_pc
	.byte	1                               @ DW_AT_call_file
	.byte	31                              @ DW_AT_call_line
	.byte	18                              @ DW_AT_call_column
	.byte	22                              @ Abbrev [22] 0x270:0x5 DW_TAG_formal_parameter
	.long	373                             @ DW_AT_abstract_origin
	.byte	21                              @ Abbrev [21] 0x275:0x9 DW_TAG_variable
	.long	.Ldebug_loc5                    @ DW_AT_location
	.long	384                             @ DW_AT_abstract_origin
	.byte	0                               @ End Of Children Mark
	.byte	19                              @ Abbrev [19] 0x27f:0x1f DW_TAG_inlined_subroutine
	.long	360                             @ DW_AT_abstract_origin
	.long	.Ltmp26                         @ DW_AT_low_pc
	.long	.Ltmp30                         @ DW_AT_high_pc
	.byte	1                               @ DW_AT_call_file
	.byte	32                              @ DW_AT_call_line
	.byte	18                              @ DW_AT_call_column
	.byte	22                              @ Abbrev [22] 0x28f:0x5 DW_TAG_formal_parameter
	.long	373                             @ DW_AT_abstract_origin
	.byte	21                              @ Abbrev [21] 0x294:0x9 DW_TAG_variable
	.long	.Ldebug_loc6                    @ DW_AT_location
	.long	384                             @ DW_AT_abstract_origin
	.byte	0                               @ End Of Children Mark
	.byte	19                              @ Abbrev [19] 0x29e:0x1f DW_TAG_inlined_subroutine
	.long	360                             @ DW_AT_abstract_origin
	.long	.Ltmp31                         @ DW_AT_low_pc
	.long	.Ltmp35                         @ DW_AT_high_pc
	.byte	1                               @ DW_AT_call_file
	.byte	33                              @ DW_AT_call_line
	.byte	18                              @ DW_AT_call_column
	.byte	22                              @ Abbrev [22] 0x2ae:0x5 DW_TAG_formal_parameter
	.long	373                             @ DW_AT_abstract_origin
	.byte	21                              @ Abbrev [21] 0x2b3:0x9 DW_TAG_variable
	.long	.Ldebug_loc7                    @ DW_AT_location
	.long	384                             @ DW_AT_abstract_origin
	.byte	0                               @ End Of Children Mark
	.byte	19                              @ Abbrev [19] 0x2bd:0x1f DW_TAG_inlined_subroutine
	.long	360                             @ DW_AT_abstract_origin
	.long	.Ltmp36                         @ DW_AT_low_pc
	.long	.Ltmp40                         @ DW_AT_high_pc
	.byte	1                               @ DW_AT_call_file
	.byte	34                              @ DW_AT_call_line
	.byte	18                              @ DW_AT_call_column
	.byte	22                              @ Abbrev [22] 0x2cd:0x5 DW_TAG_formal_parameter
	.long	373                             @ DW_AT_abstract_origin
	.byte	21                              @ Abbrev [21] 0x2d2:0x9 DW_TAG_variable
	.long	.Ldebug_loc8                    @ DW_AT_location
	.long	384                             @ DW_AT_abstract_origin
	.byte	0                               @ End Of Children Mark
	.byte	19                              @ Abbrev [19] 0x2dc:0x1f DW_TAG_inlined_subroutine
	.long	360                             @ DW_AT_abstract_origin
	.long	.Ltmp41                         @ DW_AT_low_pc
	.long	.Ltmp45                         @ DW_AT_high_pc
	.byte	1                               @ DW_AT_call_file
	.byte	35                              @ DW_AT_call_line
	.byte	19                              @ DW_AT_call_column
	.byte	22                              @ Abbrev [22] 0x2ec:0x5 DW_TAG_formal_parameter
	.long	373                             @ DW_AT_abstract_origin
	.byte	21                              @ Abbrev [21] 0x2f1:0x9 DW_TAG_variable
	.long	.Ldebug_loc9                    @ DW_AT_location
	.long	384                             @ DW_AT_abstract_origin
	.byte	0                               @ End Of Children Mark
	.byte	19                              @ Abbrev [19] 0x2fb:0x1f DW_TAG_inlined_subroutine
	.long	360                             @ DW_AT_abstract_origin
	.long	.Ltmp46                         @ DW_AT_low_pc
	.long	.Ltmp50                         @ DW_AT_high_pc
	.byte	1                               @ DW_AT_call_file
	.byte	36                              @ DW_AT_call_line
	.byte	19                              @ DW_AT_call_column
	.byte	22                              @ Abbrev [22] 0x30b:0x5 DW_TAG_formal_parameter
	.long	373                             @ DW_AT_abstract_origin
	.byte	21                              @ Abbrev [21] 0x310:0x9 DW_TAG_variable
	.long	.Ldebug_loc10                   @ DW_AT_location
	.long	384                             @ DW_AT_abstract_origin
	.byte	0                               @ End Of Children Mark
	.byte	19                              @ Abbrev [19] 0x31a:0x21 DW_TAG_inlined_subroutine
	.long	360                             @ DW_AT_abstract_origin
	.long	.Ltmp51                         @ DW_AT_low_pc
	.long	.Ltmp55                         @ DW_AT_high_pc
	.byte	1                               @ DW_AT_call_file
	.byte	39                              @ DW_AT_call_line
	.byte	19                              @ DW_AT_call_column
	.byte	20                              @ Abbrev [20] 0x32a:0x7 DW_TAG_formal_parameter
	.byte	1                               @ DW_AT_location
	.byte	86
	.long	373                             @ DW_AT_abstract_origin
	.byte	21                              @ Abbrev [21] 0x331:0x9 DW_TAG_variable
	.long	.Ldebug_loc11                   @ DW_AT_location
	.long	384                             @ DW_AT_abstract_origin
	.byte	0                               @ End Of Children Mark
	.byte	19                              @ Abbrev [19] 0x33b:0x1f DW_TAG_inlined_subroutine
	.long	360                             @ DW_AT_abstract_origin
	.long	.Ltmp56                         @ DW_AT_low_pc
	.long	.Ltmp60                         @ DW_AT_high_pc
	.byte	1                               @ DW_AT_call_file
	.byte	40                              @ DW_AT_call_line
	.byte	19                              @ DW_AT_call_column
	.byte	22                              @ Abbrev [22] 0x34b:0x5 DW_TAG_formal_parameter
	.long	373                             @ DW_AT_abstract_origin
	.byte	21                              @ Abbrev [21] 0x350:0x9 DW_TAG_variable
	.long	.Ldebug_loc12                   @ DW_AT_location
	.long	384                             @ DW_AT_abstract_origin
	.byte	0                               @ End Of Children Mark
	.byte	19                              @ Abbrev [19] 0x35a:0x1f DW_TAG_inlined_subroutine
	.long	360                             @ DW_AT_abstract_origin
	.long	.Ltmp61                         @ DW_AT_low_pc
	.long	.Ltmp65                         @ DW_AT_high_pc
	.byte	1                               @ DW_AT_call_file
	.byte	41                              @ DW_AT_call_line
	.byte	19                              @ DW_AT_call_column
	.byte	22                              @ Abbrev [22] 0x36a:0x5 DW_TAG_formal_parameter
	.long	373                             @ DW_AT_abstract_origin
	.byte	21                              @ Abbrev [21] 0x36f:0x9 DW_TAG_variable
	.long	.Ldebug_loc13                   @ DW_AT_location
	.long	384                             @ DW_AT_abstract_origin
	.byte	0                               @ End Of Children Mark
	.byte	0                               @ End Of Children Mark
	.byte	19                              @ Abbrev [19] 0x37a:0x42 DW_TAG_inlined_subroutine
	.long	396                             @ DW_AT_abstract_origin
	.long	.Ltmp67                         @ DW_AT_low_pc
	.long	.Ltmp75                         @ DW_AT_high_pc
	.byte	1                               @ DW_AT_call_file
	.byte	98                              @ DW_AT_call_line
	.byte	2                               @ DW_AT_call_column
	.byte	20                              @ Abbrev [20] 0x38a:0x7 DW_TAG_formal_parameter
	.byte	1                               @ DW_AT_location
	.byte	84
	.long	405                             @ DW_AT_abstract_origin
	.byte	23                              @ Abbrev [23] 0x391:0x9 DW_TAG_formal_parameter
	.long	.Ldebug_loc14                   @ DW_AT_location
	.long	416                             @ DW_AT_abstract_origin
	.byte	19                              @ Abbrev [19] 0x39a:0x21 DW_TAG_inlined_subroutine
	.long	360                             @ DW_AT_abstract_origin
	.long	.Ltmp68                         @ DW_AT_low_pc
	.long	.Ltmp73                         @ DW_AT_high_pc
	.byte	1                               @ DW_AT_call_file
	.byte	49                              @ DW_AT_call_line
	.byte	19                              @ DW_AT_call_column
	.byte	20                              @ Abbrev [20] 0x3aa:0x7 DW_TAG_formal_parameter
	.byte	1                               @ DW_AT_location
	.byte	85
	.long	373                             @ DW_AT_abstract_origin
	.byte	21                              @ Abbrev [21] 0x3b1:0x9 DW_TAG_variable
	.long	.Ldebug_loc15                   @ DW_AT_location
	.long	384                             @ DW_AT_abstract_origin
	.byte	0                               @ End Of Children Mark
	.byte	0                               @ End Of Children Mark
	.byte	0                               @ End Of Children Mark
	.byte	9                               @ Abbrev [9] 0x3bd:0x47 DW_TAG_subprogram
	.long	.Linfo_string29                 @ DW_AT_name
	.byte	1                               @ DW_AT_decl_file
	.byte	52                              @ DW_AT_decl_line
	.byte	1                               @ DW_AT_prototyped
	.byte	1                               @ DW_AT_inline
	.byte	10                              @ Abbrev [10] 0x3c6:0xb DW_TAG_formal_parameter
	.long	.Linfo_string12                 @ DW_AT_name
	.byte	1                               @ DW_AT_decl_file
	.byte	52                              @ DW_AT_decl_line
	.long	188                             @ DW_AT_type
	.byte	11                              @ Abbrev [11] 0x3d1:0xb DW_TAG_variable
	.long	.Linfo_string18                 @ DW_AT_name
	.byte	1                               @ DW_AT_decl_file
	.byte	77                              @ DW_AT_decl_line
	.long	1028                            @ DW_AT_type
	.byte	24                              @ Abbrev [24] 0x3dc:0xd DW_TAG_lexical_block
	.byte	11                              @ Abbrev [11] 0x3dd:0xb DW_TAG_variable
	.long	.Linfo_string30                 @ DW_AT_name
	.byte	1                               @ DW_AT_decl_file
	.byte	55                              @ DW_AT_decl_line
	.long	1033                            @ DW_AT_type
	.byte	0                               @ End Of Children Mark
	.byte	24                              @ Abbrev [24] 0x3e9:0xd DW_TAG_lexical_block
	.byte	11                              @ Abbrev [11] 0x3ea:0xb DW_TAG_variable
	.long	.Linfo_string30                 @ DW_AT_name
	.byte	1                               @ DW_AT_decl_file
	.byte	63                              @ DW_AT_decl_line
	.long	1033                            @ DW_AT_type
	.byte	0                               @ End Of Children Mark
	.byte	24                              @ Abbrev [24] 0x3f6:0xd DW_TAG_lexical_block
	.byte	11                              @ Abbrev [11] 0x3f7:0xb DW_TAG_variable
	.long	.Linfo_string30                 @ DW_AT_name
	.byte	1                               @ DW_AT_decl_file
	.byte	75                              @ DW_AT_decl_line
	.long	1033                            @ DW_AT_type
	.byte	0                               @ End Of Children Mark
	.byte	0                               @ End Of Children Mark
	.byte	7                               @ Abbrev [7] 0x404:0x5 DW_TAG_pointer_type
	.long	105                             @ DW_AT_type
	.byte	5                               @ Abbrev [5] 0x409:0x7 DW_TAG_base_type
	.long	.Linfo_string31                 @ DW_AT_name
	.byte	5                               @ DW_AT_encoding
	.byte	4                               @ DW_AT_byte_size
	.byte	15                              @ Abbrev [15] 0x410:0x24 DW_TAG_subprogram
	.long	.Linfo_string32                 @ DW_AT_name
	.byte	1                               @ DW_AT_decl_file
	.byte	4                               @ DW_AT_decl_line
	.byte	1                               @ DW_AT_prototyped
	.long	105                             @ DW_AT_type
	.byte	1                               @ DW_AT_inline
	.byte	10                              @ Abbrev [10] 0x41d:0xb DW_TAG_formal_parameter
	.long	.Linfo_string33                 @ DW_AT_name
	.byte	1                               @ DW_AT_decl_file
	.byte	4                               @ DW_AT_decl_line
	.long	105                             @ DW_AT_type
	.byte	10                              @ Abbrev [10] 0x428:0xb DW_TAG_formal_parameter
	.long	.Linfo_string34                 @ DW_AT_name
	.byte	1                               @ DW_AT_decl_file
	.byte	4                               @ DW_AT_decl_line
	.long	1033                            @ DW_AT_type
	.byte	0                               @ End Of Children Mark
	.byte	16                              @ Abbrev [16] 0x434:0x506 DW_TAG_subprogram
	.long	.Lfunc_begin1                   @ DW_AT_low_pc
	.long	.Lfunc_end1                     @ DW_AT_high_pc
	.byte	1                               @ DW_AT_frame_base
	.byte	93
	.byte	116                             @ DW_AT_TI_max_frame_size
	.long	.Linfo_string36                 @ DW_AT_name
	.byte	1                               @ DW_AT_decl_file
	.byte	104                             @ DW_AT_decl_line
	.byte	1                               @ DW_AT_prototyped
	.byte	1                               @ DW_AT_external
	.byte	17                              @ Abbrev [17] 0x448:0xf DW_TAG_formal_parameter
	.long	.Ldebug_loc16                   @ DW_AT_location
	.long	.Linfo_string12                 @ DW_AT_name
	.byte	1                               @ DW_AT_decl_file
	.byte	104                             @ DW_AT_decl_line
	.long	188                             @ DW_AT_type
	.byte	17                              @ Abbrev [17] 0x457:0xf DW_TAG_formal_parameter
	.long	.Ldebug_loc17                   @ DW_AT_location
	.long	.Linfo_string37                 @ DW_AT_name
	.byte	1                               @ DW_AT_decl_file
	.byte	104                             @ DW_AT_decl_line
	.long	71                              @ DW_AT_type
	.byte	17                              @ Abbrev [17] 0x466:0xf DW_TAG_formal_parameter
	.long	.Ldebug_loc18                   @ DW_AT_location
	.long	.Linfo_string38                 @ DW_AT_name
	.byte	1                               @ DW_AT_decl_file
	.byte	104                             @ DW_AT_decl_line
	.long	286                             @ DW_AT_type
	.byte	25                              @ Abbrev [25] 0x475:0xf DW_TAG_variable
	.long	.Ldebug_loc20                   @ DW_AT_location
	.long	.Linfo_string39                 @ DW_AT_name
	.byte	1                               @ DW_AT_decl_file
	.byte	106                             @ DW_AT_decl_line
	.long	71                              @ DW_AT_type
	.byte	26                              @ Abbrev [26] 0x484:0x4b5 DW_TAG_lexical_block
	.long	.Ltmp77                         @ DW_AT_low_pc
	.long	.Ltmp220                        @ DW_AT_high_pc
	.byte	25                              @ Abbrev [25] 0x48d:0xf DW_TAG_variable
	.long	.Ldebug_loc19                   @ DW_AT_location
	.long	.Linfo_string30                 @ DW_AT_name
	.byte	1                               @ DW_AT_decl_file
	.byte	107                             @ DW_AT_decl_line
	.long	286                             @ DW_AT_type
	.byte	19                              @ Abbrev [19] 0x49c:0x49c DW_TAG_inlined_subroutine
	.long	957                             @ DW_AT_abstract_origin
	.long	.Ltmp89                         @ DW_AT_low_pc
	.long	.Ltmp220                        @ DW_AT_high_pc
	.byte	1                               @ DW_AT_call_file
	.byte	111                             @ DW_AT_call_line
	.byte	4                               @ DW_AT_call_column
	.byte	23                              @ Abbrev [23] 0x4ac:0x9 DW_TAG_formal_parameter
	.long	.Ldebug_loc21                   @ DW_AT_location
	.long	966                             @ DW_AT_abstract_origin
	.byte	27                              @ Abbrev [27] 0x4b5:0x5 DW_TAG_variable
	.long	977                             @ DW_AT_abstract_origin
	.byte	26                              @ Abbrev [26] 0x4ba:0x13 DW_TAG_lexical_block
	.long	.Ltmp89                         @ DW_AT_low_pc
	.long	.Ltmp95                         @ DW_AT_high_pc
	.byte	21                              @ Abbrev [21] 0x4c3:0x9 DW_TAG_variable
	.long	.Ldebug_loc22                   @ DW_AT_location
	.long	989                             @ DW_AT_abstract_origin
	.byte	0                               @ End Of Children Mark
	.byte	28                              @ Abbrev [28] 0x4cd:0x45b DW_TAG_lexical_block
	.long	.Ldebug_ranges0                 @ DW_AT_ranges
	.byte	27                              @ Abbrev [27] 0x4d2:0x5 DW_TAG_variable
	.long	1002                            @ DW_AT_abstract_origin
	.byte	19                              @ Abbrev [19] 0x4d7:0x23 DW_TAG_inlined_subroutine
	.long	1040                            @ DW_AT_abstract_origin
	.long	.Ltmp97                         @ DW_AT_low_pc
	.long	.Ltmp99                         @ DW_AT_high_pc
	.byte	1                               @ DW_AT_call_file
	.byte	65                              @ DW_AT_call_line
	.byte	3                               @ DW_AT_call_column
	.byte	23                              @ Abbrev [23] 0x4e7:0x9 DW_TAG_formal_parameter
	.long	.Ldebug_loc24                   @ DW_AT_location
	.long	1053                            @ DW_AT_abstract_origin
	.byte	23                              @ Abbrev [23] 0x4f0:0x9 DW_TAG_formal_parameter
	.long	.Ldebug_loc23                   @ DW_AT_location
	.long	1064                            @ DW_AT_abstract_origin
	.byte	0                               @ End Of Children Mark
	.byte	19                              @ Abbrev [19] 0x4fa:0x23 DW_TAG_inlined_subroutine
	.long	1040                            @ DW_AT_abstract_origin
	.long	.Ltmp100                        @ DW_AT_low_pc
	.long	.Ltmp102                        @ DW_AT_high_pc
	.byte	1                               @ DW_AT_call_file
	.byte	65                              @ DW_AT_call_line
	.byte	3                               @ DW_AT_call_column
	.byte	23                              @ Abbrev [23] 0x50a:0x9 DW_TAG_formal_parameter
	.long	.Ldebug_loc26                   @ DW_AT_location
	.long	1053                            @ DW_AT_abstract_origin
	.byte	23                              @ Abbrev [23] 0x513:0x9 DW_TAG_formal_parameter
	.long	.Ldebug_loc25                   @ DW_AT_location
	.long	1064                            @ DW_AT_abstract_origin
	.byte	0                               @ End Of Children Mark
	.byte	19                              @ Abbrev [19] 0x51d:0x23 DW_TAG_inlined_subroutine
	.long	1040                            @ DW_AT_abstract_origin
	.long	.Ltmp103                        @ DW_AT_low_pc
	.long	.Ltmp105                        @ DW_AT_high_pc
	.byte	1                               @ DW_AT_call_file
	.byte	65                              @ DW_AT_call_line
	.byte	3                               @ DW_AT_call_column
	.byte	23                              @ Abbrev [23] 0x52d:0x9 DW_TAG_formal_parameter
	.long	.Ldebug_loc28                   @ DW_AT_location
	.long	1053                            @ DW_AT_abstract_origin
	.byte	23                              @ Abbrev [23] 0x536:0x9 DW_TAG_formal_parameter
	.long	.Ldebug_loc27                   @ DW_AT_location
	.long	1064                            @ DW_AT_abstract_origin
	.byte	0                               @ End Of Children Mark
	.byte	19                              @ Abbrev [19] 0x540:0x20 DW_TAG_inlined_subroutine
	.long	1040                            @ DW_AT_abstract_origin
	.long	.Ltmp106                        @ DW_AT_low_pc
	.long	.Ltmp108                        @ DW_AT_high_pc
	.byte	1                               @ DW_AT_call_file
	.byte	65                              @ DW_AT_call_line
	.byte	3                               @ DW_AT_call_column
	.byte	23                              @ Abbrev [23] 0x550:0x9 DW_TAG_formal_parameter
	.long	.Ldebug_loc29                   @ DW_AT_location
	.long	1053                            @ DW_AT_abstract_origin
	.byte	29                              @ Abbrev [29] 0x559:0x6 DW_TAG_formal_parameter
	.byte	7                               @ DW_AT_const_value
	.long	1064                            @ DW_AT_abstract_origin
	.byte	0                               @ End Of Children Mark
	.byte	19                              @ Abbrev [19] 0x560:0x23 DW_TAG_inlined_subroutine
	.long	1040                            @ DW_AT_abstract_origin
	.long	.Ltmp109                        @ DW_AT_low_pc
	.long	.Ltmp111                        @ DW_AT_high_pc
	.byte	1                               @ DW_AT_call_file
	.byte	66                              @ DW_AT_call_line
	.byte	3                               @ DW_AT_call_column
	.byte	23                              @ Abbrev [23] 0x570:0x9 DW_TAG_formal_parameter
	.long	.Ldebug_loc31                   @ DW_AT_location
	.long	1053                            @ DW_AT_abstract_origin
	.byte	23                              @ Abbrev [23] 0x579:0x9 DW_TAG_formal_parameter
	.long	.Ldebug_loc30                   @ DW_AT_location
	.long	1064                            @ DW_AT_abstract_origin
	.byte	0                               @ End Of Children Mark
	.byte	19                              @ Abbrev [19] 0x583:0x23 DW_TAG_inlined_subroutine
	.long	1040                            @ DW_AT_abstract_origin
	.long	.Ltmp112                        @ DW_AT_low_pc
	.long	.Ltmp114                        @ DW_AT_high_pc
	.byte	1                               @ DW_AT_call_file
	.byte	66                              @ DW_AT_call_line
	.byte	3                               @ DW_AT_call_column
	.byte	23                              @ Abbrev [23] 0x593:0x9 DW_TAG_formal_parameter
	.long	.Ldebug_loc33                   @ DW_AT_location
	.long	1053                            @ DW_AT_abstract_origin
	.byte	23                              @ Abbrev [23] 0x59c:0x9 DW_TAG_formal_parameter
	.long	.Ldebug_loc32                   @ DW_AT_location
	.long	1064                            @ DW_AT_abstract_origin
	.byte	0                               @ End Of Children Mark
	.byte	19                              @ Abbrev [19] 0x5a6:0x1e DW_TAG_inlined_subroutine
	.long	1040                            @ DW_AT_abstract_origin
	.long	.Ltmp115                        @ DW_AT_low_pc
	.long	.Ltmp116                        @ DW_AT_high_pc
	.byte	1                               @ DW_AT_call_file
	.byte	66                              @ DW_AT_call_line
	.byte	3                               @ DW_AT_call_column
	.byte	20                              @ Abbrev [20] 0x5b6:0x7 DW_TAG_formal_parameter
	.byte	1                               @ DW_AT_location
	.byte	81
	.long	1053                            @ DW_AT_abstract_origin
	.byte	29                              @ Abbrev [29] 0x5bd:0x6 DW_TAG_formal_parameter
	.byte	8                               @ DW_AT_const_value
	.long	1064                            @ DW_AT_abstract_origin
	.byte	0                               @ End Of Children Mark
	.byte	19                              @ Abbrev [19] 0x5c4:0x20 DW_TAG_inlined_subroutine
	.long	1040                            @ DW_AT_abstract_origin
	.long	.Ltmp117                        @ DW_AT_low_pc
	.long	.Ltmp119                        @ DW_AT_high_pc
	.byte	1                               @ DW_AT_call_file
	.byte	66                              @ DW_AT_call_line
	.byte	3                               @ DW_AT_call_column
	.byte	23                              @ Abbrev [23] 0x5d4:0x9 DW_TAG_formal_parameter
	.long	.Ldebug_loc34                   @ DW_AT_location
	.long	1053                            @ DW_AT_abstract_origin
	.byte	29                              @ Abbrev [29] 0x5dd:0x6 DW_TAG_formal_parameter
	.byte	7                               @ DW_AT_const_value
	.long	1064                            @ DW_AT_abstract_origin
	.byte	0                               @ End Of Children Mark
	.byte	19                              @ Abbrev [19] 0x5e4:0x23 DW_TAG_inlined_subroutine
	.long	1040                            @ DW_AT_abstract_origin
	.long	.Ltmp120                        @ DW_AT_low_pc
	.long	.Ltmp122                        @ DW_AT_high_pc
	.byte	1                               @ DW_AT_call_file
	.byte	67                              @ DW_AT_call_line
	.byte	3                               @ DW_AT_call_column
	.byte	23                              @ Abbrev [23] 0x5f4:0x9 DW_TAG_formal_parameter
	.long	.Ldebug_loc36                   @ DW_AT_location
	.long	1053                            @ DW_AT_abstract_origin
	.byte	23                              @ Abbrev [23] 0x5fd:0x9 DW_TAG_formal_parameter
	.long	.Ldebug_loc35                   @ DW_AT_location
	.long	1064                            @ DW_AT_abstract_origin
	.byte	0                               @ End Of Children Mark
	.byte	19                              @ Abbrev [19] 0x607:0x23 DW_TAG_inlined_subroutine
	.long	1040                            @ DW_AT_abstract_origin
	.long	.Ltmp123                        @ DW_AT_low_pc
	.long	.Ltmp125                        @ DW_AT_high_pc
	.byte	1                               @ DW_AT_call_file
	.byte	67                              @ DW_AT_call_line
	.byte	3                               @ DW_AT_call_column
	.byte	23                              @ Abbrev [23] 0x617:0x9 DW_TAG_formal_parameter
	.long	.Ldebug_loc38                   @ DW_AT_location
	.long	1053                            @ DW_AT_abstract_origin
	.byte	23                              @ Abbrev [23] 0x620:0x9 DW_TAG_formal_parameter
	.long	.Ldebug_loc37                   @ DW_AT_location
	.long	1064                            @ DW_AT_abstract_origin
	.byte	0                               @ End Of Children Mark
	.byte	19                              @ Abbrev [19] 0x62a:0x1e DW_TAG_inlined_subroutine
	.long	1040                            @ DW_AT_abstract_origin
	.long	.Ltmp126                        @ DW_AT_low_pc
	.long	.Ltmp127                        @ DW_AT_high_pc
	.byte	1                               @ DW_AT_call_file
	.byte	67                              @ DW_AT_call_line
	.byte	3                               @ DW_AT_call_column
	.byte	20                              @ Abbrev [20] 0x63a:0x7 DW_TAG_formal_parameter
	.byte	1                               @ DW_AT_location
	.byte	86
	.long	1053                            @ DW_AT_abstract_origin
	.byte	29                              @ Abbrev [29] 0x641:0x6 DW_TAG_formal_parameter
	.byte	8                               @ DW_AT_const_value
	.long	1064                            @ DW_AT_abstract_origin
	.byte	0                               @ End Of Children Mark
	.byte	19                              @ Abbrev [19] 0x648:0x23 DW_TAG_inlined_subroutine
	.long	1040                            @ DW_AT_abstract_origin
	.long	.Ltmp128                        @ DW_AT_low_pc
	.long	.Ltmp131                        @ DW_AT_high_pc
	.byte	1                               @ DW_AT_call_file
	.byte	67                              @ DW_AT_call_line
	.byte	3                               @ DW_AT_call_column
	.byte	23                              @ Abbrev [23] 0x658:0x9 DW_TAG_formal_parameter
	.long	.Ldebug_loc40                   @ DW_AT_location
	.long	1053                            @ DW_AT_abstract_origin
	.byte	23                              @ Abbrev [23] 0x661:0x9 DW_TAG_formal_parameter
	.long	.Ldebug_loc39                   @ DW_AT_location
	.long	1064                            @ DW_AT_abstract_origin
	.byte	0                               @ End Of Children Mark
	.byte	19                              @ Abbrev [19] 0x66b:0x23 DW_TAG_inlined_subroutine
	.long	1040                            @ DW_AT_abstract_origin
	.long	.Ltmp132                        @ DW_AT_low_pc
	.long	.Ltmp134                        @ DW_AT_high_pc
	.byte	1                               @ DW_AT_call_file
	.byte	68                              @ DW_AT_call_line
	.byte	3                               @ DW_AT_call_column
	.byte	23                              @ Abbrev [23] 0x67b:0x9 DW_TAG_formal_parameter
	.long	.Ldebug_loc42                   @ DW_AT_location
	.long	1053                            @ DW_AT_abstract_origin
	.byte	23                              @ Abbrev [23] 0x684:0x9 DW_TAG_formal_parameter
	.long	.Ldebug_loc41                   @ DW_AT_location
	.long	1064                            @ DW_AT_abstract_origin
	.byte	0                               @ End Of Children Mark
	.byte	19                              @ Abbrev [19] 0x68e:0x23 DW_TAG_inlined_subroutine
	.long	1040                            @ DW_AT_abstract_origin
	.long	.Ltmp135                        @ DW_AT_low_pc
	.long	.Ltmp137                        @ DW_AT_high_pc
	.byte	1                               @ DW_AT_call_file
	.byte	68                              @ DW_AT_call_line
	.byte	3                               @ DW_AT_call_column
	.byte	23                              @ Abbrev [23] 0x69e:0x9 DW_TAG_formal_parameter
	.long	.Ldebug_loc44                   @ DW_AT_location
	.long	1053                            @ DW_AT_abstract_origin
	.byte	23                              @ Abbrev [23] 0x6a7:0x9 DW_TAG_formal_parameter
	.long	.Ldebug_loc43                   @ DW_AT_location
	.long	1064                            @ DW_AT_abstract_origin
	.byte	0                               @ End Of Children Mark
	.byte	19                              @ Abbrev [19] 0x6b1:0x23 DW_TAG_inlined_subroutine
	.long	1040                            @ DW_AT_abstract_origin
	.long	.Ltmp138                        @ DW_AT_low_pc
	.long	.Ltmp140                        @ DW_AT_high_pc
	.byte	1                               @ DW_AT_call_file
	.byte	68                              @ DW_AT_call_line
	.byte	3                               @ DW_AT_call_column
	.byte	23                              @ Abbrev [23] 0x6c1:0x9 DW_TAG_formal_parameter
	.long	.Ldebug_loc46                   @ DW_AT_location
	.long	1053                            @ DW_AT_abstract_origin
	.byte	23                              @ Abbrev [23] 0x6ca:0x9 DW_TAG_formal_parameter
	.long	.Ldebug_loc45                   @ DW_AT_location
	.long	1064                            @ DW_AT_abstract_origin
	.byte	0                               @ End Of Children Mark
	.byte	19                              @ Abbrev [19] 0x6d4:0x23 DW_TAG_inlined_subroutine
	.long	1040                            @ DW_AT_abstract_origin
	.long	.Ltmp141                        @ DW_AT_low_pc
	.long	.Ltmp143                        @ DW_AT_high_pc
	.byte	1                               @ DW_AT_call_file
	.byte	68                              @ DW_AT_call_line
	.byte	3                               @ DW_AT_call_column
	.byte	23                              @ Abbrev [23] 0x6e4:0x9 DW_TAG_formal_parameter
	.long	.Ldebug_loc48                   @ DW_AT_location
	.long	1053                            @ DW_AT_abstract_origin
	.byte	23                              @ Abbrev [23] 0x6ed:0x9 DW_TAG_formal_parameter
	.long	.Ldebug_loc47                   @ DW_AT_location
	.long	1064                            @ DW_AT_abstract_origin
	.byte	0                               @ End Of Children Mark
	.byte	19                              @ Abbrev [19] 0x6f7:0x23 DW_TAG_inlined_subroutine
	.long	1040                            @ DW_AT_abstract_origin
	.long	.Ltmp144                        @ DW_AT_low_pc
	.long	.Ltmp146                        @ DW_AT_high_pc
	.byte	1                               @ DW_AT_call_file
	.byte	69                              @ DW_AT_call_line
	.byte	3                               @ DW_AT_call_column
	.byte	23                              @ Abbrev [23] 0x707:0x9 DW_TAG_formal_parameter
	.long	.Ldebug_loc50                   @ DW_AT_location
	.long	1053                            @ DW_AT_abstract_origin
	.byte	23                              @ Abbrev [23] 0x710:0x9 DW_TAG_formal_parameter
	.long	.Ldebug_loc49                   @ DW_AT_location
	.long	1064                            @ DW_AT_abstract_origin
	.byte	0                               @ End Of Children Mark
	.byte	19                              @ Abbrev [19] 0x71a:0x23 DW_TAG_inlined_subroutine
	.long	1040                            @ DW_AT_abstract_origin
	.long	.Ltmp147                        @ DW_AT_low_pc
	.long	.Ltmp149                        @ DW_AT_high_pc
	.byte	1                               @ DW_AT_call_file
	.byte	69                              @ DW_AT_call_line
	.byte	3                               @ DW_AT_call_column
	.byte	23                              @ Abbrev [23] 0x72a:0x9 DW_TAG_formal_parameter
	.long	.Ldebug_loc52                   @ DW_AT_location
	.long	1053                            @ DW_AT_abstract_origin
	.byte	23                              @ Abbrev [23] 0x733:0x9 DW_TAG_formal_parameter
	.long	.Ldebug_loc51                   @ DW_AT_location
	.long	1064                            @ DW_AT_abstract_origin
	.byte	0                               @ End Of Children Mark
	.byte	19                              @ Abbrev [19] 0x73d:0x23 DW_TAG_inlined_subroutine
	.long	1040                            @ DW_AT_abstract_origin
	.long	.Ltmp150                        @ DW_AT_low_pc
	.long	.Ltmp152                        @ DW_AT_high_pc
	.byte	1                               @ DW_AT_call_file
	.byte	69                              @ DW_AT_call_line
	.byte	3                               @ DW_AT_call_column
	.byte	23                              @ Abbrev [23] 0x74d:0x9 DW_TAG_formal_parameter
	.long	.Ldebug_loc54                   @ DW_AT_location
	.long	1053                            @ DW_AT_abstract_origin
	.byte	23                              @ Abbrev [23] 0x756:0x9 DW_TAG_formal_parameter
	.long	.Ldebug_loc53                   @ DW_AT_location
	.long	1064                            @ DW_AT_abstract_origin
	.byte	0                               @ End Of Children Mark
	.byte	19                              @ Abbrev [19] 0x760:0x23 DW_TAG_inlined_subroutine
	.long	1040                            @ DW_AT_abstract_origin
	.long	.Ltmp153                        @ DW_AT_low_pc
	.long	.Ltmp156                        @ DW_AT_high_pc
	.byte	1                               @ DW_AT_call_file
	.byte	69                              @ DW_AT_call_line
	.byte	3                               @ DW_AT_call_column
	.byte	23                              @ Abbrev [23] 0x770:0x9 DW_TAG_formal_parameter
	.long	.Ldebug_loc56                   @ DW_AT_location
	.long	1053                            @ DW_AT_abstract_origin
	.byte	23                              @ Abbrev [23] 0x779:0x9 DW_TAG_formal_parameter
	.long	.Ldebug_loc55                   @ DW_AT_location
	.long	1064                            @ DW_AT_abstract_origin
	.byte	0                               @ End Of Children Mark
	.byte	19                              @ Abbrev [19] 0x783:0x23 DW_TAG_inlined_subroutine
	.long	1040                            @ DW_AT_abstract_origin
	.long	.Ltmp157                        @ DW_AT_low_pc
	.long	.Ltmp159                        @ DW_AT_high_pc
	.byte	1                               @ DW_AT_call_file
	.byte	70                              @ DW_AT_call_line
	.byte	3                               @ DW_AT_call_column
	.byte	23                              @ Abbrev [23] 0x793:0x9 DW_TAG_formal_parameter
	.long	.Ldebug_loc58                   @ DW_AT_location
	.long	1053                            @ DW_AT_abstract_origin
	.byte	23                              @ Abbrev [23] 0x79c:0x9 DW_TAG_formal_parameter
	.long	.Ldebug_loc57                   @ DW_AT_location
	.long	1064                            @ DW_AT_abstract_origin
	.byte	0                               @ End Of Children Mark
	.byte	19                              @ Abbrev [19] 0x7a6:0x23 DW_TAG_inlined_subroutine
	.long	1040                            @ DW_AT_abstract_origin
	.long	.Ltmp160                        @ DW_AT_low_pc
	.long	.Ltmp162                        @ DW_AT_high_pc
	.byte	1                               @ DW_AT_call_file
	.byte	70                              @ DW_AT_call_line
	.byte	3                               @ DW_AT_call_column
	.byte	23                              @ Abbrev [23] 0x7b6:0x9 DW_TAG_formal_parameter
	.long	.Ldebug_loc60                   @ DW_AT_location
	.long	1053                            @ DW_AT_abstract_origin
	.byte	23                              @ Abbrev [23] 0x7bf:0x9 DW_TAG_formal_parameter
	.long	.Ldebug_loc59                   @ DW_AT_location
	.long	1064                            @ DW_AT_abstract_origin
	.byte	0                               @ End Of Children Mark
	.byte	19                              @ Abbrev [19] 0x7c9:0x23 DW_TAG_inlined_subroutine
	.long	1040                            @ DW_AT_abstract_origin
	.long	.Ltmp163                        @ DW_AT_low_pc
	.long	.Ltmp165                        @ DW_AT_high_pc
	.byte	1                               @ DW_AT_call_file
	.byte	70                              @ DW_AT_call_line
	.byte	3                               @ DW_AT_call_column
	.byte	23                              @ Abbrev [23] 0x7d9:0x9 DW_TAG_formal_parameter
	.long	.Ldebug_loc62                   @ DW_AT_location
	.long	1053                            @ DW_AT_abstract_origin
	.byte	23                              @ Abbrev [23] 0x7e2:0x9 DW_TAG_formal_parameter
	.long	.Ldebug_loc61                   @ DW_AT_location
	.long	1064                            @ DW_AT_abstract_origin
	.byte	0                               @ End Of Children Mark
	.byte	19                              @ Abbrev [19] 0x7ec:0x23 DW_TAG_inlined_subroutine
	.long	1040                            @ DW_AT_abstract_origin
	.long	.Ltmp166                        @ DW_AT_low_pc
	.long	.Ltmp169                        @ DW_AT_high_pc
	.byte	1                               @ DW_AT_call_file
	.byte	70                              @ DW_AT_call_line
	.byte	3                               @ DW_AT_call_column
	.byte	23                              @ Abbrev [23] 0x7fc:0x9 DW_TAG_formal_parameter
	.long	.Ldebug_loc64                   @ DW_AT_location
	.long	1053                            @ DW_AT_abstract_origin
	.byte	23                              @ Abbrev [23] 0x805:0x9 DW_TAG_formal_parameter
	.long	.Ldebug_loc63                   @ DW_AT_location
	.long	1064                            @ DW_AT_abstract_origin
	.byte	0                               @ End Of Children Mark
	.byte	19                              @ Abbrev [19] 0x80f:0x23 DW_TAG_inlined_subroutine
	.long	1040                            @ DW_AT_abstract_origin
	.long	.Ltmp170                        @ DW_AT_low_pc
	.long	.Ltmp172                        @ DW_AT_high_pc
	.byte	1                               @ DW_AT_call_file
	.byte	71                              @ DW_AT_call_line
	.byte	3                               @ DW_AT_call_column
	.byte	23                              @ Abbrev [23] 0x81f:0x9 DW_TAG_formal_parameter
	.long	.Ldebug_loc66                   @ DW_AT_location
	.long	1053                            @ DW_AT_abstract_origin
	.byte	23                              @ Abbrev [23] 0x828:0x9 DW_TAG_formal_parameter
	.long	.Ldebug_loc65                   @ DW_AT_location
	.long	1064                            @ DW_AT_abstract_origin
	.byte	0                               @ End Of Children Mark
	.byte	19                              @ Abbrev [19] 0x832:0x23 DW_TAG_inlined_subroutine
	.long	1040                            @ DW_AT_abstract_origin
	.long	.Ltmp173                        @ DW_AT_low_pc
	.long	.Ltmp175                        @ DW_AT_high_pc
	.byte	1                               @ DW_AT_call_file
	.byte	71                              @ DW_AT_call_line
	.byte	3                               @ DW_AT_call_column
	.byte	23                              @ Abbrev [23] 0x842:0x9 DW_TAG_formal_parameter
	.long	.Ldebug_loc68                   @ DW_AT_location
	.long	1053                            @ DW_AT_abstract_origin
	.byte	23                              @ Abbrev [23] 0x84b:0x9 DW_TAG_formal_parameter
	.long	.Ldebug_loc67                   @ DW_AT_location
	.long	1064                            @ DW_AT_abstract_origin
	.byte	0                               @ End Of Children Mark
	.byte	19                              @ Abbrev [19] 0x855:0x23 DW_TAG_inlined_subroutine
	.long	1040                            @ DW_AT_abstract_origin
	.long	.Ltmp176                        @ DW_AT_low_pc
	.long	.Ltmp178                        @ DW_AT_high_pc
	.byte	1                               @ DW_AT_call_file
	.byte	71                              @ DW_AT_call_line
	.byte	3                               @ DW_AT_call_column
	.byte	23                              @ Abbrev [23] 0x865:0x9 DW_TAG_formal_parameter
	.long	.Ldebug_loc70                   @ DW_AT_location
	.long	1053                            @ DW_AT_abstract_origin
	.byte	23                              @ Abbrev [23] 0x86e:0x9 DW_TAG_formal_parameter
	.long	.Ldebug_loc69                   @ DW_AT_location
	.long	1064                            @ DW_AT_abstract_origin
	.byte	0                               @ End Of Children Mark
	.byte	19                              @ Abbrev [19] 0x878:0x23 DW_TAG_inlined_subroutine
	.long	1040                            @ DW_AT_abstract_origin
	.long	.Ltmp179                        @ DW_AT_low_pc
	.long	.Ltmp182                        @ DW_AT_high_pc
	.byte	1                               @ DW_AT_call_file
	.byte	71                              @ DW_AT_call_line
	.byte	3                               @ DW_AT_call_column
	.byte	23                              @ Abbrev [23] 0x888:0x9 DW_TAG_formal_parameter
	.long	.Ldebug_loc72                   @ DW_AT_location
	.long	1053                            @ DW_AT_abstract_origin
	.byte	23                              @ Abbrev [23] 0x891:0x9 DW_TAG_formal_parameter
	.long	.Ldebug_loc71                   @ DW_AT_location
	.long	1064                            @ DW_AT_abstract_origin
	.byte	0                               @ End Of Children Mark
	.byte	19                              @ Abbrev [19] 0x89b:0x23 DW_TAG_inlined_subroutine
	.long	1040                            @ DW_AT_abstract_origin
	.long	.Ltmp183                        @ DW_AT_low_pc
	.long	.Ltmp185                        @ DW_AT_high_pc
	.byte	1                               @ DW_AT_call_file
	.byte	72                              @ DW_AT_call_line
	.byte	3                               @ DW_AT_call_column
	.byte	23                              @ Abbrev [23] 0x8ab:0x9 DW_TAG_formal_parameter
	.long	.Ldebug_loc74                   @ DW_AT_location
	.long	1053                            @ DW_AT_abstract_origin
	.byte	23                              @ Abbrev [23] 0x8b4:0x9 DW_TAG_formal_parameter
	.long	.Ldebug_loc73                   @ DW_AT_location
	.long	1064                            @ DW_AT_abstract_origin
	.byte	0                               @ End Of Children Mark
	.byte	19                              @ Abbrev [19] 0x8be:0x23 DW_TAG_inlined_subroutine
	.long	1040                            @ DW_AT_abstract_origin
	.long	.Ltmp186                        @ DW_AT_low_pc
	.long	.Ltmp188                        @ DW_AT_high_pc
	.byte	1                               @ DW_AT_call_file
	.byte	72                              @ DW_AT_call_line
	.byte	3                               @ DW_AT_call_column
	.byte	23                              @ Abbrev [23] 0x8ce:0x9 DW_TAG_formal_parameter
	.long	.Ldebug_loc76                   @ DW_AT_location
	.long	1053                            @ DW_AT_abstract_origin
	.byte	23                              @ Abbrev [23] 0x8d7:0x9 DW_TAG_formal_parameter
	.long	.Ldebug_loc75                   @ DW_AT_location
	.long	1064                            @ DW_AT_abstract_origin
	.byte	0                               @ End Of Children Mark
	.byte	19                              @ Abbrev [19] 0x8e1:0x23 DW_TAG_inlined_subroutine
	.long	1040                            @ DW_AT_abstract_origin
	.long	.Ltmp189                        @ DW_AT_low_pc
	.long	.Ltmp191                        @ DW_AT_high_pc
	.byte	1                               @ DW_AT_call_file
	.byte	72                              @ DW_AT_call_line
	.byte	3                               @ DW_AT_call_column
	.byte	23                              @ Abbrev [23] 0x8f1:0x9 DW_TAG_formal_parameter
	.long	.Ldebug_loc78                   @ DW_AT_location
	.long	1053                            @ DW_AT_abstract_origin
	.byte	23                              @ Abbrev [23] 0x8fa:0x9 DW_TAG_formal_parameter
	.long	.Ldebug_loc77                   @ DW_AT_location
	.long	1064                            @ DW_AT_abstract_origin
	.byte	0                               @ End Of Children Mark
	.byte	19                              @ Abbrev [19] 0x904:0x23 DW_TAG_inlined_subroutine
	.long	1040                            @ DW_AT_abstract_origin
	.long	.Ltmp192                        @ DW_AT_low_pc
	.long	.Ltmp194                        @ DW_AT_high_pc
	.byte	1                               @ DW_AT_call_file
	.byte	72                              @ DW_AT_call_line
	.byte	3                               @ DW_AT_call_column
	.byte	23                              @ Abbrev [23] 0x914:0x9 DW_TAG_formal_parameter
	.long	.Ldebug_loc80                   @ DW_AT_location
	.long	1053                            @ DW_AT_abstract_origin
	.byte	23                              @ Abbrev [23] 0x91d:0x9 DW_TAG_formal_parameter
	.long	.Ldebug_loc79                   @ DW_AT_location
	.long	1064                            @ DW_AT_abstract_origin
	.byte	0                               @ End Of Children Mark
	.byte	0                               @ End Of Children Mark
	.byte	28                              @ Abbrev [28] 0x928:0xf DW_TAG_lexical_block
	.long	.Ldebug_ranges1                 @ DW_AT_ranges
	.byte	21                              @ Abbrev [21] 0x92d:0x9 DW_TAG_variable
	.long	.Ldebug_loc81                   @ DW_AT_location
	.long	1015                            @ DW_AT_abstract_origin
	.byte	0                               @ End Of Children Mark
	.byte	0                               @ End Of Children Mark
	.byte	0                               @ End Of Children Mark
	.byte	0                               @ End Of Children Mark
	.byte	0                               @ End Of Children Mark
.Ldebug_info_end0:
	.section	.debug_ranges,"",%progbits
.Ldebug_ranges0:
	.long	.Ltmp95
	.long	.Ltmp199
	.long	.Ltmp201
	.long	.Ltmp202
	.long	0
	.long	0
.Ldebug_ranges1:
	.long	.Ltmp199
	.long	.Ltmp201
	.long	.Ltmp202
	.long	.Ltmp217
	.long	0
	.long	0
.Ldebug_ranges2:
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
	.asciz	"chacha20/chacha20.c"           @ string offset=120
.Linfo_string2:
	.asciz	"/home/main/Documents/school/Fault-Injection-Finder/targets/timspm0l2228/source" @ string offset=140
.Linfo_string3:
	.asciz	"char"                          @ string offset=219
.Linfo_string4:
	.asciz	"__ARRAY_SIZE_TYPE__"           @ string offset=224
.Linfo_string5:
	.asciz	"unsigned char"                 @ string offset=244
.Linfo_string6:
	.asciz	"__uint8_t"                     @ string offset=258
.Linfo_string7:
	.asciz	"uint8_t"                       @ string offset=268
.Linfo_string8:
	.asciz	"unsigned int"                  @ string offset=276
.Linfo_string9:
	.asciz	"__uint32_t"                    @ string offset=289
.Linfo_string10:
	.asciz	"uint32_t"                      @ string offset=300
.Linfo_string11:
	.asciz	"chacha20_init_block"           @ string offset=309
.Linfo_string12:
	.asciz	"ctx"                           @ string offset=329
.Linfo_string13:
	.asciz	"keystream32"                   @ string offset=333
.Linfo_string14:
	.asciz	"position"                      @ string offset=345
.Linfo_string15:
	.asciz	"size_t"                        @ string offset=354
.Linfo_string16:
	.asciz	"key"                           @ string offset=361
.Linfo_string17:
	.asciz	"nonce"                         @ string offset=365
.Linfo_string18:
	.asciz	"counter"                       @ string offset=371
.Linfo_string19:
	.asciz	"unsigned long long"            @ string offset=379
.Linfo_string20:
	.asciz	"__uint64_t"                    @ string offset=398
.Linfo_string21:
	.asciz	"uint64_t"                      @ string offset=409
.Linfo_string22:
	.asciz	"state"                         @ string offset=418
.Linfo_string23:
	.asciz	"chacha20_context"              @ string offset=424
.Linfo_string24:
	.asciz	"magic_constant"                @ string offset=441
.Linfo_string25:
	.asciz	"pack4"                         @ string offset=456
.Linfo_string26:
	.asciz	"a"                             @ string offset=462
.Linfo_string27:
	.asciz	"res"                           @ string offset=464
.Linfo_string28:
	.asciz	"chacha20_block_set_counter"    @ string offset=468
.Linfo_string29:
	.asciz	"chacha20_block_next"           @ string offset=495
.Linfo_string30:
	.asciz	"i"                             @ string offset=515
.Linfo_string31:
	.asciz	"int"                           @ string offset=517
.Linfo_string32:
	.asciz	"rotl32"                        @ string offset=521
.Linfo_string33:
	.asciz	"x"                             @ string offset=528
.Linfo_string34:
	.asciz	"n"                             @ string offset=530
.Linfo_string35:
	.asciz	"chacha20_init_context"         @ string offset=532
.Linfo_string36:
	.asciz	"chacha20_xor"                  @ string offset=554
.Linfo_string37:
	.asciz	"bytes"                         @ string offset=567
.Linfo_string38:
	.asciz	"n_bytes"                       @ string offset=573
.Linfo_string39:
	.asciz	"keystream8"                    @ string offset=581
	.ident	"TI clang version 18.1.8 (ssh://git@bitbucket.itg.ti.com/code/llvm-project.git 41ce286cff6db007d382d297353d8bf884b450b7)"
	.section	".note.GNU-stack","",%progbits
	.eabi_attribute	30, 1	@ Tag_ABI_optimization_goals
	.section	.debug_line,"",%progbits
.Lline_table_start0:
