#if defined(__linux__) && defined(__ELF__)
.section .note.GNU-stack,"",%progbits
#endif

	.text
        .globl drrt_call_snprintf_with

        ## extern "C"
        ## int drrt_call_snprintf_with(void *buffer, size_t size, const void *fmt,
        ##                             const void *int_registers, const void *stack_arguments, size_t size_stack_arguments,
	##                             void *SSE_arguments);

drrt_call_snprintf_with:
        ## setup stack frame
        pushq %rbp
        movq %rsp, %rbp
        
	## save other arguments for later
        pushq %rdi
        pushq %rsi
        pushq %rdx
        pushq %rcx

        ## reserve space for stack arguments
        subq %r9, %rsp

        ## set up arguments to memcpy
        movq %rsp, %rdi
        movq %r8, %rsi
        movq %r9, %rdx

        ## memcpy stack arguments to stack
        call memcpy@PLT

        ## move SSE arguments into SSE registers
        movq 16(%rbp), %rdi
        movsd (%rdi), %xmm0
        movsd 8(%rdi), %xmm1
        movsd 16(%rdi), %xmm2
        movsd 24(%rdi), %xmm3
        movsd 32(%rdi), %xmm4
        movsd 40(%rdi), %xmm5
        movsd 48(%rdi), %xmm6
        movsd 56(%rdi), %xmm7
        mov $8, %al

        ## move int arguments into int registers
	movq -8(%rbp), %rdi
        movq -16(%rbp), %rsi
        movq -24(%rbp), %rdx
        movq -32(%rbp), %r9
        movq (%r9), %rcx
        movq 8(%r9), %r8
        movq 16(%r9), %r9

        call snprintf@PLT
        
	leave
	ret
