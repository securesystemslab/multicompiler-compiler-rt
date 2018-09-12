#if defined(__linux__) && defined(__ELF__)
.section .note.GNU-stack,"",%progbits
#endif

	.text
        .globl drrt_call_snprintf_with

# extern "C"
# int drrt_call_snprintf_with(const void *stack_arguments, size_t stack_size)

drrt_call_snprintf_with:
        # Setup stack frame.
        push %ebp
        mov %esp, %ebp

        # Create 16 byte alignment on stack.
        sub $8, %esp

        # Create space for stack arguments.
        sub 12(%ebp), %esp

        # Prepare arguments for memcpy.
        mov %esp, %ecx
        sub $4, %esp
        push 12(%ebp)
        push 8(%ebp)
        push %ecx

        # memcpy arguments to the stack.
        call memcpy@PLT

        # Cleanup from memcpy call.
        add $16, %esp

        call snprintf@PLT

        leave
        ret
