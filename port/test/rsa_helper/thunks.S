/* the two symbols the kernel build's retpoline / return-thunk flags leave undefined in a Rust object: plain jump / return here
 * (this is the userspace link of the REAL kernel object, run.sh --object) */
	.text
	.globl __x86_indirect_thunk_r11
__x86_indirect_thunk_r11:
	jmp *%r11
	.globl __x86_return_thunk
__x86_return_thunk:
	ret
	.section .note.GNU-stack,"",@progbits
