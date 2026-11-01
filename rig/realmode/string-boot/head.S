/* Entry of the test image (cs = ds = es = ss = 0x1000, linked at 0 like the real-mode setup): clear .bss, call main(), exit via isa-debug-exit. */
	.code16
	.section .head, "ax"
	.globl _start
_start:	cli
	movw %cs, %ax
	movw %ax, %ds
	movw %ax, %es
	movw %ax, %ss
	movl $0xfff0, %esp
	cld
	movl $__bss_start, %edi
	movl $_end, %ecx
	subl %edi, %ecx
	xorl %eax, %eax
	rep stosb
	calll main
	movw $0xf4, %dx
	outb %al, %dx
2:	hlt
	jmp 2b
