/* Boot sector: loads NSECT sectors (LBA 1..) of the test image to 0x1000:0000 (int 13h extension read) and jumps there. */
	.code16
	.text
	.globl _s
_s:	cli
	xorw %ax, %ax
	movw %ax, %ds
	movw %ax, %es
	movw %ax, %ss
	movw $0x7c00, %sp
	sti
	movw $dap, %si
	movb $0x42, %ah
	int $0x13
	jc 1f
	.byte 0xea
	.word 0, 0x1000
1:	movw $0xf4, %dx
	movb $0x7e, %al
	outb %al, %dx
	hlt
dap:	.byte 0x10, 0
	.word NSECT
	.word 0, 0x1000
	.quad 1
	. = 510
	.word 0xaa55
