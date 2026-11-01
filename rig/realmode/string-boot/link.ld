OUTPUT_FORMAT("elf32-i386")
OUTPUT_ARCH(i386)
ENTRY(_start)
SECTIONS {
	. = 0;
	.head : { *(.head) }
	.text : { *(.text .text.*) }
	.rodata : { *(.rodata*) }
	.data : { *(.data*) }
	. = ALIGN(4);
	__bss_start = .;
	.bss : { *(.bss*) *(COMMON) }
	. = ALIGN(16);
	_end = .;
	/DISCARD/ : { *(.note*) *(.comment) *(.eh_frame) }
}
