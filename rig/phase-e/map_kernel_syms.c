/* Real symbols for the Rust __startup_64() wrapper (rip_rel_ptr() -> `lea sym(%rip)`) in the userspace test:
 * what head_64.S / the linker script provide in the kernel. */
char _text[4096], _end[4096];
unsigned char boot_cpu_data[512];
#ifdef AMD_SYMS
char bss_dec[8 << 20];
__asm__(".globl __start_bss_decrypted\n.set __start_bss_decrypted, bss_dec\n"
	".globl __end_bss_decrypted\n.set __end_bss_decrypted, bss_dec + 6291456\n");
#endif
