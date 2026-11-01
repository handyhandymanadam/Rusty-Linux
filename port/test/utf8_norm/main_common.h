/* shared with utf8_core/main.c: the random generator and the code point repertoire */
static unsigned long long rs_;
static unsigned long long rnd64(void) { rs_ = rs_ * 6364136223846793005ULL + 1442695040888963407ULL; return (rs_ >> 11) ^ (rs_ << 53); }
static unsigned rnd(unsigned n) { return n ? (unsigned)(rnd64() % n) : 0; }
static size_t enc(unsigned char *p, unsigned cp)
{
	if (cp < 0x80) { p[0] = cp; return 1; }
	if (cp < 0x800) { p[0] = 0xC0 | cp >> 6; p[1] = 0x80 | (cp & 63); return 2; }
	if (cp < 0x10000) { p[0] = 0xE0 | cp >> 12; p[1] = 0x80 | (cp >> 6 & 63); p[2] = 0x80 | (cp & 63); return 3; }
	p[0] = 0xF0 | cp >> 18; p[1] = 0x80 | (cp >> 12 & 63); p[2] = 0x80 | (cp >> 6 & 63); p[3] = 0x80 | (cp & 63); return 4;
}
static unsigned pickcp(void)
{
	static const unsigned lst[] = { 0x41, 0x61, 0x7a, 0xc0, 0xc5, 0xe9, 0xdf, 0x130, 0x1e9e, 0x300, 0x301, 0x302, 0x308, 0x323, 0x327, 0x334, 0x345, 0x344, 0x34f, 0x5b0, 0x5b4, 0x64b, 0x93c, 0xe38, 0xf71,
		0x1100, 0x1161, 0x11a8, 0x1e0a, 0x1e63, 0x1f80, 0x1fbc, 0x2126, 0x212b, 0x2160, 0x3042, 0x3099, 0x309a, 0xf900, 0xfa10, 0xfb01, 0xfb1d, 0xfe20, 0xff21, 0x10400, 0x1d15e, 0x1d1bb, 0x1f600, 0x2f800, 0x13a0, 0xab70, 0x1c80, 0x0345 };
	switch (rnd(8)) {
	case 0: return 0x20 + rnd(95);
	case 1: case 2: case 3: return lst[rnd(sizeof lst / sizeof *lst)];
	case 4: return 0xac00 + rnd(11172);
	case 5: return 0x300 + rnd(0x70);
	case 6: return rnd(2) ? rnd(0x3000) : 0x10000 + rnd(0x20000);
	default: return 0xe000 + rnd(0x2000);
	}
}
