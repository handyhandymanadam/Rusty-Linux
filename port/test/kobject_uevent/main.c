/* kobject_uevent differential: kobject_synth_uevent() and zap_modalias_env() of pristine lib/kobject_uevent.c (ARM_REF) against the same functions through kobject_uevent_glue.c's
 * wrappers over kobject_uevent_rs.rs (ARM_RS). Part 1: random "action [UUID KEY=VALUE ...]" strings (valid and broken in every field: action word, newline/NUL tail, UUID,
 * separators, key/value characters, count shorter than the string, too many or too long arguments) -> the stubbed kobject_uevent_env() prints the action and the whole env;
 * Part 2: random environments with MODALIAS= variables, zap_modalias_env(), the whole env block printed.   usage: t SHARD (env KU_N, KU_PROVE=1) */
#include <ctype.h>
#include <linux/kobject.h>
int warn_count; static long allocs_out;
void klog(const char *tag, const char *fmt, ...) { char b[512]; va_list ap; va_start(ap, fmt); vsnprintf(b, sizeof b, fmt, ap); va_end(ap); printf("  LOG %s: %s%s", tag, b, b[0] && b[strlen(b) - 1] == '\n' ? "" : "\n"); }
static int alloc_fail;
void *kzalloc(size_t n, gfp_t g) { (void)g; if (alloc_fail) { alloc_fail = 0; return NULL; } allocs_out++; return calloc(1, n); }
void kfree(const void *p) { if (p) allocs_out--; free((void *)p); }
bool uuid_is_valid(const char *uuid)
{
	for (unsigned i = 0; i < UUID_STRING_LEN; i++) {
		if (i == 8 || i == 13 || i == 18 || i == 23) { if (uuid[i] != '-') return false; }
		else if (!isxdigit((unsigned char)uuid[i])) return false;
	}
	return true;
}
static int ue_fail;
int kobject_uevent_env(struct kobject *kobj, enum kobject_action action, char *envp[])
{
	(void)kobj; printf("  UEVENT action=%d", action);
	for (int i = 0; envp[i]; i++) printf(" [%s]", envp[i]);
	printf("\n");
	if (ue_fail) { ue_fail = 0; return -ENOMEM; }
	return 0;
}
char *kobject_get_path(const struct kobject *kobj, gfp_t gfp) { (void)gfp; return (kobj && kobj->id & 1) ? strdup("/devices/test") : NULL; }
static const char *kobject_actions[] = { [KOBJ_ADD] = "add", [KOBJ_REMOVE] = "remove", [KOBJ_CHANGE] = "change", [KOBJ_MOVE] = "move", [KOBJ_ONLINE] = "online", [KOBJ_OFFLINE] = "offline", [KOBJ_BIND] = "bind", [KOBJ_UNBIND] = "unbind" };
#include SRC

static unsigned long long rs_;
static unsigned rnd(unsigned n) { rs_ = rs_ * 6364136223846793005ULL + 1442695040888963407ULL; return n ? (unsigned)(rs_ >> 40) % n : 0; }
static const char *UUIDS[] = { "0123abcd-4567-89ab-cdef-0123456789ab", "ABCDEF01-2345-6789-ABCD-EF0123456789", "0123abcd-4567-89ab-cdef-0123456789a", "0123abcd_4567-89ab-cdef-0123456789ab",
	"0123abcg-4567-89ab-cdef-0123456789ab", "0123abcd-4567-89ab-cdef-0123456789abx" };
static const char *WORDS[] = { "A", "key1", "K", "ab12", "Z9", "x_y", "k-v", "a b", "", "naïve", "0", "value" };
static const char *ACTS[] = { "add", "remove", "change", "move", "online", "offline", "bind", "unbind", "ad", "adds", "ADD", "", "bin", "unbindx", "change2", "o" };

static void part1(long s)
{
	char b[4096]; int n = 0;
	static char longw[301]; if (!longw[0]) memset(longw, 'q', 300);
	static const char *OKW[] = { "A", "key1", "K", "ab12", "Z9", "value", "0", "x1y2", longw, "\xe9k", "\xd7" };
	n += sprintf(b + n, "%s", ACTS[rnd(10) ? rnd(8) : rnd(16)]);
	int npairs = rnd(3) ? rnd(4) : rnd(50);
	if (rnd(8) != 0) {
		b[n++] = ' ';
		n += sprintf(b + n, "%s", UUIDS[rnd(10) ? rnd(2) : rnd(6)]);
		int stress = rnd(10) == 0;
		for (int i = 0; i < (stress ? 12 : npairs) && n < 2400; i++)
			n += sprintf(b + n, " %s=%s", stress && rnd(2) ? longw : OKW[rnd(12) ? rnd(8) : 8 + rnd(3)], stress ? longw : OKW[rnd(12) ? rnd(8) : 8 + rnd(3)]);
	}
	if (rnd(3) == 0) { /* one corruption */
		static const char C[] = { ' ', '=', '\n', 'x', '_', '-', '\t', (char)0xc3, '1' };
		int pos = rnd(n + 1), kind = rnd(3);
		if (kind == 0 && n > 0) { if (pos == n) pos--; b[pos] = C[rnd(9)]; }
		else if (kind == 1 && n > 0) { if (pos == n) pos--; memmove(b + pos, b + pos + 1, n - pos - 1); n--; }
		else { memmove(b + pos + 1, b + pos, n - pos); b[pos] = C[rnd(9)]; n++; }
	}
	int tail = rnd(5); /* 0 nothing, 1 '\n', 2 NUL, 3 '\n' + NUL, 4 two newlines */
	if (tail == 1) b[n++] = '\n'; else if (tail == 2) b[n++] = 0; else if (tail == 3) { b[n++] = '\n'; b[n++] = 0; } else if (tail == 4) { b[n++] = '\n'; b[n++] = '\n'; }
	size_t count = n;
	if (rnd(10) == 0) count = rnd(n + 1);
	/* the bytes the functions may read are exactly `count`; anything else read shows up under valgrind */
	/* KU_EXACT=1 allocates exactly `count` bytes (valgrind sees any over-read); otherwise the bytes after `count` are the real continuation of the string */
	size_t alloc = getenv("KU_EXACT") ? count : (size_t)n + 8;
	char *buf = malloc(alloc ? alloc : 1); memcpy(buf, b, alloc < (size_t)n ? alloc : (size_t)n); if (alloc > (size_t)n) memset(buf + n, '!', alloc - n);
	/* an embedded NUL before the action word ends would make C read past a string literal; leave those out */
	if (memchr(buf, 0, count > 0 ? count - 1 : 0)) { free(buf); printf("%ld skip-nul\n", s); return; }
	struct kobject k = { .id = rnd(2) };
	if (rnd(15) == 0) ue_fail = 1;
	if (rnd(25) == 0) alloc_fail = 1;
	int r = kobject_synth_uevent(&k, buf, count);
	ue_fail = 0; alloc_fail = 0;
	printf("%ld synth '", s); for (size_t i = 0; i < count; i++) putchar(buf[i] >= 32 && buf[i] < 127 ? buf[i] : '?'); printf("' count=%zu -> %d\n", count, r);
	free(buf);
}

static void dump_env(struct kobj_uevent_env *e)
{
	unsigned long h = 5381;
	for (int i = 0; i < UEVENT_BUFFER_SIZE; i++) h = h * 33 + (unsigned char)e->buf[i];
	printf("  ENV idx=%d buflen=%d bufhash=%lx:", e->envp_idx, e->buflen, h);
	for (int i = 0; i < e->envp_idx; i++) printf(" [%ld:%s]", (long)(e->envp[i] - e->buf), e->envp[i]);
	printf("\n  SLOTS");
	for (int i = 0; i < UEVENT_NUM_ENVP; i++) if (e->envp[i]) printf(" %d:%ld", i, (long)(e->envp[i] - e->buf));
	printf("\n");
}
static void part2(long s)
{
	static struct kobj_uevent_env e; memset(&e, 0xAA, sizeof e); e.envp_idx = 0; e.buflen = 0; memset(e.envp, 0, sizeof e.envp);
	int n = rnd(4) ? rnd(8) : rnd(70);
	for (int i = 0; i < n; i++) {
		static const char *K[] = { "MODALIAS", "MODALIAS", "ACTION", "DEVPATH", "MODALIAS2", "MODALIA", "SEQNUM", "modalias", "XMODALIAS" };
		const char *k = K[rnd(9)];
		if (rnd(4) == 0) { if (add_uevent_var(&e, "%s=%s", k, "") ) break; }
		else if (add_uevent_var(&e, "%s=%s%d", k, "val", (int)rnd(1000))) break;
	}
	printf("%ld zap n=%d\n", s, n); dump_env(&e);
	zap_modalias_env(&e); dump_env(&e);
	zap_modalias_env(&e);
}

int main(int argc, char **argv)
{
	int shard = argc > 1 ? atoi(argv[1]) : 0; long n = getenv("KU_N") ? atol(getenv("KU_N")) : 30000; int prove = getenv("KU_PROVE") != NULL;
	setvbuf(stdout, NULL, _IOFBF, 1 << 20);
	rs_ = 0x9e3779b97f4a7c15ULL * (shard + 1);
	for (long s = 0; s < n; s++) {
		if (rnd(3)) part1(s); else part2(s);
		if (prove && s == 20) printf("  POISON\n");
	}
	printf("final warn=%d allocs=%ld\n", warn_count, allocs_out);
	return 0;
}
