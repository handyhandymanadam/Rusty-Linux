#define DEFINE_PER_CPU(t, n) t n
#define DECLARE_PER_CPU(t, n) extern t n
#define EXPORT_PER_CPU_SYMBOL_GPL(x)
#define this_cpu_ptr(p) (p)
#define per_cpu(var, cpu) (var)
