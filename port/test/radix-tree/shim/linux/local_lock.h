typedef struct { int dummy; } local_lock_t;
#define INIT_LOCAL_LOCK(x) { 0 }
extern long local_lock_depth;
#define local_lock(l) do { (void)(l); local_lock_depth++; } while (0)
#define local_unlock(l) do { (void)(l); local_lock_depth--; } while (0)
