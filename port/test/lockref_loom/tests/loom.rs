use loom::sync::Arc;
use loom::sync::atomic::Ordering;
use loom::thread;
use lockref_loom::*;

// word layout: lock = low 32 bits, count = high 32 bits
fn mk(count: i32) -> Arc<Lockref> { Arc::new(Lockref { lock_count: loom::sync::atomic::AtomicU64::new((count as u32 as u64) << 32) }) }
fn count(l: &Lockref) -> i32 { (l.lock_count.load(Ordering::SeqCst) >> 32) as i32 }
fn p(l: &Arc<Lockref>) -> *mut Lockref { Arc::as_ptr(l) as *mut Lockref }

// A fast-path op that returns "take the lock" must be redone under the lock; model the lock as a CAS of the low half
fn locked_add(l: &Lockref, d: i32) {
    loop {
        let old = l.lock_count.load(Ordering::SeqCst);
        if (old as u32) != 0 { loom::thread::yield_now(); continue; }
        let locked = old | 1;
        if l.lock_count.compare_exchange(old, locked, Ordering::SeqCst, Ordering::SeqCst).is_ok() {
            let c = ((locked >> 32) as i32).wrapping_add(d);
            l.lock_count.store((c as u32 as u64) << 32, Ordering::SeqCst); // unlock + new count together
            return;
        }
    }
}

#[test]
fn gets_and_puts_conserve_count() {
    loom::model(|| {
        let l = mk(2);
        let (a, b, c) = (l.clone(), l.clone(), l.clone());
        let t1 = thread::spawn(move || unsafe { if !rust_lockref_get_fast(p(&a)) { locked_add(&a, 1) } });
        let t2 = thread::spawn(move || unsafe { if rust_lockref_put_return(p(&b)) < 0 { locked_add(&b, -1) } });
        let t3 = thread::spawn(move || unsafe { if !rust_lockref_put_or_lock_fast(p(&c)) { locked_add(&c, -1) } });
        t1.join().unwrap(); t2.join().unwrap(); t3.join().unwrap();
        assert_eq!(count(&l), 1);
    });
}
