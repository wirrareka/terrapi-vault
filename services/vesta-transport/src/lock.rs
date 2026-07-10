//! Poison-tolerant mutex locking for request paths.
//!
//! A panic while holding a `std::sync::Mutex` poisons it; with `.lock().expect(..)`
//! every later request on the shared state then panics too, turning one bug into a
//! service-wide 500 storm. The guarded state in these services is always left
//! consistent-enough (writes are single-step or idempotent), so the right recovery
//! is to take the guard anyway and keep serving.

use std::sync::{Mutex, MutexGuard, PoisonError};

pub trait MutexExt<T> {
    /// Lock, recovering the guard if a previous holder panicked.
    fn lock_recover(&self) -> MutexGuard<'_, T>;
}

impl<T> MutexExt<T> for Mutex<T> {
    fn lock_recover(&self) -> MutexGuard<'_, T> {
        self.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovers_after_poison() {
        let m = std::sync::Arc::new(Mutex::new(1u32));
        let m2 = m.clone();
        let _ = std::thread::spawn(move || {
            let _g = m2.lock().expect("fresh lock");
            panic!("poison it");
        })
        .join();
        assert!(m.lock().is_err(), "mutex should be poisoned");
        *m.lock_recover() = 2;
        assert_eq!(*m.lock_recover(), 2);
    }
}
