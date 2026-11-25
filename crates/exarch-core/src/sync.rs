//! Poison-tolerant locking shared by the modules of this crate.

use std::sync::Mutex;
use std::sync::MutexGuard;
use std::sync::PoisonError;

/// Locks `mutex`, taking the data of a poisoned one.
///
/// Recovering assumes that whatever the panicking holder left behind is still
/// usable. That holds for the records guarded in this crate that are written
/// whole (the TAR metadata window and exempt path, the recorded source fault).
/// It does not hold in general: the ZIP reader state in `zip_structure`
/// (window, cursor and the wrapped reader's believed position) can be stale if
/// the wrapped reader panicked mid-read, so that caller is only safe as long as
/// such a panic ends the operation that owns the reader. This is the only place
/// the crate spells the recovery out.
pub(crate) fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_poisoned_mutex_still_yields_its_data() {
        let mutex = std::sync::Arc::new(Mutex::new(7u8));
        let held = std::sync::Arc::clone(&mutex);
        let panicked = std::thread::spawn(move || {
            let _guard = held.lock();
            panic!("poison the lock");
        })
        .join();
        assert!(panicked.is_err());
        assert!(mutex.is_poisoned());
        assert_eq!(*lock_unpoisoned(&mutex), 7);
    }
}
