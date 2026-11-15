//! A `Password` must not be duplicated: copies of the secret would outlive the
//! one that is wiped. Callers share it with `Arc<Password>` instead.

use exarch_core::Password;

fn main() {
    let password = Password::new(b"correct-horse".to_vec()).unwrap();
    let _copy = password.clone();
}
