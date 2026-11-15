//! A `Password` cannot be assembled around a buffer that skipped the length
//! check: its field is private, so `Password::new` is the only constructor.

use exarch_core::Password;

#[allow(unreachable_code)]
fn main() {
    let _password = Password(todo!());
}
