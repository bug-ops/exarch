//! A `Password` must not be printable with `{}`: only the redacted `Debug`
//! exists, so a secret cannot reach a log line through `Display`.

use exarch_core::Password;

fn main() {
    let password = Password::new(b"correct-horse".to_vec()).unwrap();
    let _text = format!("{password}");
}
