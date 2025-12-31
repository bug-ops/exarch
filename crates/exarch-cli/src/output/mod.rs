//! Output formatting module.

mod formatter;
mod human;
mod json;

pub use formatter::OutputFormatter;

use human::HumanFormatter;
use json::JsonFormatter;

/// Creates an output formatter based on CLI flags
pub fn create_formatter(json: bool, verbose: bool, quiet: bool) -> Box<dyn OutputFormatter> {
    if json {
        Box::new(JsonFormatter)
    } else {
        Box::new(HumanFormatter::new(verbose, quiet))
    }
}
