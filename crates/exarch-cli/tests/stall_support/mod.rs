//! Drives `exarch extract` into the `test-hooks` stall seam
//! (`EXARCH_TEST_STALL_AT_ENTRY`) and synchronizes on the ready line the hook
//! writes to stderr, never on a sleep.

#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::disallowed_methods
)]

use std::io::BufRead as _;
use std::io::BufReader;
use std::io::Read as _;
use std::path::Path;
use std::process::Child;
use std::process::ChildStdin;
use std::process::Command;
use std::process::ExitStatus;
use std::process::Stdio;
use std::sync::mpsc;
use std::time::Duration;
use std::time::Instant;

use assert_cmd::cargo::cargo_bin_cmd;

pub const DEADLINE: Duration = Duration::from_secs(20);

pub fn ready_line(entry: usize) -> String {
    format!("exarch-test: stalled at entry {entry}")
}

pub struct Stalled {
    child: Child,
    stdin: Option<ChildStdin>,
    lines: mpsc::Receiver<String>,
}

impl Drop for Stalled {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub const READY_AFTER_PREPARE: &str = "exarch-test: stalled after prepare";

pub fn spawn(args: &[&str], archive: &Path, out: &Path, entry: usize) -> Stalled {
    launch(
        args,
        archive,
        out,
        ("EXARCH_TEST_STALL_AT_ENTRY", &entry.to_string()),
    )
}

/// Stalls at the end of the interrupt `prepare`, before `start`.
pub fn spawn_after_prepare(args: &[&str], archive: &Path, out: &Path) -> Stalled {
    launch(args, archive, out, ("EXARCH_TEST_STALL_AFTER_PREPARE", "1"))
}

fn launch(args: &[&str], archive: &Path, out: &Path, hook: (&str, &str)) -> Stalled {
    let mut child = Command::new(cargo_bin_cmd!("exarch").get_program())
        .args(args)
        .arg(archive)
        .arg(out)
        .env(hook.0, hook.1)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn exarch");
    let stdin = child.stdin.take();
    let stderr = child.stderr.take().expect("stderr");
    let (sender, lines) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            if sender.send(line).is_err() {
                return;
            }
        }
    });
    Stalled {
        child,
        stdin,
        lines,
    }
}

impl Stalled {
    /// Waits until the hook reports the stall at `entry`; returns every stderr
    /// line seen up to and including it.
    pub fn wait_ready(&self, entry: usize) -> Vec<String> {
        self.wait_for_line(&ready_line(entry))
    }

    /// Waits until the run reports the stall after `prepare`.
    pub fn wait_ready_after_prepare(&self) -> Vec<String> {
        self.wait_for_line(READY_AFTER_PREPARE)
    }

    fn wait_for_line(&self, expected: &str) -> Vec<String> {
        let ends = Instant::now() + DEADLINE;
        let mut seen = Vec::new();
        loop {
            let left = ends.saturating_duration_since(Instant::now());
            match self.lines.recv_timeout(left) {
                Ok(line) => {
                    let found = line == expected;
                    seen.push(line);
                    if found {
                        return seen;
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout | mpsc::RecvTimeoutError::Disconnected) => {
                    panic!("the stall hook never wrote {expected:?}; stderr: {seen:?}")
                }
            }
        }
    }

    pub fn process_id(&self) -> u32 {
        self.child.id()
    }

    /// Delivers one SIGINT.
    pub fn interrupt_once(&self) {
        let sent = Command::new("kill")
            .args(["-INT", &self.child.id().to_string()])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("run kill");
        assert!(sent.success(), "{sent:?}");
    }

    /// Sends SIGINT until the process ends; returns its status and stdout.
    pub fn interrupt_until_exit(&mut self) -> (ExitStatus, String) {
        let ends = Instant::now() + DEADLINE;
        let status = loop {
            self.interrupt_once();
            std::thread::sleep(Duration::from_millis(50));
            if let Some(status) = self.child.try_wait().unwrap() {
                break status;
            }
            assert!(Instant::now() < ends, "the run outlived repeated SIGINTs");
        };
        let mut stdout = Vec::new();
        self.child
            .stdout
            .take()
            .unwrap()
            .read_to_end(&mut stdout)
            .unwrap();
        (status, String::from_utf8_lossy_owned(stdout))
    }

    /// Closes stdin so the stalled read returns and the run continues.
    pub fn release(&mut self) {
        drop(self.stdin.take());
    }

    /// Waits for the process to end after `release`; returns status and stdout.
    pub fn finish(mut self) -> (ExitStatus, String) {
        self.release();
        let mut stdout = Vec::new();
        self.child
            .stdout
            .take()
            .unwrap()
            .read_to_end(&mut stdout)
            .unwrap();
        let status = self.child.wait().unwrap();
        (status, String::from_utf8_lossy_owned(stdout))
    }
}
