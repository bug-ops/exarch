//! Gives up the `AesTurn` before a block's decoder first calls the archive
//! source.

use std::cell::RefCell;
use std::io;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;

use crate::encryption::kdf::AesTurn;

/// A source wrapper that holds back the absolute seek sevenz-rust2 makes while
/// it builds a block's decoder and drops the turn before the first call that
/// reaches the inner source.
///
/// The turn guards the derivation of the block's AES key. When the AES coder is
/// the first one the decoder builds, that derivation happens before any source
/// call, so nothing the source does can run under the turn. `release_on_io`
/// says whether the block has that layout; for any other layout the wrapper is
/// transparent and the turn stays with its owner.
#[derive(Debug)]
pub(super) struct TurnGate<'a, R> {
    inner: &'a mut R,
    turn: &'a RefCell<Option<AesTurn>>,
    release_on_io: bool,
    pending_seek: Option<u64>,
}

impl<'a, R> TurnGate<'a, R> {
    /// Wraps `inner`; `turn` is shared with the code that also gives the turn
    /// up once entries are handed over.
    pub(super) const fn new(
        inner: &'a mut R,
        turn: &'a RefCell<Option<AesTurn>>,
        release_on_io: bool,
    ) -> Self {
        Self {
            inner,
            turn,
            release_on_io,
            pending_seek: None,
        }
    }

    fn defers(&self) -> bool {
        self.release_on_io && self.turn.borrow().is_some()
    }
}

impl<R: Seek> TurnGate<'_, R> {
    /// Gives the turn up and performs the seek that was held back.
    fn settle(&mut self) -> io::Result<()> {
        if self.release_on_io {
            drop(self.turn.borrow_mut().take());
        }
        if let Some(position) = self.pending_seek.take() {
            self.inner.seek(SeekFrom::Start(position))?;
        }
        Ok(())
    }
}

impl<R: Read + Seek> Read for TurnGate<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.settle()?;
        self.inner.read(buf)
    }
}

impl<R: Seek> Seek for TurnGate<'_, R> {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        match to {
            SeekFrom::Start(position) if self.defers() => {
                self.pending_seek = Some(position);
                Ok(position)
            }
            _ => {
                self.settle()?;
                self.inner.seek(to)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    struct Recording {
        inner: Cursor<Vec<u8>>,
        calls: usize,
        calls_under_turn: usize,
    }

    impl Recording {
        fn note(&mut self) {
            self.calls += 1;
            if AesTurn::held_by_current_thread() {
                self.calls_under_turn += 1;
            }
        }
    }

    impl Read for Recording {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.note();
            self.inner.read(buf)
        }
    }

    impl Seek for Recording {
        fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
            self.note();
            self.inner.seek(to)
        }
    }

    fn source() -> Recording {
        Recording {
            inner: Cursor::new((0u8..32).collect()),
            calls: 0,
            calls_under_turn: 0,
        }
    }

    #[test]
    fn the_seek_is_held_back_and_the_turn_is_given_up_before_the_first_read() {
        let turn = RefCell::new(Some(AesTurn::acquire()));
        let mut inner = source();
        let mut gate = TurnGate::new(&mut inner, &turn, true);

        assert_eq!(gate.seek(SeekFrom::Start(8)).unwrap(), 8);
        assert!(turn.borrow().is_some());
        let mut buf = [0u8; 2];
        gate.read_exact(&mut buf).unwrap();

        assert_eq!(buf, [8, 9]);
        assert!(turn.borrow().is_none());
        assert!(inner.calls >= 2, "the source was reached");
        assert_eq!(inner.calls_under_turn, 0);
    }

    #[test]
    fn a_relative_seek_gives_the_turn_up_too() {
        let turn = RefCell::new(Some(AesTurn::acquire()));
        let mut inner = source();
        let mut gate = TurnGate::new(&mut inner, &turn, true);

        assert_eq!(gate.seek(SeekFrom::End(-4)).unwrap(), 28);

        assert!(turn.borrow().is_none());
        assert_eq!(inner.calls_under_turn, 0);
    }

    #[test]
    fn a_block_that_does_not_lead_with_its_aes_coder_keeps_the_turn() {
        let turn = RefCell::new(Some(AesTurn::acquire()));
        let mut inner = source();
        let mut gate = TurnGate::new(&mut inner, &turn, false);

        gate.seek(SeekFrom::Start(4)).unwrap();
        gate.read_exact(&mut [0u8; 1]).unwrap();

        assert!(turn.borrow().is_some());
        assert_eq!(inner.calls_under_turn, 2);
    }
}
