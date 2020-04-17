use std::convert::TryInto;
use std::error::Error;
use std::fmt::{Display, Write};

use bytes::BytesMut;
use tokio_util::codec::{Decoder, Encoder};

use crate::Reply;

const DEFAULT_LINE_LENGTH: usize = 2048;
const DEFAULT_MAX_CHUNK_SIZE: u64 = 1024 * 1024;

#[derive(Clone, Debug)]
pub struct LineCodec {
    max_length: usize,
    /// Max chunk that is buffered at once. If a BDAT is larger than
    /// this, it will be split into chunks of this size.
    max_chunk_size: u64,
    valid: bool,
    state: State,
}

#[derive(Debug)]
pub enum LineError {
    LineTooLong,
    IO(std::io::Error),
    ChunkingDone,
    DataAbort,
}

#[derive(Clone, Debug)]
enum State {
    Text { next_index: usize },
    Chunk(u64),
}

impl LineCodec {
    fn new(max_length: Option<usize>, max_chunk_size: Option<u64>) -> Self {
        Self {
            max_length: max_length.unwrap_or(DEFAULT_LINE_LENGTH),
            max_chunk_size: max_chunk_size.unwrap_or(DEFAULT_MAX_CHUNK_SIZE),
            state: State::Text { next_index: 0 },
            valid: true,
        }
    }

    fn decode_text(
        &mut self,
        buf: &mut BytesMut,
        next_index: usize,
    ) -> Result<Option<BytesMut>, LineError> {
        let read_to = std::cmp::min(self.max_length.saturating_add(1), buf.len());

        let crlf_offset = buf[next_index..read_to]
            .windows(2)
            .position(|x| x == b"\r\n")
            .map(|i| i + next_index + 2);

        match crlf_offset {
            Some(offset) => {
                self.state = State::Text { next_index: 0 };

                Ok(Some(buf.split_to(offset)))
            }
            None => {
                if buf.len() > self.max_length {
                    self.valid = false;
                    Err(LineError::LineTooLong)
                } else {
                    self.state = State::Text {
                        next_index: buf.len().saturating_sub(1),
                    };
                    Ok(None)
                }
            }
        }
    }

    fn decode_binary(
        &mut self,
        buf: &mut BytesMut,
        bytes_remaining: u64,
    ) -> Result<Option<BytesMut>, LineError> {
        if bytes_remaining == 0 {
            self.state = State::Text { next_index: 0 };
            return Err(LineError::ChunkingDone);
        }

        // FIXME: too many conversions to be clear.
        let wanted_chunk: u64 = std::cmp::min(self.max_chunk_size, bytes_remaining);
        let buf_len: u64 = buf.len().try_into().unwrap();

        if buf_len >= wanted_chunk {
            let chunk_size: usize = wanted_chunk.try_into().unwrap_or(std::usize::MAX);
            let chunk_size_u64: u64 = chunk_size.try_into().unwrap();

            self.state = State::Chunk(bytes_remaining - chunk_size_u64);
            Ok(Some(buf.split_to(chunk_size)))
        } else {
            Ok(None)
        }
    }

    pub(crate) fn chunking_mode(&mut self, chunk_size: u64) {
        self.state = match self.state {
            State::Text { .. } => State::Chunk(chunk_size),
            State::Chunk(..) => panic!("Invalid chunking state"),
        }
    }
}

impl Default for LineCodec {
    fn default() -> Self {
        Self::new(None, None)
    }
}

impl Decoder for LineCodec {
    type Error = LineError;
    type Item = BytesMut;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if !self.valid {
            return Err(LineError::LineTooLong);
        }

        match self.state {
            State::Text { next_index } => self.decode_text(buf, next_index),
            State::Chunk(remaining) => self.decode_binary(buf, remaining),
        }
    }
}

impl Encoder<Reply> for LineCodec {
    type Error = LineError;

    fn encode(&mut self, reply: Reply, buf: &mut BytesMut) -> Result<(), Self::Error> {
        write!(buf, "{}", reply)
            .map_err(|_| LineError::from(std::io::Error::from(std::io::ErrorKind::Other)))
    }
}

impl From<std::io::Error> for LineError {
    fn from(err: std::io::Error) -> Self {
        Self::IO(err)
    }
}

impl Error for LineError {}

impl Display for LineError {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        write!(fmt, "{:?}", self)
    }
}
