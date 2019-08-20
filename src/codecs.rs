use std::error::Error;
use std::fmt::{Display, Write};

use bytes::BytesMut;
use tokio::codec::{Decoder, Encoder};

use crate::Reply;

const DEFAULT_LINE_LENGTH: usize = 2048;

#[derive(Clone, Debug)]
pub struct LineCodec {
    max_length: usize,
    next_index: usize,
    valid: bool,
}

#[derive(Debug)]
pub enum LineError {
    LineTooLong,
    IO(std::io::Error),
}

impl LineCodec {
    fn new(max_length: Option<usize>) -> Self {
        Self {
            max_length: max_length.unwrap_or(DEFAULT_LINE_LENGTH),
            next_index: 0,
            valid: true,
        }
    }
}

impl Default for LineCodec {
    fn default() -> Self {
        Self::new(None)
    }
}

impl Decoder for LineCodec {
    type Error = LineError;
    type Item = BytesMut;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if !self.valid {
            return Err(LineError::LineTooLong);
        }

        let read_to = std::cmp::min(self.max_length.saturating_add(1), buf.len());

        let crlf_offset = buf[self.next_index..read_to]
            .windows(2)
            .position(|x| x == b"\r\n")
            .map(|i| i + self.next_index + 2);

        match crlf_offset {
            Some(offset) => {
                self.next_index = 0;

                Ok(Some(buf.split_to(offset)))
            }
            None => {
                if buf.len() > self.max_length {
                    self.valid = false;
                    Err(LineError::LineTooLong)
                } else {
                    self.next_index = buf.len().saturating_sub(1);
                    Ok(None)
                }
            }
        }
    }
}

impl Encoder for LineCodec {
    type Error = LineError;
    type Item = Reply;

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
