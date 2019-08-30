use std::borrow::Cow;
use std::fmt::Display;

pub struct Reply {
    code: u16,
    ecode: Option<EnhancedCode>,
    text: Cow<'static, str>,
}

impl Reply {
    pub fn new_checked<S: Into<Cow<'static, str>>>(
        code: u16,
        ecode: Option<EnhancedCode>,
        text: S,
    ) -> Option<Self> {
        let text = text.into();
        if code < 200 || code >= 600 || text.contains('\r') {
            return None;
        }
        Some(Reply { code, ecode, text })
    }

    pub fn new<S: Into<Cow<'static, str>>>(
        code: u16,
        ecode: Option<EnhancedCode>,
        text: S,
    ) -> Self {
        Self::new_checked(code, ecode, text).expect("Invalid code or CR in reply text.")
    }

    pub fn ok() -> Self {
        Self::new(250, None, "OK")
    }

    pub fn bad_sequence() -> Self {
        Self::new(503, None, "Bad sequence of commands")
    }

    pub fn no_mail_transaction() -> Self {
        Self::new(503, None, "No mail transaction in progress")
    }

    pub fn no_valid_recipients() -> Self {
        Self::new(554, None, "No valid recipients")
    }

    pub fn syntax_error() -> Self {
        Self::new(500, None, "Syntax error")
    }

    pub fn not_implemented() -> Self {
        Self::new(502, None, "Command not implemented")
    }

    pub fn is_error(&self) -> bool {
        match ReplyCategory::from(self) {
            ReplyCategory::TempError | ReplyCategory::PermError => true,
            _ => false,
        }
    }
}

pub(crate) trait ReplyDefault {
    fn with_default(self, default: Reply) -> Result<Reply, Reply>;
}

impl ReplyDefault for Option<Reply> {
    fn with_default(self, default: Reply) -> Result<Reply, Reply> {
        let expected_category = ReplyCategory::from(&default);
        let reply = self.unwrap_or(default);
        let category = ReplyCategory::from(&reply);

        if category == expected_category {
            Ok(reply)
        } else {
            Err(reply)
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum ReplyCategory {
    Success,
    Intermediate,
    TempError,
    PermError,
}

impl From<&Reply> for ReplyCategory {
    fn from(input: &Reply) -> Self {
        // Caveat: 552 on reply to RCPT is considered temporary.

        match input.code {
            200..=299 => Self::Success,
            300..=399 => Self::Intermediate,
            400..=499 => Self::TempError,
            500..=599 => Self::PermError,
            _ => unreachable!(),
        }
    }
}

impl Display for Reply {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        let mut lines_iter = self.text.lines().peekable();

        loop {
            let line = match (lines_iter.next(), lines_iter.peek()) {
                (Some(line), Some(_)) => {
                    write!(fmt, "{}-", self.code)?;
                    line
                }
                (Some(line), None) => {
                    write!(fmt, "{} ", self.code)?;
                    line
                }
                (None, _) => break,
            };

            if let Some(ecode) = &self.ecode {
                write!(fmt, "{} ", ecode)?;
            }

            writeln!(fmt, "{}\r", line)?;
        }

        Ok(())
    }
}

pub struct EnhancedCode(u8, u16, u16);

impl Display for EnhancedCode {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(fmt, "{}.{}.{}", self.0, self.1, self.2)
    }
}
