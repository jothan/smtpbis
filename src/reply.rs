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
