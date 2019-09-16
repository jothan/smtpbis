use nom::branch::alt;
use nom::combinator::map;

use rustyknife::rfc5321::{
    bdat_command, command as base_command, starttls_command, Command as BaseCommand, UTF8Policy,
};
use rustyknife::NomResult;
use rustyknife::xforward::{command as xforward_command, Param as XforwardParam};

#[derive(Debug)]
pub enum Command {
    Base(BaseCommand),
    Ext(Ext),
}

#[derive(Debug)]
pub enum Ext {
    STARTTLS,
    BDAT(u64, bool),
    XFORWARD(Vec<XforwardParam>),
}

pub fn command<P: UTF8Policy>(input: &[u8]) -> NomResult<'_, Command> {
    alt((
        map(base_command::<P>, Command::Base),
        map(starttls_command, |_| Command::Ext(Ext::STARTTLS)),
        map(bdat_command, |(size, last)| {
            Command::Ext(Ext::BDAT(size, last))
        }),
        map(xforward_command, |params| {
            Command::Ext(Ext::XFORWARD(params))
        }),
    ))(input)
}
