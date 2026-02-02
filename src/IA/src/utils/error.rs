use crate::prelude::String;

#[derive(Debug)]
pub enum Error {
    Custom(String),
}

pub type Result<T> = core::result::Result<T, Error>;
