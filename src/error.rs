use std;

use tag::Tag;

#[derive(Debug)]
pub enum Error {
    TagNotStrictlyIncreasing(Tag),
    EncodingFailure(std::io::Error),
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::EncodingFailure(err)
    }
}
