// Copyright 2017 int08h LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std;

use tag::Tag;

/// Error types generated by this implementation
#[derive(Debug)]
pub enum Error {
    /// The associated tag was added to an `RtMessage` in non-increasing order.
    TagNotStrictlyIncreasing(Tag),

    /// The associated byte sequence does not correspond to a valid Roughtime tag.
    InvalidTag(Box<[u8]>),

    /// Encoding failed. The associated `std::io::Error` should provide more information.
    EncodingFailure(std::io::Error),

    /// Request was less than 1024 bytes
    RequestTooShort,

    /// Otherwise invalid request
    InvalidRequest,
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::EncodingFailure(err)
    }
}
