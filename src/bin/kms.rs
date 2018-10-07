// Copyright 2017-2018 int08h LLC
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

//!
//! Work with Roughenough long-term key
//!

#[macro_use]
extern crate clap;
#[macro_use]
extern crate log;
extern crate ring;
extern crate roughenough;
extern crate simple_logger;
extern crate untrusted;

#[cfg(feature = "kms")]
use roughenough::key::awskms::AwsKms;

use std::default::Default;

use clap::{App, Arg};
use roughenough::VERSION;

pub fn main() {
    use log::Level;

    simple_logger::init_with_level(Level::Info).unwrap();

    let matches = App::new("Roughenough key management")
        .version(VERSION)
        .arg(
            Arg::with_name("operation")
                .required(true)
                .help("The operation to perform")
                .takes_value(true),
        ).get_matches();

    if cfg!(feature = "kms") {
        info!("KMS feature enabled");
        let client = AwsKms::from_arn(
            "arn:aws:kms:us-east-2:927891522318:key/1c96fb2c-d417-48f4-bf24-8e7173a587f5",
        ).unwrap();

        let ciphertext = client.encrypt("This is a test".as_ref()).unwrap();
        info!("Ciphertext: {:?}", ciphertext);

        let plaintext = String::from_utf8(client.decrypt(ciphertext.as_ref()).unwrap()).unwrap();
        info!("Plaintext : {:?}", plaintext);
    }

    info!("Done");
}
