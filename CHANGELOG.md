## Version 1.2.0-draft-5
* Roughenough (mostly) implements the Roughtime protocol as specified in [the draft-5 RFC](https://www.ietf.org/archive/id/draft-ietf-ntp-roughtime-05.html).
  
  **Important differences from the draft RFC**
  1. Roughenough uses SHA-512/256 to compute the Merkle tree. Draft-5 of the RFC uses a
     bespoke 32-byte SHA-512 prefix without rationale or justification. Given that
     standardized 32-byte SHA-512/256 exists and is already implemented widely, I'm 
     sticking with it while I advocate for the RFC to move away from the custom prefix
     and adopt SHA-512/256.
  2. The server and client send/expect RFC protocol version `1` (VER tag is `0x00000001`) 
     instead of the draft's suggested `0x80000000 + version`.

* The Roughenough server operates both the "classic" protocol **and** the RFC compliant 
  protocol at the same time on a single serving port (the 8-byte magic frame value added 
  by the RFC is used to distinguish classic vs. rfc requests).

  The new `-p/--protocol` flag of `roughenough-client` controls the protocol version to
  use in requests (`0` = classic protocol, `1` = RFC protocol). The default is `0` the
  "classic" protocol, until the RFC is finalized:

  ```
  # send RFC protocol Roughtime requests
  $ roughenough-client -p 1 roughtime.int08h.com 2002
  ```
* Added `-d/--dump` to `roughenough-client` that will pretty-print text representations 
  of the messages it sends and receives.

## Version 1.1.9

Housekeeping:
* 8f088f1 Overdue Ring update 0.13 -> 0.16
* 43b1de3 GCK KMS updated to the latest dependencies
* 7ff2e53 AWS KMS also updated to latest dependencies 

## Version 1.1.8

New feature:
* 407f12d client: output local time by default, add -z/--zulu for UTC 

Housekeeping:
* 02212e2 Switch to std::time and drop use of 'time' crate 
* d42db50 Upgrade several dependencies to latest versions 
* e13d6fd Remove deprecated `std::error::Error::description` calls 
* 32f11aa Update Dockerfile to Rust 1.42 

## Version 1.1.7

* Improved options for client output thanks to @zicklag (f1f834e8c).

  By default the client now outputs just the time reported by the queried server. 
  The `-v` or `--verbose` flag will print additional information such as the response's 
  midpoint and radius. `-j` or `--json` outputs responses in JSON format instead.

  Non-response text output is written to standard error to enable verbose output 
  while redirecting the response(s) to a file or pipe like so:
  
  ```
  $ roughenough-client -v roughtime.int08h.com 2002 > time.txt
  Requesting time from: "roughtime.int08h.com":2002
  Received time from server: midpoint="Oct 08 2019 18:40:38", radius=1000000, verified=No (merkle_index=0)
  
  $ cat time.txt
  Oct 08 2019 18:40:38
  ```

## Version 1.1.6

* Fix several Clippy items (266f1adc9) 
* Update to latest Rusoto (6ff01af52)
* Update to latest google-cloudkms (a0165c019)
* Update Dockerfile to Rust 1.38 (a14c2e8)

## Version 1.1.5

* Improved error messages (3841942)
* Update fuzzer server target to sync with roughenough-fuzz
* Add Dockerfile to create a server container

## Version 1.1.4

* Implement Roughtime ecosystem response mangling (177372f, f851deb)
* Doc fix from @Muncan90 (20ba144)

## Version 1.1.3

* Add decrypt option to `roughenough-kms` 

## Version 1.1.2 

* Add client request statistics tracking.
* Clean-up and simplification of server inner loop.
* Rust 2018 edition required to compile.

## Version 1.1.1

* Provide auxiliary data to the AWS KMS decryption call. The auxiliary data _was_ provided in encrypt, but not decrypt, resulting in unconditional failure when unwrapping the long-term identity. See https://github.com/int08h/roughenough/commit/846128d08bd3fcd72f23b3123b332d0692782e41#diff-7f7c3059af30a5ded26269301caf8531R102

## Version 1.1.0

* Optional HTTP health check (requested in #8), see the
  [feature's documentation](https://github.com/int08h/roughenough/blob/master/doc/OPTIONAL-FEATURES.md#http-health-check)
* Support AWS and Google Key Management Systems (KMS) to protect the server's long-term key.
  See the [KMS documentation](https://github.com/int08h/roughenough/blob/master/doc/OPTIONAL-FEATURES.md#key-management-system-kms-support).
* Numerous refactorings and clean ups to support fuzzing of 
  server components (b801eda, thanks to @Aaron1011)

## Version 1.0.6

* As pointed out in #10, the client and server binary names were too generic. Rename 
  them to be packaging friendly. Thank you @grempe. (b43bcb27ad)
  
## Version 1.0.5

* The server now supports configuration from 
  [environment variables](https://github.com/int08h/roughenough#server-configuration)
  
## Version 1.0.4

* Update `untrusted` dependency to incorporate security fix (see https://github.com/RustSec/advisory-db/pull/24). 
  Fixes #6 reported by @tirkarthi (383b0347).
  
## Release 1.0.3

* Limit the number of tags in a message to 1024 (0b8c965)

## Release 1.0.2

* Merge input validation and error handling improvements from #5. Fuzzing FTW.
* Misc docstring and README updates
* Fix incorrect range-check introduced in 9656fda and released as 1.0.1.

## Release 1.0.1 (yanked)

* Release 1.0.1 was removed from Github and yanked from crates.io due to a range-check bug. 
  1.0.2 is its replacement. 
  
## Release 1.0.0

Thanks to @Aaron1011's work, Roughenough has 1.0 level of functionality.

* Server batches responses and signs Merkle tree root (3471e04, ee38933f, and 31bf8b3)
* `mio` error handling improvement (613fb01f)
* Build on Rust Nightly (350b23a)
