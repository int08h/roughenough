## Version 1.1.0

* Optional HTTP health check (requested in #8), see the
  [feature's documentation](https://github.com/int08h/roughenough/blob/doc/OPTIONAL-FEATURES.md#http-health-check)
* Support AWS and Google Key Management Systems (KMS) to protect the server's long-term key.
  See the [KMS documentation](https://github.com/int08h/roughenough/blob/doc/OPTIONAL-FEATURES.md#key-management-system-kms-support).
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