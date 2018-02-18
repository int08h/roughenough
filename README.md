# Roughenough 

[![Apache License 2](https://img.shields.io/badge/license-ASF2-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0.txt)
[![Build Status](https://travis-ci.org/int08h/roughenough.svg?branch=master)](https://travis-ci.org/int08h/roughenough)

**Roughenough** is a [Roughtime](https://roughtime.googlesource.com/roughtime) secure time 
synchronization server implemented in Rust.

The server is bare-bones, but functionally complete: it parses client requests and generates valid Roughtime responses.
*Rough edges and unimplemented features remain*, see [limitations](#limitations) below. 
Contributions are welcome.

## Links
* [Roughenough Github repo](https://github.com/int08h/roughenough)
* [Roughtime project](https://roughtime.googlesource.com/roughtime)
* My blog posts [describing Roughtime features](https://int08h.com/post/to-catch-a-lying-timeserver/) and 
  exploring the [details of Roughtime messages](https://int08h.com/post/roughtime-message-anatomy/).

## Building and Running

### Starting the Server

```bash
$ cargo run --release --bin server /path/to/config.file
...
2017-07-03T19:39:45-05:00 [INFO] Roughenough server v0.1 starting
2017-07-03T19:39:45-05:00 [INFO] Long-term public key: d0756ee69ff5fe96cbcf9273208fec53124b1dd3a24d3910e07c7c54e2473012
2017-07-03T19:39:45-05:00 [INFO] Ephemeral public key: 575d5ed128143c0f7a5cdaf476601dd1b8a192a7199e62c0d2c039b53234d062
2017-07-03T19:39:45-05:00 [INFO] Server listening on 127.0.0.1:8686
```

The resulting binary is `target/release/server`. After building you can copy the 
binary and run on its own (no `cargo` needed):

```bash
$ cp target/release/server /usr/local/bin 
$ /usr/local/bin/server /path/to/config.file
```

### Configuration File

The server is configured via a YAML file:

```yaml
interface: 127.0.0.1
port: 8686
seed: f61075c988feb9cb700a4a6a3291bfbc9cab11b9c9eca8c802468eb38a43d7d3
```

Where:

* **`interface`** - IP address or interface name for listening to client requests
* **`port`** - UDP port to listen for requests
* **`seed`** - A 32-byte hexadecimal value used to generate the server's long-term 
               key pair. **This is a secret value**, treat it with care.

### Stopping the Server
Use Ctrl-C or `kill` the process.

## Limitations

Roughtime features not implemented:

* Leap-second smearing.
* Ecosystem-style response fault injection.
* On-line key rotation. The server must be restarted to generate a new delegated key. 
* Multi-request Merkle Tree batching. For now each request gets its own response 
  with `PATH` empty and `INDX` zero.

Other notes:

* Error-handling is not robust. There are `unwrap()`'s and `expect()`'s in the request 
  handling path.
* The server is a simple single-threaded `recv_from` loop. `mio` and `tokio` are 
  intentionally avoided to keep the implementation straightforward and maximize 
  comprehensibility by newbie Rustaceans. Blazing async ninja speed is not a goal.
* Per-request heap allocations could be reduced: a few `Vec`'s could be replaced by 
  lifetime scoped slices.
* Constants aren't consistently used. A few hard-coded magic numbers remain.
* Goal of using self-contained dependencies did not bear fruit. Many transitive 
  dependencies lengthen the build-time. Build is (to me) too long for such a 
  simple project. 

## About the Roughtime Protocol
[Roughtime](https://roughtime.googlesource.com/roughtime) is a protocol that aims to achieve rough 
time synchronisation in a secure way that doesn't depend on any particular time server, and in such
a way that, if a time server does misbehave, clients end up with cryptographic proof of it. It was 
created by Adam Langley and Robert Obryk.
  
## Contributors
* Stuart Stock, original author and current maintainer (stuart {at} int08h.com)

## Copyright and License
Roughenough is copyright (c) 2017-2018 int08h LLC. All rights reserved. 

int08h LLC licenses Roughenough (the "Software") to you under the Apache License, version 2.0 
(the "License"); you may not use this Software except in compliance with the License. You may obtain 
a copy of the License from the [LICENSE](../master/LICENSE) file included with the Software or at:

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License 
is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or 
implied. See the License for the specific language governing permissions and limitations under 
the License.
