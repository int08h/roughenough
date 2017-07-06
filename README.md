# Roughenough
**Roughenough** is a [Roughtime](https://roughtime.googlesource.com/roughtime) secure time 
synchronization server implemented in Rust.

The server is functionally complete: it parses client requests and generates valid Roughtime responses.
Rough edges remain, particularly in error-handling. See 
[Limitations](#limitations) below. Contributions welcome.

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
Thu Jul  6 15:56:12 2017 [INFO] Roughenough server v0.1 starting
Thu Jul  6 15:56:12 2017 [INFO] Long-term public key: d0756ee69ff5fe96cbcf9273208fec53124b1dd3a24d3910e07c7c54e2473012
Thu Jul  6 15:56:12 2017 [INFO] Ephemeral public key: 7e105566cb7e2e5526b807c4513ef82a417d7dd2556cd6afe6a148e76ac809a6
Thu Jul  6 15:56:12 2017 [INFO] Server listening on 127.0.0.1:8686

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
* **`seed`** - A 32-byte hexadecimal value used to generate the 
             server's long-term key pair. **This is a secret value**, treat it
             with care.

### Stopping the Server
Use Ctrl-C or `kill` the process.

## Limitations

Roughtime features not implemented:

* On-line key rotation. The server must be restarted to generate a new delegated key. 
* Ecosystem-style response fault injection.
* Multi-request Merkle tree is not built. Each request gets its own response with 
  ROOT empty and INDX zero.

Error-handling is not robust. There are many `unwrap()`'s and `expect()`'s in the request handling path.

The server is a dead simple single-threaded `recv_from` loop. `mio` and `tokio` are 
intentionally avoided to keep the implementation straightforward and maximize 
comprehensibility by newbie Rustaceans. Blazing async ninja speed is not a goal.

Per-request heap allocations could be reduced: a few `Vec`'s could be replaced by 
lifetime scoped slices.

Constants aren't consistently used. A few hard-coded magic numbers remain.

## About the Roughtime Protocol
[Roughtime](https://roughtime.googlesource.com/roughtime) is a protocol that aims to achieve rough 
time synchronisation in a secure way that doesn't depend on any particular time server, and in such
a way that, if a time server does misbehave, clients end up with cryptographic proof of it. It was 
created by Adam Langley and Robert Obryk.
  
## Contributors
* Stuart Stock, original author and current maintainer (stuart {at} int08h.com)

## Copyright and License
Roughenough is copyright (c) 2017 int08h LLC. All rights reserved. 

int08h LLC licenses Roughenough (the "Software") to you under the Apache License, version 2.0 
(the "License"); you may not use this Software except in compliance with the License. You may obtain 
a copy of the License from the [LICENSE](../master/LICENSE) file included with the Software or at:

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License 
is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or 
implied. See the License for the specific language governing permissions and limitations under 
the License.
