# Roughenough
**Roughenough** is a **WORK IN PROGRESS** Rust implementation of the [Roughtime](https://roughtime.googlesource.com/roughtime) 
secure time synchronization protocol.

## About the Roughtime Protocol
[Roughtime](https://roughtime.googlesource.com/roughtime) is a protocol that aims to achieve rough 
time synchronisation in a secure way that doesn't depend on any particular time server, and in such
a way that, if a time server does misbehave, clients end up with cryptographic proof of it. It was 
created by Adam Langley and Robert Obryk.

## Links
* [Roughenough Github repo](https://github.com/int08h/roughenough)
* [Roughtime project](https://roughtime.googlesource.com/roughtime)
* My blog posts [describing Roughtime features](https://int08h.com/post/to-catch-a-lying-timeserver/) and 
  exploring the [details of Roughtime messages](https://int08h.com/post/roughtime-message-anatomy/).

## Building

Use `cargo` to compile:

```bash
$ cargo run
```

## Implementation Status

Work-in-progress.

* Protocol - incomplete
* Server - not started
  
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
