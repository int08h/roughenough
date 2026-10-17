# Testing the Linux KRS Seed Backend

Instructions for verifying the Linux Key Retention Service (KRS) seed backend,
`crates/roughenough-keys/src/seed/linuxkrs.rs`. The backend is compiled only on Linux
(`cfg(all(target_os = "linux", feature = "online-linux-krs"))`), so a macOS build never
compiles or tests it. Run everything below on Linux.

## What changed and needs verifying

The backend was rewritten on the `fix-correctness-bugs` branch. Compared to `master`:

- **The constructor takes the seed.** `LinuxKrsBackend::new(seed)` derives the public key
  on the calling thread, spawns the worker, and stores the seed before it returns. The
  `store_seed`, `get_seed`, `seed_len`, and `public_key_bytes` methods are gone. The
  `SeedBackend` trait is now `sign` and `public_key` only.
- **Early failures surface from `new`.** If the worker cannot create the thread keyring,
  `new` returns `Err(BackendError::WorkerDisconnect)`. On `master`, `new` succeeded and
  the later store failed.
- **A key that already exists no longer panics.** If `roughenough-seed` is already on the
  thread keyring, the worker logs an error and exits, and callers see `WorkerDisconnect`.
  On `master` this panicked. In practice it cannot happen, because each worker gets a fresh
  thread keyring.
- **One job type replaces the request enum.** Each operation is a boxed closure run on the
  worker thread, with a reply channel.
- **Shutdown closes the channel.** `Drop` drops the job sender, which ends the worker's
  loop. The worker then clears the keyring, and `Drop` joins it. The `Shutdown` message
  is gone.
- **Seed reads are zeroized.** `load_seed` reads into a `Zeroizing<[u8; 32]>`, checks for
  exactly `Seed::LEN` bytes, and builds the seed with `Seed::from_bytes`.
- **Signing uses the shared Ed25519 code path.** `sign` loads the seed on the worker and
  signs with `crate::online::aws_lc_ed25519::KeyPair`, the same wrapper the other backends
  use. It no longer uses `aws_lc_rs::signature::Ed25519KeyPair`.
- **The module moved.** It is now `seed::linuxkrs` (was `online::linuxkrs::krs_backend`).
  It is re-exported as `roughenough_keys::seed::LinuxKrsBackend`, and the server builds it
  with `seed::open(BackendKind::Krs, Some(seed))`.

All of this was first compiled and reviewed on macOS. The steps below have since passed on
Debian 13 (kernel 7.2.6), with step 5 run under the systemd filter rather than Docker.

## Environment

- **Machine.** Use a Linux VM or bare metal with keyring support (`CONFIG_KEYS`, which
  every mainstream distro kernel has). A GitHub Actions `ubuntu-latest` runner works.
- **Containers.** Docker's and Podman's default seccomp profiles block the `add_key`,
  `keyctl`, and `request_key` syscalls. Every KRS operation fails inside a default
  container. Use that setup only for the negative test in step 5. For the positive tests,
  use a VM, or run the container with `--security-opt seccomp=unconfined`.
- **Tools.**
  - Rust stable and nightly (nightly for `cargo +nightly fmt`).
  - A C toolchain for `aws-lc-sys` (`build-essential` or the equivalent, plus `cmake`
    and `clang` if the build asks for them).
  - Optionally `keyutils`, for `keyctl`.

## ssh-agent safety

`SshAgentBackend`'s `Drop` removes **all** identities from the agent it talks to. Any test
run with `--all-features` or `--features online-ssh-agent` must therefore use a
throwaway agent. Never use the inherited `SSH_AUTH_SOCK`. Wrap those runs like this:

```bash
bash -c 'eval "$(ssh-agent -s)" >/dev/null; trap "ssh-agent -k >/dev/null" EXIT; exec_cmd_here'
```

The default feature set of `roughenough-keys` does not include `online-ssh-agent`, so the
KRS-only commands in step 3 are safe without the wrapper.

## Steps

Run these from the repository root with the branch checked out. Do not skip, ignore, or
disable a test to get a run to pass. Report every failure as you found it.

### 1. Compile and lint

```bash
cargo +nightly fmt --check
cargo check -p roughenough-keys --all-targets                         # default: online-linux-krs
cargo check -p roughenough-keys --all-targets --no-default-features   # KRS compiled out
cargo check -p roughenough-keys --all-targets --features online-ssh-agent
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

With `--no-default-features`, `BackendKind::Krs` must still parse. Opening it must then
fail with `BackendNotAvailable`. `open_krs_without_feature_is_not_available` checks this:

```bash
cargo test -p roughenough-keys --no-default-features seed::tests::open_krs
```

### 2. Server code that only runs on Linux

The same clippy run also compiles the Linux-only server code: the `recvmmsg`/`sendmmsg`
path in `crates/roughenough-server/src/network.rs` and the BPF filter in
`crates/roughenough-server/src/filter.rs`. Two dead methods were removed from
`network.rs`: `NetworkHandler::send_response` and its manual `Debug` impl. Confirm that
nothing Linux-only still referred to them. For the BPF filter itself, see
`doc/BPF-FILTER.md`.

### 3. KRS unit tests

```bash
cargo test -p roughenough-keys seed::linuxkrs -- --nocapture
```

Expect these six tests to pass. The test logs should show "Cleared keyring on worker
thread shutdown" and "Worker thread shut down cleanly".

| Test | What it checks |
|---|---|
| `new_with_seed_succeeds` | Construction stores the seed. |
| `read_what_we_stored_roundtrip` | The stored bytes read back intact through the worker. |
| `confirm_drop_clears_the_seed_key` | `Drop` clears and joins the worker; a new backend reads its own seed. |
| `sign_verify_roundtrip` | Signatures verify against `public_key()`, so the caller-side derivation matches the worker-side signing key. |
| `concurrent_access_from_multiple_threads` | `sign` from 5 threads behind a mutex. |
| `init_on_thread_1_then_ops_from_thread_2` | The backend moves across threads and keeps working. |

Run the module tests 20 times to shake out ordering problems in the channel and
`Drop`/join handshake. Any hang is a bug.

```bash
for i in $(seq 20); do cargo test -q -p roughenough-keys seed::linuxkrs || break; done
```

### 4. Full test suites

```bash
cargo test                                                   # default members, default features
bash -c 'eval "$(ssh-agent -s)" >/dev/null; trap "ssh-agent -k >/dev/null" EXIT; cargo test --workspace --all-features'
cargo test -p roughenough-server --test alloc_tests
cargo build && cargo build --release && target/debug/roughenough_integration_test
```

Expect no failures and no tests ignored beyond the ones the macOS run ignored (3 with
`--all-features`). Linux adds the KRS, mmsg, and BPF filter tests, so the pass counts
will be higher than on macOS.

### 5. Negative test: keyring unavailable

This runs inside a container with the **default** seccomp profile, so that keyring
syscalls fail:

```bash
docker run --rm -v "$PWD":/src -w /src rust:latest \
  cargo test -p roughenough-keys seed::linuxkrs::tests::new_with_seed_succeeds
```

- **Expected:** the test fails promptly. The panic message contains `WorkerDisconnect`,
  and the log contains "Failed to create thread-specific keyring".
- **Wrong:** a hang, a panic from inside the worker thread, or a pass. If it passes,
  check whether the runtime's seccomp profile allows keyctl.

This is the one test here that is expected to fail. Do not change the test to make it pass.

In the same container, the server should exit with status 1 and log
`opening 'krs' seed backend: KRS worker thread disconnected unexpectedly`:

```bash
cargo run --bin roughenough_server -- --seed-backend krs --insecure-zero-seed
```

Without Docker or Podman, a transient systemd user service can apply the same restriction.
Docker's default profile fails these syscalls with `EPERM`, so set that errno too; the
default action kills the process with `SIGSYS` instead. Build first, then run the binaries
directly, so that cargo itself does not run under the filter:

```bash
cargo test -p roughenough-keys --no-run   # prints the test binary path
cargo build
deny_keyring() {
  systemd-run --user --quiet --wait --pipe --collect -p WorkingDirectory="$PWD" \
    -p "SystemCallFilter=~add_key keyctl request_key" -p SystemCallErrorNumber=EPERM \
    -E RUST_LOG=debug "$@"
}
deny_keyring "$PWD"/target/debug/deps/roughenough_keys-<hash> \
  seed::linuxkrs::tests::new_with_seed_succeeds --nocapture
deny_keyring "$PWD"/target/debug/roughenough_server --seed-backend krs --insecure-zero-seed
```

`systemd-run --wait` exits with the service's status. As a control, run the test binary
without the two `-p` filter options; the test should then pass.

### 6. End to end with the server (VM, not a default container)

```bash
cargo build
target/debug/roughenough_server --seed-backend memory --insecure-zero-seed -i 127.0.0.1 -p 5319 &
# note the "Long term public key:" log line, then stop it
kill %1

target/debug/roughenough_server --seed-backend krs --insecure-zero-seed -i 127.0.0.1 -p 5319 -v &
```

- **Public key:** the `krs` run must log the same long-term public key as the `memory`
  run. Both derive from the all-zero seed.
- **Backend log:** the log must show "Opened 'krs' seed backend". Every worker thread signs
  its online key with the backend at startup, so this also exercises `sign` from several
  threads.

Query the server with the logged key. The log prints it as `PUBK(<hex>)`; pass only the
hex part:

```bash
target/debug/roughenough_client 127.0.0.1 5319 -k <public-key> -n 5
target/debug/roughenough_client 127.0.0.1 5319 -k <public-key> -P both
```

Both must print a time with no validation errors.

While the server runs, check from another shell as the same user:

```bash
grep roughenough-seed /proc/keys
```

This should print nothing, because the key grants permissions to its possessor (the
worker thread) only. If it shows up, report it.

Stop the server with `kill -INT %1`. It should log "Server finished" and exit 0. Because
the run uses `-v`, the log should then show "Cleared keyring on worker thread shutdown"
when the backend drops at the end of `main`.

## Reporting

Report to the maintainer:

- the exact commands you ran;
- the kernel version (`uname -r`) and the distro;
- pass and ignore counts for each suite;
- the result of each check above, including the logged public keys from step 6.

Do not commit fixes, rewrite history, or push unless the maintainer asks. If they ask for
a fix, follow the repository style: one logical statement per line, and comments that
explain why, not what.
