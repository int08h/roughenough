#![forbid(unsafe_code)]
//! End-to-end smoke test: runs the server and client binaries built alongside this one
//! (same target directory and profile) against each other over loopback UDP.

use std::net::UdpSocket;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use std::{fs, io, thread};

/// Public key for the all-zero test seed
const ZERO_SEED_PUBKEY: &str = "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29";
const UNKNOWN_PUBKEY: &str = "4242424242424242424242424242424242424242424242424242424242424242";
const TIMEOUT_MSG: &str = "timeout waiting for server response";

#[derive(Debug)]
enum Expect {
    Success,
    Timeout,
}

struct Case {
    name: &'static str,
    args: &'static [&'static str],
    expect: Expect,
}

const CASES: &[Case] = &[
    Case {
        name: "50 requests across batches",
        args: &["-n", "50", "-k", ZERO_SEED_PUBKEY],
        expect: Expect::Success,
    },
    Case {
        name: "offers version 1",
        args: &["-P", "1", "-k", ZERO_SEED_PUBKEY],
        expect: Expect::Success,
    },
    Case {
        name: "offers version 1 and draft",
        args: &["-P", "both", "-k", ZERO_SEED_PUBKEY],
        expect: Expect::Success,
    },
    // RFC 5.1.1: no common version, so the server ignores the request
    Case {
        name: "offers only draft",
        args: &["-P", "19", "-t", "1", "-k", ZERO_SEED_PUBKEY],
        expect: Expect::Timeout,
    },
    // RFC 5.2: SRV commits to a key the server does not hold
    Case {
        name: "unknown public key",
        args: &["-t", "1", "-k", UNKNOWN_PUBKEY],
        expect: Expect::Timeout,
    },
];

fn pick_free_udp_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0")
        .expect("binding an ephemeral UDP port should succeed")
        .local_addr()
        .expect("bound socket has a local address")
        .port()
}

struct TestSeedFile {
    path: PathBuf,
}

impl TestSeedFile {
    fn new(label: &str) -> io::Result<Self> {
        let path = std::env::temp_dir().join(format!(
            "roughenough-integration-{}-{label}.seed",
            std::process::id()
        ));
        fs::write(&path, format!("seed://{}\n", "00".repeat(32)))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        }
        Ok(Self { path })
    }
}

impl Drop for TestSeedFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

struct ServerGuard(Child);

impl Drop for ServerGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn main() {
    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    if let Err(e) = run(profile) {
        eprintln!("=== {profile} end-to-end test FAILED: {e}");
        std::process::exit(1);
    }
    println!("=== {profile} end-to-end test PASSED");
}

fn run(profile: &str) -> Result<(), String> {
    let server_path = sibling_binary("roughenough_server")?;
    let client_path = sibling_binary("roughenough_client")?;

    let seed_file =
        TestSeedFile::new(profile).map_err(|e| format!("creating the test seed file: {e}"))?;
    let port = pick_free_udp_port().to_string();

    println!("=== Starting server on port {port}...");
    let child = Command::new(&server_path)
        .args(["-p", &port, "--seed-file"])
        .arg(&seed_file.path)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| format!("starting {}: {e}", server_path.display()))?;
    let mut server = ServerGuard(child);

    thread::sleep(Duration::from_millis(200));
    let early_exit = server
        .0
        .try_wait()
        .map_err(|e| format!("checking server status: {e}"))?;
    if let Some(status) = early_exit {
        return Err(format!("server exited during startup with {status}"));
    }

    for case in CASES {
        run_case(&client_path, &port, case)?;
    }
    Ok(())
}

/// Locating the binaries next to this one follows the build profile and `CARGO_TARGET_DIR`
fn sibling_binary(name: &str) -> Result<PathBuf, String> {
    let exe = std::env::current_exe().map_err(|e| format!("locating this binary: {e}"))?;
    let dir = exe.parent().ok_or("this binary has no parent directory")?;
    let path = dir.join(format!("{name}{}", std::env::consts::EXE_SUFFIX));
    if !path.exists() {
        return Err(format!(
            "{} not found; run `cargo build` (or `cargo build --release`) first",
            path.display()
        ));
    }
    Ok(path)
}

fn run_case(client_path: &Path, port: &str, case: &Case) -> Result<(), String> {
    let output = Command::new(client_path)
        .args(["127.0.0.1", port])
        .args(case.args)
        .output()
        .map_err(|e| format!("{}: running the client: {e}", case.name))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    let passed = match case.expect {
        Expect::Success => output.status.success(),
        Expect::Timeout => {
            let timed_out = stdout.contains(TIMEOUT_MSG) || stderr.contains(TIMEOUT_MSG);
            !output.status.success() && timed_out
        }
    };
    if !passed {
        return Err(format!(
            "{}: expected {:?}, client exited with {}\n--- client stdout\n{stdout}\n--- client stderr\n{stderr}",
            case.name, case.expect, output.status
        ));
    }

    println!("=== {} ok", case.name);
    Ok(())
}
