use std::io::{BufReader, Read};
use std::net::UdpSocket;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

fn pick_free_udp_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0")
        .expect("binding an ephemeral UDP port should succeed")
        .local_addr()
        .expect("bound socket has a local address")
        .port()
}

/// Start a server, run a client against it, and ensure the client exits cleanly.
fn main() {
    println!("=== Running end-to-end integration test...");

    for build_mode in ["debug", "release"] {
        println!("\n=== Testing {build_mode} ...");

        if !test_build_mode(build_mode) {
            eprintln!("=== {build_mode} test FAILED");
            std::process::exit(1);
        }

        println!("=== {build_mode} test PASSED");
    }

    println!("\n=== All end-to-end integration tests PASSED");
}

/// Negative test: with an empty --seed and no --insecure-zero-seed the server
/// must exit nonzero
fn test_seedless_server_refuses_to_start(server_path: &str) -> bool {
    println!("=== Starting server with no seed (expecting refusal)...");
    let port = pick_free_udp_port();
    let mut child = match Command::new(server_path)
        .args(["-p", &port.to_string()])
        .env_remove("ROUGHENOUGH_SEED")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(e) => {
            eprintln!("=== Failed to start server: {e}");
            return false;
        }
    };

    // The refusal happens during startup; poll briefly for exit
    let mut status = None;
    for _ in 0..30 {
        match child.try_wait() {
            Ok(Some(s)) => {
                status = Some(s);
                break;
            }
            Ok(None) => thread::sleep(Duration::from_millis(100)),
            Err(e) => {
                eprintln!("=== Error checking server status: {e}");
                let _ = child.kill();
                let _ = child.wait();
                return false;
            }
        }
    }

    let Some(status) = status else {
        eprintln!("=== Server with no seed kept running; it must refuse to start");
        let _ = child.kill();
        let _ = child.wait();
        return false;
    };

    if status.success() {
        eprintln!("=== Server with no seed exited zero; expected nonzero");
        return false;
    }

    let mut output = String::new();
    if let Some(mut stdout) = child.stdout.take() {
        let _ = stdout.read_to_string(&mut output);
    }
    if let Some(mut stderr) = child.stderr.take() {
        let _ = stderr.read_to_string(&mut output);
    }

    if !output.contains("no seed provided") {
        eprintln!("=== Expected 'no seed provided' error, got: {output}");
        return false;
    }

    println!("=== Server refused to start without a seed, as expected");
    true
}

fn test_build_mode(build_mode: &str) -> bool {
    let server_path = format!("target/{build_mode}/roughenough_server");
    let client_path = format!("target/{build_mode}/roughenough_client");

    if !test_seedless_server_refuses_to_start(&server_path) {
        return false;
    }

    let port = pick_free_udp_port();
    let port_str = port.to_string();
    println!("=== Starting server on port {port}...");
    let mut server_process = match Command::new(&server_path)
        .args(["-p", &port_str, "--insecure-zero-seed"])
        .env_remove("ROUGHENOUGH_SEED")
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
    {
        Ok(process) => process,
        Err(e) => {
            eprintln!("=== Failed to start server: {e}");
            return false;
        }
    };

    // Give the server time to start up
    thread::sleep(Duration::from_millis(200));

    // Check if server is still running
    match server_process.try_wait() {
        Ok(Some(status)) => {
            eprintln!("=== Server exited unexpectedly with status: {status}");
            if let Some(stderr) = server_process.stderr.take() {
                let mut stderr_content = String::new();
                BufReader::new(stderr)
                    .read_to_string(&mut stderr_content)
                    .unwrap();
                eprintln!("=== Server stderr: {stderr_content}");
            }
            if let Some(stdout) = server_process.stdout.take() {
                let mut stdout_content = String::new();
                BufReader::new(stdout)
                    .read_to_string(&mut stdout_content)
                    .unwrap();
                eprintln!("=== Server stdout: {stdout_content}");
            }
            return false;
        }
        Err(e) => {
            eprintln!("=== Error checking server status: {e}");
            return false;
        }
        Ok(None) => {
            // Server is still running, good
        }
    }

    // Run the client with multiple requests to test multi-batch behavior
    println!("=== Running client with 50 requests...");
    let client_result = Command::new(&client_path)
        // -k is the pubkey for test seed [0u8; 32]
        .args([
            "127.0.0.1",
            &port_str,
            "-n",
            "50",
            "-k",
            "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29",
        ])
        .output();

    // Version negotiation: the client offers RFC version 1, then both versions;
    // the server must answer either offer with a valid response
    for version_arg in ["1", "both"] {
        println!("=== Running client offering version '{version_arg}'...");
        let version_result = Command::new(&client_path)
            .args([
                "127.0.0.1",
                &port_str,
                "-P",
                version_arg,
                "-k",
                "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29",
            ])
            .output();

        match version_result {
            Ok(output) if output.status.success() => {
                println!("=== Client offering version '{version_arg}' succeeded");
            }
            Ok(output) => {
                eprintln!(
                    "=== Client offering version '{version_arg}' failed: {}",
                    output.status
                );
                eprintln!(
                    "=== Client stderr: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
                let _ = server_process.kill();
                let _ = server_process.wait();
                return false;
            }
            Err(e) => {
                eprintln!("=== Failed to run client: {e}");
                let _ = server_process.kill();
                let _ = server_process.wait();
                return false;
            }
        }
    }

    // Negative test: --set-clock without a public key must be rejected
    println!("=== Running client with --set-clock and no key (expecting clap error)...");
    let set_clock_result = Command::new(&client_path)
        .args(["127.0.0.1", &port_str, "-s"])
        .output();

    match set_clock_result {
        Ok(output) if output.status.success() => {
            eprintln!("=== Client with --set-clock and no key unexpectedly succeeded");
            let _ = server_process.kill();
            let _ = server_process.wait();
            return false;
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stderr.contains("the following required arguments were not provided")
                || !stderr.contains("--pub-key")
            {
                eprintln!("=== Expected clap error naming --pub-key, got: {stderr}");
                let _ = server_process.kill();
                let _ = server_process.wait();
                return false;
            }
            println!("=== Client with --set-clock and no key was rejected, as expected");
        }
        Err(e) => {
            eprintln!("=== Failed to run client: {e}");
            let _ = server_process.kill();
            let _ = server_process.wait();
            return false;
        }
    }

    // Negative test: a client committing to a different long-term key sends an
    // SRV the server does not hold; RFC 5.2 requires the server to ignore the
    // request, so the client must time out
    println!("=== Running client with wrong public key (expecting timeout)...");
    let wrong_key_result = Command::new(&client_path)
        .args([
            "127.0.0.1",
            &port_str,
            "-t",
            "1",
            "-k",
            "4242424242424242424242424242424242424242424242424242424242424242",
        ])
        .output();

    // Kill the server
    let _ = server_process.kill();
    let _ = server_process.wait();

    match wrong_key_result {
        Ok(output) if output.status.success() => {
            eprintln!("=== Client with wrong public key unexpectedly got a response");
            return false;
        }
        Ok(output) => {
            // The specific failure mode matters: the server ignores the
            // mismatched SRV commitment so the client must time out; a crash
            // or any other error must not pass this test
            let combined = format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            if !combined.contains("timeout waiting for server response") {
                eprintln!("=== Expected a server timeout, got: {combined}");
                return false;
            }
            println!("=== Client with wrong public key timed out, as expected");
        }
        Err(e) => {
            eprintln!("=== Failed to run client: {e}");
            return false;
        }
    }

    // Check client result
    match client_result {
        Ok(output) => {
            if output.status.success() {
                println!("=== Client completed successfully");
                true
            } else {
                eprintln!("=== Client failed with exit code: {}", output.status);
                eprintln!(
                    "=== Client stdout: {}",
                    String::from_utf8_lossy(&output.stdout)
                );
                eprintln!(
                    "=== Client stderr: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
                false
            }
        }
        Err(e) => {
            eprintln!("=== Failed to run client: {e}");
            false
        }
    }
}
