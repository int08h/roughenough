use std::io::{BufReader, Read};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

/// Start a server, run a client against it, and ensure the client exits cleanly.
/// This is a live end-to-end integration test to catch bugs missed by unit tests.
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

fn test_build_mode(build_mode: &str) -> bool {
    let server_path = format!("target/{build_mode}/server");
    let client_path = format!("target/{build_mode}/client");

    // Start the server
    println!("=== Starting server...");
    let mut server_process = match Command::new(server_path)
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
    let client_result = Command::new(client_path)
        // -k is the pubkey for test seed [0u8; 32]
        .args([
            "127.0.0.1",
            "2003",
            "-n",
            "50",
            "-k",
            "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29",
        ])
        .output();

    // Kill the server
    let _ = server_process.kill();
    let _ = server_process.wait();

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
