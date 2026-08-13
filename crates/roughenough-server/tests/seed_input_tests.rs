#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

const SEED_SENTINEL: &str = "abababababababababababababababababababababababababababababababab";
static NEXT_TEMP_DIR: AtomicUsize = AtomicUsize::new(0);

fn server_path() -> &'static str {
    env!("CARGO_BIN_EXE_roughenough_server")
}

fn seed_file() -> (std::path::PathBuf, std::path::PathBuf) {
    let suffix = NEXT_TEMP_DIR.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "roughenough-seed-input-test-{}-{suffix}",
        std::process::id(),
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir(&dir).unwrap();
    let path = dir.join("seed");
    fs::write(&path, format!("seed://{SEED_SENTINEL}\n")).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    (dir, path)
}

#[test]
fn verbose_startup_never_logs_seed_file_contents() {
    let (dir, seed_path) = seed_file();
    let missing_metrics_dir = dir.join("missing-metrics-directory");

    let output = Command::new(server_path())
        .arg("--seed-file")
        .arg(&seed_path)
        .arg("--metrics-output")
        .arg(&missing_metrics_dir)
        .arg("-v")
        .env_remove("ROUGHENOUGH_SEED")
        .env_remove("ROUGHENOUGH_SEED_FILE")
        .output()
        .unwrap();

    let logs = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!output.status.success());
    assert!(
        !logs.contains(SEED_SENTINEL),
        "seed appeared in logs: {logs}"
    );

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn legacy_seed_inputs_are_rejected_without_echoing_the_seed() {
    let cli_output = Command::new(server_path())
        .args(["--seed", SEED_SENTINEL])
        .env_remove("ROUGHENOUGH_SEED")
        .env_remove("ROUGHENOUGH_SEED_FILE")
        .output()
        .unwrap();
    let cli_error = String::from_utf8_lossy(&cli_output.stderr);
    assert!(!cli_output.status.success());
    assert!(!cli_error.contains(SEED_SENTINEL));

    let env_output = Command::new(server_path())
        .env("ROUGHENOUGH_SEED", SEED_SENTINEL)
        .env_remove("ROUGHENOUGH_SEED_FILE")
        .output()
        .unwrap();
    let env_error = String::from_utf8_lossy(&env_output.stderr);
    assert!(!env_output.status.success());
    assert!(env_error.contains("--seed-file"));
    assert!(!env_error.contains(SEED_SENTINEL));
}

#[test]
fn seed_file_path_can_come_from_environment() {
    let (dir, seed_path) = seed_file();
    let missing_metrics_dir = dir.join("missing-metrics-directory");

    let output = Command::new(server_path())
        .arg("--metrics-output")
        .arg(&missing_metrics_dir)
        .env("ROUGHENOUGH_SEED_FILE", &seed_path)
        .env_remove("ROUGHENOUGH_SEED")
        .output()
        .unwrap();

    let logs = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!output.status.success());
    assert!(logs.contains("metrics path"), "unexpected output: {logs}");
    assert!(!logs.contains(SEED_SENTINEL));

    fs::remove_dir_all(dir).unwrap();
}
