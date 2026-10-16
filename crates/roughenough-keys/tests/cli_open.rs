//! `roughenough_keys open` must exit non-zero, and print no seed, whenever it cannot decrypt the
//! envelope. None of these cases reach a KMS, so no network access is needed.

use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

const ENVELOPE: &str =
    r#"{"key_id":"aws-kms://arn:aws:kms:us-east-1:1:key/x","seed_ct":"AQID","dek_ct":"BAUG"}"#;

static NEXT_TEMP_FILE: AtomicUsize = AtomicUsize::new(0);

/// Removes the envelope file when the test ends, pass or fail
struct TempFile(PathBuf);

impl TempFile {
    fn with_contents(contents: &str) -> Self {
        let suffix = NEXT_TEMP_FILE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "roughenough-keys-cli-open-{}-{suffix}.json",
            std::process::id()
        ));
        std::fs::write(&path, contents).unwrap();
        TempFile(path)
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// The tool's log lines also go to stdout, so look for the seed itself: 32 bytes as 64 hex chars
fn printed_a_seed(stdout: &[u8]) -> bool {
    let mut run = 0;
    for b in stdout {
        run = if b.is_ascii_hexdigit() { run + 1 } else { 0 };
        if run >= 64 {
            return true;
        }
    }
    false
}

fn run_open(extra_args: &[&str]) -> Output {
    let envelope = TempFile::with_contents(ENVELOPE);
    Command::new(env!("CARGO_BIN_EXE_roughenough_keys"))
        .arg("open")
        .arg("-i")
        .arg(&envelope.0)
        .args(extra_args)
        .output()
        .unwrap()
}

#[cfg(any(feature = "longterm-aws", feature = "longterm-gcp"))]
#[test]
fn open_with_unprefixed_key_override_fails_without_output() {
    let output = run_open(&["--key", "arn:aws:kms:us-east-1:1:key/x"]);

    assert!(
        !output.status.success(),
        "open succeeded with an unusable key id; stdout: {:?}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        !printed_a_seed(&output.stdout),
        "open printed a seed it did not decrypt: {:?}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[cfg(not(any(feature = "longterm-aws", feature = "longterm-gcp")))]
#[test]
fn open_without_kms_features_fails() {
    let output = run_open(&[]);

    assert!(
        !output.status.success(),
        "open succeeded without any KMS backend; stdout: {:?}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        !printed_a_seed(&output.stdout),
        "open printed a seed it did not decrypt: {:?}",
        String::from_utf8_lossy(&output.stdout)
    );
}
