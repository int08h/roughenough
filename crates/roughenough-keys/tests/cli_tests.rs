//! Exit codes and output of the `roughenough_keys` binary. Every failure must exit non-zero
//! and print no seed. None of these cases reach a cloud service, so no network access is needed.

use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

#[cfg(not(feature = "longterm-aws"))]
const KMS_ENVELOPE: &str =
    r#"{"key_id":"aws-kms://arn:aws:kms:us-east-1:1:key/x","seed_ct":"AQID","dek_ct":"BAUG"}"#;

static NEXT_TEMP_FILE: AtomicUsize = AtomicUsize::new(0);

/// Removes the file when the test ends, pass or fail
struct TempFile(PathBuf);

impl TempFile {
    fn with_contents(contents: impl AsRef<[u8]>) -> Self {
        Self::with_mode(contents, 0o600)
    }

    fn with_mode(contents: impl AsRef<[u8]>, mode: u32) -> Self {
        let suffix = NEXT_TEMP_FILE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "roughenough-keys-cli-{}-{suffix}",
            std::process::id()
        ));
        std::fs::write(&path, contents).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        }
        #[cfg(not(unix))]
        let _ = mode;
        TempFile(path)
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_roughenough_keys"))
        .args(args)
        .output()
        .unwrap()
}

fn run_with_input(subcommand: &str, input: &TempFile, extra_args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_roughenough_keys"))
        .arg(subcommand)
        .arg("-i")
        .arg(&input.0)
        .args(extra_args)
        .output()
        .unwrap()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// Exited non-zero with nothing on stdout, which carries only seeds and seed files
fn assert_failed_silently(output: &Output) {
    assert!(
        !output.status.success(),
        "expected failure; stdout: {:?}, stderr: {:?}",
        String::from_utf8_lossy(&output.stdout),
        stderr(output)
    );
    assert!(
        output.stdout.is_empty(),
        "printed output on failure: {:?}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn generate_requires_resource() {
    let output = run(&["generate"]);
    assert_eq!(output.status.code(), Some(2), "stderr: {}", stderr(&output));
    assert!(output.stdout.is_empty());
}

#[test]
fn generate_rejects_plain_resource() {
    let output = run(&["generate", "--resource", "seed://00"]);
    assert_failed_silently(&output);
}

#[test]
fn protect_rejects_plain_resource() {
    let input = TempFile::with_contents("ab".repeat(32));
    let output = run_with_input("protect", &input, &["--resource", "seed://00"]);
    assert_failed_silently(&output);
}

#[cfg(unix)]
#[test]
fn protect_rejects_world_readable_input() {
    let input = TempFile::with_mode("ab".repeat(32), 0o644);
    let output = run_with_input(
        "protect",
        &input,
        &[
            "--resource",
            "aws-secret://arn:aws:secretsmanager:us-east-1:1:secret:x",
        ],
    );
    assert_failed_silently(&output);
    assert!(
        stderr(&output).contains("group or other"),
        "stderr: {}",
        stderr(&output)
    );
}

#[test]
fn protect_rejects_raw_binary_input() {
    let raw: Vec<u8> = (0x80..0xa0).collect();
    let input = TempFile::with_contents(raw);
    let output = run_with_input(
        "protect",
        &input,
        &[
            "--resource",
            "aws-secret://arn:aws:secretsmanager:us-east-1:1:secret:x",
        ],
    );
    assert_failed_silently(&output);
    assert!(
        stderr(&output).contains("UTF-8"),
        "stderr: {}",
        stderr(&output)
    );
}

#[test]
fn recover_plain_seed_file() {
    let input = TempFile::with_contents(format!("seed://{}\n", "ab".repeat(32)));
    let output = run_with_input("recover", &input, &[]);

    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(stdout, format!("seed://{}\n", "ab".repeat(32)));
}

#[test]
fn recover_writes_output_file() {
    let input = TempFile::with_contents("AB".repeat(32));
    let target = TempFile::with_contents("");
    std::fs::remove_file(&target.0).unwrap();

    let output = run_with_input("recover", &input, &["-o", target.0.to_str().unwrap()]);

    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(output.stdout.is_empty());
    let contents = std::fs::read_to_string(&target.0).unwrap();
    assert_eq!(contents, format!("seed://{}\n", "ab".repeat(32)));
}

#[test]
fn recover_failure_leaves_no_output_file() {
    let input = TempFile::with_contents("vault://x");
    let target = TempFile::with_contents("");
    std::fs::remove_file(&target.0).unwrap();

    let output = run_with_input("recover", &input, &["-o", target.0.to_str().unwrap()]);

    assert_failed_silently(&output);
    assert!(!target.0.exists());
}

#[test]
fn existing_output_file_is_kept() {
    let input = TempFile::with_contents("ab".repeat(32));
    let target = TempFile::with_contents("keep me");

    let output = run_with_input("recover", &input, &["-o", target.0.to_str().unwrap()]);

    assert_failed_silently(&output);
    let contents = std::fs::read_to_string(&target.0).unwrap();
    assert_eq!(contents, "keep me");
}

#[test]
fn recover_unknown_scheme_fails() {
    let input = TempFile::with_contents("vault://x");
    let output = run_with_input("recover", &input, &[]);
    assert_failed_silently(&output);
}

#[test]
fn recover_json_with_unknown_key_scheme_fails() {
    let input =
        TempFile::with_contents(r#"{"key_id":"vault://x","seed_ct":"AQID","dek_ct":"BAUG"}"#);
    let output = run_with_input("recover", &input, &[]);
    assert_failed_silently(&output);
}

/// A key id without a scheme prefix, and no envelope scheme to inherit, routes nowhere
#[test]
fn recover_with_unprefixed_key_override_fails_without_output() {
    let input =
        TempFile::with_contents(r#"{"key_id":"vault://x","seed_ct":"AQID","dek_ct":"BAUG"}"#);
    let output = run_with_input(
        "recover",
        &input,
        &["--key", "arn:aws:kms:us-east-1:1:key/x"],
    );
    assert_failed_silently(&output);
}

#[test]
fn recover_rejects_key_override_for_plain_seed() {
    let input = TempFile::with_contents("ab".repeat(32));
    let output = run_with_input(
        "recover",
        &input,
        &["--key", "aws-kms://arn:aws:kms:us-east-1:1:key/x"],
    );
    assert_failed_silently(&output);
}

#[cfg(not(any(feature = "longterm-aws", feature = "longterm-gcp")))]
#[test]
fn recover_without_kms_features_fails() {
    let input = TempFile::with_contents(KMS_ENVELOPE);
    let output = run_with_input("recover", &input, &[]);
    assert_failed_silently(&output);
}

#[cfg(not(feature = "longterm-aws"))]
#[test]
fn recover_aws_without_feature_names_feature() {
    use data_encoding::BASE64URL;

    let input = TempFile::with_contents(format!(
        "aws-kms://{}",
        BASE64URL.encode(KMS_ENVELOPE.as_bytes())
    ));
    let output = run_with_input("recover", &input, &[]);

    assert_failed_silently(&output);
    assert!(
        stderr(&output).contains("longterm-aws"),
        "stderr: {}",
        stderr(&output)
    );
}
