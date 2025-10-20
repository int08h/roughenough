# Release Checklist

Use this checklist when preparing a new release of Roughenough for publication to crates.io.

## Pre-Release Preparation

### Code Quality

- [ ] All tests pass: `cargo test --workspace`
- [ ] All benchmarks run without errors: `cargo bench --workspace`
- [ ] No clippy warnings: `cargo clippy --workspace --all-features`
- [ ] Code is formatted: `cargo +nightly fmt --check`
- [ ] Integration tests pass: `target/debug/roughenough_integration_test`
- [ ] Optional features build correctly:
  - [ ] `cargo build -p keys --features online-linux-krs`
  - [ ] `cargo build -p keys --features online-ssh-agent`
  - [ ] `cargo build -p keys --features online-pkcs11`
  - [ ] `cargo build -p keys --features longterm-aws-kms`
  - [ ] `cargo build -p keys --features longterm-gcp-kms`
  - [ ] `cargo build -p keys --features longterm-aws-secret-manager`
  - [ ] `cargo build -p keys --features longterm-gcp-secret-manager`
  - [ ] `cargo build -p client --features reporting`

### Documentation

- [ ] CHANGELOG.md updated with all changes since last release
- [ ] README.md is current and accurate
- [ ] All crate-level documentation reviewed and updated
- [ ] Doc comments are accurate and complete
- [ ] Code examples in documentation compile: `cargo test --doc`
- [ ] Generated docs look correct: `cargo doc --open --workspace`

### Version Management

- [ ] Version number follows semantic versioning (MAJOR.MINOR.PATCH)
- [ ] Version bumped in `Cargo.toml` `[workspace.package]` section
- [ ] Version consistent across all workspace crates
- [ ] CHANGELOG.md reflects the new version number
- [ ] No breaking changes in PATCH releases
- [ ] Breaking changes documented in CHANGELOG for MAJOR releases

### Metadata Verification

For each publishable crate, verify `Cargo.toml` contains:

- [ ] **protocol**
  - [ ] Correct `description`
  - [ ] Appropriate `keywords` (max 5)
  - [ ] Relevant `categories`
  - [ ] `readme` path is correct
  - [ ] `repository` URL is accurate
  - [ ] `homepage` URL is accurate

- [ ] **common**
  - [ ] Correct `description`
  - [ ] Appropriate `keywords` (max 5)
  - [ ] Relevant `categories`
  - [ ] `readme` path is correct
  - [ ] `repository` URL is accurate
  - [ ] `homepage` URL is accurate

- [ ] **merkle**
  - [ ] Correct `description`
  - [ ] Appropriate `keywords` (max 5)
  - [ ] Relevant `categories`
  - [ ] `readme` path is correct
  - [ ] `repository` URL is accurate
  - [ ] `homepage` URL is accurate

- [ ] **keys**
  - [ ] Correct `description`
  - [ ] Appropriate `keywords` (max 5)
  - [ ] Relevant `categories`
  - [ ] `readme` path is correct
  - [ ] `repository` URL is accurate
  - [ ] `homepage` URL is accurate
  - [ ] Feature flags documented

- [ ] **server**
  - [ ] Correct `description`
  - [ ] Appropriate `keywords` (max 5)
  - [ ] Relevant `categories`
  - [ ] `readme` path is correct
  - [ ] `repository` URL is accurate
  - [ ] `homepage` URL is accurate

- [ ] **client**
  - [ ] Correct `description`
  - [ ] Appropriate `keywords` (max 5)
  - [ ] Relevant `categories`
  - [ ] `readme` path is correct
  - [ ] `repository` URL is accurate
  - [ ] `homepage` URL is accurate
  - [ ] Feature flags documented

### License and Legal

- [ ] LICENSE-APACHE and LICENSE-MIT files are current
- [ ] All crates have `license = "Apache-2.0 OR MIT"` in Cargo.toml
- [ ] License files included in packages (see PUBLICATION.md)
- [ ] No copyright violations in code or dependencies
- [ ] Third-party dependencies reviewed and acceptable

### Package Verification

For each crate (in dependency order):

- [ ] **protocol**
  - [ ] `cargo package --list` shows expected files
  - [ ] Package size is reasonable (< 1 MiB)
  - [ ] `cargo publish --dry-run` succeeds
  - [ ] Package builds in isolation
  - [ ] No unexpected files included

- [ ] **common**
  - [ ] `cargo package --list` shows expected files
  - [ ] Package size is reasonable (< 1 MiB)
  - [ ] `cargo publish --dry-run` succeeds
  - [ ] Package builds in isolation
  - [ ] No unexpected files included

- [ ] **merkle**
  - [ ] `cargo package --list` shows expected files
  - [ ] Package size is reasonable (< 1 MiB)
  - [ ] `cargo publish --dry-run` succeeds
  - [ ] Package builds in isolation
  - [ ] No unexpected files included

- [ ] **keys**
  - [ ] `cargo package --list` shows expected files
  - [ ] Package size is reasonable (< 1 MiB)
  - [ ] `cargo publish --dry-run` succeeds
  - [ ] Package builds in isolation
  - [ ] No unexpected files included

- [ ] **server**
  - [ ] `cargo package --list` shows expected files
  - [ ] Package size is reasonable (< 1 MiB)
  - [ ] `cargo publish --dry-run` succeeds
  - [ ] Package builds in isolation
  - [ ] No unexpected files included

- [ ] **client**
  - [ ] `cargo package --list` shows expected files
  - [ ] Package size is reasonable (< 1 MiB)
  - [ ] `cargo publish --dry-run` succeeds
  - [ ] Package builds in isolation
  - [ ] No unexpected files included

### Git Repository

- [ ] Git working directory is clean
- [ ] All changes committed to version control
- [ ] Branch is up to date with main/master
- [ ] No local-only commits (push first if needed)
- [ ] No merge conflicts

## Publication Process

### Publishing to crates.io

Follow the publication order in PUBLICATION.md:

- [ ] Logged in to crates.io: `cargo login`
- [ ] Publish **protocol**: `cargo publish -p roughenough-protocol`
- [ ] Wait 30 seconds for crates.io to propagate
- [ ] Publish **common**: `cargo publish -p roughenough-common`
- [ ] Publish **merkle**: `cargo publish -p roughenough-merkle`
- [ ] Wait 30 seconds for crates.io to propagate
- [ ] Publish **keys**: `cargo publish -p roughenough-keys`
- [ ] Wait 30 seconds for crates.io to propagate
- [ ] Publish **server**: `cargo publish -p roughenough-server`
- [ ] Wait 30 seconds for crates.io to propagate
- [ ] Publish **client**: `cargo publish -p roughenough-client`

### Verify Publication

- [ ] All crates visible on crates.io
- [ ] Documentation generated correctly on docs.rs
- [ ] Test installing from crates.io in a clean directory:
  ```bash
  cargo new test-install
  cd test-install
  cargo add roughenough-client
  cargo build
  ```

## Post-Release

### Git Tagging

- [ ] Create annotated tag: `git tag -a v2.0.0 -m "Release version 2.0.0"`
- [ ] Push tag to origin: `git push origin v2.0.0`
- [ ] Verify tag appears in GitHub

### GitHub Release

- [ ] Create GitHub release for the tag
- [ ] Copy relevant CHANGELOG.md section to release notes
- [ ] Mark as latest release (or pre-release if appropriate)
- [ ] Attach any relevant artifacts (optional)

### Version Bump for Development

- [ ] Bump version to next development version in `Cargo.toml`
  - Example: If released 2.0.0, bump to 2.0.1 or 2.1.0-dev
- [ ] Commit version bump: `git commit -am "Bump version for development"`
- [ ] Push to origin

### Communication

- [ ] Update project README.md with new version if needed
- [ ] Announce release (if appropriate):
  - [ ] GitHub Discussions
  - [ ] Social media
  - [ ] Mailing lists
  - [ ] Community forums

### Monitoring

- [ ] Monitor crates.io downloads (first few days)
- [ ] Watch for issues reported by early adopters
- [ ] Monitor docs.rs build status
- [ ] Check GitHub issues for new bug reports

## Rollback Procedure

If critical issues are discovered after publication:

1. **Yank the problematic version** (does not delete, just prevents new downloads):
   ```bash
   cargo yank --vers 2.0.0 roughenough-protocol
   ```

2. **Fix the issue** in a new version

3. **Publish the fixed version** following this checklist

4. **Announce the issue** and recommend upgrading

Note: Yanking should only be used for serious issues (security, data corruption, etc.)

## Notes

- Crates.io does not allow deleting or overwriting published versions
- Once published, a version number is permanent
- Yanking prevents new users from downloading but doesn't affect existing Cargo.lock files
- Always test dry-run before actual publication
- Keep a local backup/tag before publishing
- Publication is irreversible - double-check everything!

## References

- [Semantic Versioning](https://semver.org/)
- [Cargo Publishing](https://doc.rust-lang.org/cargo/reference/publishing.html)
- [Crates.io Policies](https://crates.io/policies)
- Internal: See PUBLICATION.md for detailed publication instructions
