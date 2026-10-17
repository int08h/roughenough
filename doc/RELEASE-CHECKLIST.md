# Release Checklist

Use this checklist when preparing a new release of Roughenough for publication to crates.io.

## Pre-Release Preparation

### Code Quality

- [ ] All tests pass: `cargo test --workspace --all-features` (the ssh-agent tests need a throwaway agent;
      see CONTRIBUTING.md)
- [ ] All benchmarks run without errors: `cargo bench --workspace`
- [ ] No clippy warnings: `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- [ ] Code is formatted: `cargo +nightly fmt --check`
- [ ] Dependencies pass `cargo deny check`
- [ ] End-to-end tests pass:
  - [ ] `cargo build && cargo run --bin roughenough_integration_test`
  - [ ] `cargo build --release && cargo run --release --bin roughenough_integration_test`
- [ ] The CI Keys Feature Matrix job is green

### Documentation

- [ ] CHANGELOG.md updated with all changes since last release
- [ ] README.md is current and accurate
- [ ] All crate-level documentation reviewed and updated
- [ ] Doc comments are accurate and complete
- [ ] Code examples in documentation compile: `cargo test --doc --workspace --all-features`
- [ ] Generated docs look correct: `cargo doc --open --workspace`

### Version Management

- [ ] Version number follows the Versioning Policy at the bottom of CHANGELOG.md
- [ ] Version bumped in `Cargo.toml` `[workspace.package]` section
- [ ] The internal crate versions in root `[workspace.dependencies]` bumped to match
- [ ] Version consistent across all workspace crates
- [ ] CHANGELOG.md reflects the new version number
- [ ] Every breaking change is listed under `### Breaking` in the release's CHANGELOG section

### Metadata Verification

The publishable crates are `roughenough-protocol`, `roughenough-common`,
`roughenough-merkle`, `roughenough-keys`, `roughenough-server`, and
`roughenough-client`. The `roughenough-integration-test` and
`roughenough-reporting-server` crates are marked `publish = false` and are
never published.

For each publishable crate (protocol, common, merkle, keys, server, client), verify `Cargo.toml` contains:

- [ ] Correct `description`
- [ ] Appropriate `keywords` (max 5)
- [ ] Relevant `categories`
- [ ] `readme` path is correct
- [ ] `repository` and `homepage` inherited from `[workspace.package]`, which has accurate URLs
- [ ] Feature flags documented (keys and client)

### License and Legal

- [ ] LICENSE-APACHE and LICENSE-MIT files are current
- [ ] `[workspace.package]` has `license = "Apache-2.0 OR MIT"` and every crate inherits it
- [ ] License files included in packages 
- [ ] No copyright violations in code or dependencies
- [ ] Third-party dependencies reviewed and acceptable

### Package Verification

For each publishable crate (protocol, common, merkle, keys, server, client):

- [ ] `cargo package -p <crate> --list` shows expected files and no unexpected ones
- [ ] Package size is reasonable (< 1 MiB)

Then for all of them at once:

- [ ] The dry run succeeds; it packages every crate and builds each package in isolation:
  ```bash
  cargo publish --workspace --dry-run --exclude roughenough-integration-test --exclude roughenough-reporting-server
  ```

### Git Repository

- [ ] Git working directory is clean
- [ ] All changes committed to version control
- [ ] Branch is up to date with main/master
- [ ] No local-only commits (push first if needed)
- [ ] No merge conflicts

## Publication Process

### Publishing to crates.io

- [ ] Logged in to crates.io: `cargo login`
- [ ] Publish every publishable crate. Cargo (1.90 or newer) publishes them in dependency order and waits
      for each crate to reach the index before publishing the next:
  ```bash
  cargo publish --workspace --exclude roughenough-integration-test --exclude roughenough-reporting-server
  ```

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

### Git Tagging and GitHub Release

Tags have no `v` prefix (`2.1.0`, `2.2.0`).

- [ ] Create annotated tag: `git tag -a X.Y.Z -m "Release X.Y.Z"`
- [ ] Push tag to origin: `git push origin X.Y.Z`
- [ ] Pushing the tag runs `.github/workflows/release.yml` (dist), which builds the release artifacts and
      creates the GitHub Release. Verify the dist-created release and its notes against CHANGELOG.md

### Version Bump for Development

- [ ] Bump `[workspace.package] version` and the internal crate versions in `[workspace.dependencies]` to
      the next development version
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
   cargo yank --vers X.Y.Z roughenough-protocol
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
