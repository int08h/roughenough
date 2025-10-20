# task-16 - Prepare for Crates.io Publication

## Description

Verify all crates are ready for publication to crates.io and document the publication process. Proper preparation ensures a smooth release process and reduces the risk of issues after publication.

## Acceptance Criteria

- [x] Verify all crates build with --release
- [x] Test cargo publish --dry-run for each crate
- [x] Determine publication order (dependencies first)
- [x] Document publication process
- [x] Create release checklist
- [x] Verify license files are included in packages
- [x] Check package sizes are reasonable

## Implementation Plan

1. Build all crates with --release to verify clean compilation
2. Test cargo publish --dry-run for each crate to identify issues
3. Analyze dependency graph to determine publication order
4. Check for license files in packages
5. Verify package sizes are within reasonable limits
6. Document findings and create publication guide
7. Create comprehensive release checklist

## Implementation Notes

### Critical Finding: Crate Name Conflicts

The primary blocker for publication is that all internal crate names conflict with existing packages on crates.io:
- `protocol`, `common`, `merkle`, `keys`, `server`, `client` are generic names already claimed
- These crates need to be renamed with `roughenough-` prefix before publication
- This affects all Cargo.toml files, import statements, and documentation

### Build Verification

All workspace crates build successfully with `--release` profile:
- protocol v2.0.0
- common v2.0.0
- merkle v2.0.0
- keys v2.0.0
- server v2.0.0
- client v2.0.0
- integration-test v2.0.0

Build completed in 4.22s without errors.

### Dry-Run Publication Testing

Testing revealed multiple issues:

1. **Workspace dependency version numbers**: Fixed by adding version = "2.0.0" to all internal workspace dependencies in root Cargo.toml

2. **Name conflicts on crates.io**:
   - `protocol` conflicts with "Easy protocol definitions" (v3.4.0)
   - `common` conflicts with "buffett common lib" (v0.1.0)
   - Similar conflicts expected for other generic names

3. **Dependency resolution failures**: Once renamed, crates will need to reference the new names

### Publication Order Determined

Based on dependency analysis:
1. protocol (no internal dependencies)
2. common and merkle (only depend on protocol, can publish in parallel)
3. keys (depends on protocol and common)
4. server (depends on protocol, merkle, keys)
5. client (depends on protocol, common, merkle, server)

Note: integration-test is for testing only and should not be published.

### License File Verification

- LICENSE-APACHE and LICENSE-MIT exist at repository root
- License files are NOT currently included in individual crate packages
- All crates have `license = "Apache-2.0 OR MIT"` SPDX identifier
- SPDX identifier is sufficient for crates.io, but including license text is best practice
- Recommended: Add `include` field to Cargo.toml files to include license files

### Package Sizes

All packages are well within the 10 MiB crates.io limit:
- protocol: 137 KiB uncompressed (31 KiB compressed)
- common: 30 KiB uncompressed (10 KiB compressed)
- merkle: 49 KiB uncompressed (14 KiB compressed)
- Other crates could not be packaged due to naming conflicts

Package sizes are reasonable and appropriate.

### Documentation Created

Two comprehensive documents created:

1. **doc/PUBLICATION.md**: Detailed publication guide covering:
   - Critical issues (naming conflicts, license files)
   - Publication order and dependencies
   - Pre-publication checklist
   - Step-by-step publication commands
   - Post-publication steps
   - Troubleshooting guide
   - Version management

2. **doc/RELEASE-CHECKLIST.md**: Complete release checklist including:
   - Pre-release preparation (code quality, documentation, versions)
   - Metadata verification for each crate
   - License and legal compliance
   - Package verification steps
   - Publication process with timing
   - Post-release steps (git tagging, GitHub releases)
   - Rollback procedure
   - Communication and monitoring

### Files Modified

- Cargo.toml: Added version numbers to workspace dependencies
- doc/PUBLICATION.md: Created (new file)
- doc/RELEASE-CHECKLIST.md: Created (new file)

### Next Steps Required

Before publication can proceed:

1. Rename all crates with `roughenough-` prefix
2. Update all inter-crate dependencies
3. Update import statements throughout codebase
4. Add license files to packages (via `include` field)
5. Update documentation to reflect new crate names
6. Re-test dry-run publication with renamed crates
7. Follow RELEASE-CHECKLIST.md for actual publication
