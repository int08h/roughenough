# task-7 - Repository Cleanup

## Description

Remove or properly configure files that are not appropriate for a public open-source repository. AI agent instruction files (CLAUDE.md, GEMINI.md) and local development artifacts should not be included in the public repository as they are project-specific tooling configurations.

## Acceptance Criteria

- [x] CLAUDE.md moved outside repository or added to .gitignore (AI agent instructions shouldn't be public)
- [x] GEMINI.md moved outside repository or added to .gitignore
- [x] .junie/ directory added to .gitignore (appears to be local tooling)
- [x] package.json and package-lock.json removed or documented (unclear why they exist in a Rust project)
- [x] .pants-ignore removed or documented

## Implementation Plan

1. Check current .gitignore to understand existing exclusions
2. Add CLAUDE.md and GEMINI.md to .gitignore (keep files in repo for local use but exclude from git)
3. Add .junie/ directory to .gitignore
4. Investigate package.json and package-lock.json - determine if they serve a purpose or should be removed
5. Investigate .pants-ignore - determine if it serves a purpose or should be removed
6. Update .gitignore with all necessary exclusions
7. Verify changes with git status

## Implementation Notes

### Approach
- Added AI instruction files and local tooling to .gitignore rather than deleting them, allowing local use while excluding from version control
- Investigated and removed files that served no purpose in this Rust project

### Files Modified
- .gitignore: Added exclusions for CLAUDE.md, GEMINI.md, and .junie/
- Deleted: package.json (empty, no purpose)
- Deleted: package-lock.json (empty, no dependencies)
- Deleted: .pants-ignore (Pants build tool config, not used in this Cargo-based Rust project)

### Technical Decisions
- Kept AI instruction files (CLAUDE.md, GEMINI.md) in the working directory but excluded from git, allowing developers to use AI assistance locally without polluting the public repository
- Removed npm files (package.json, package-lock.json) as they were empty and this is a Rust project with no JavaScript dependencies
- Removed .pants-ignore as it contained only a CVE ignore rule for RSA keys, but this project uses Cargo (not Pants) and Ed25519 keys (not RSA)
