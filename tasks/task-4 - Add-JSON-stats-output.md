---
id: task-4
title: Add JSON stats output
status: Done
assignee: []
created_date: '2025-07-20'
updated_date: '2025-07-20'
labels: []
dependencies: []
---

# task-4 - Add JSON stats output

## Description

Enable the Roughtime server to write statistics to a JSON file at each reporting interval. This provides a simple, file-based mechanism for external monitoring tools to consume server metrics without requiring shared memory or network connections.

## Acceptance Criteria

- [x] Server writes stats to a new JSON file when --stats-path is specified
- [x] JSON output includes timestamp, per-worker stats, and aggregate totals
- [x] File writes are atomic (write to temp file, then rename) to prevent partial reads
- [x] JSON file is updated at the same interval as log output (stats_interval)
- [x] A new file is created each interval, following pattern `roughenough-stats-YYYYMMDD-hhmmss.json`
- [x] Feature works on Linux and macOS
- [x] No JSON file is created when --stats-path is not specified
- [x] JSON output preserves all existing stats information from log output
- [x] Server continues to function normally if JSON file write fails
- [x] If --stats-path is specified, at startup the server checks that the directory exists and is writable
- [x] Write a client PoC that watches the --stats-path directory, reads new files as they appear, and prints 
      the updates to the screen.

## Implementation Plan

1. Add --stats-path CLI argument to server args
2. Create JSON serializable data structures for stats
3. Implement atomic file writing with timestamp pattern
4. Integrate JSON writing into existing stats reporting
5. Add startup directory validation
6. Handle write failures gracefully
7. Test on Linux and macOS  
8. Create client PoC example

## Implementation Notes

The implementation adds JSON stats output capability to the Roughenough server, enabling external monitoring tools to consume server metrics.

### Approach taken:
- Added `--stats-path` CLI argument to specify the directory for JSON stats output
- Extended existing stats structures with serde derives for JSON serialization
- Created `json_stats.rs` module containing `JsonStats` struct and atomic file writing logic
- Integrated JSON writing into `StatsAggregator::report_stats()` method
- Added startup validation to ensure stats directory exists and is writable

### Features implemented:
- **CLI argument**: `--stats-path` option with environment variable support (`ROUGHENOUGH_STATS_PATH`)
- **JSON structure**: Complete stats output including timestamp, duration, per-worker stats, and aggregated totals
- **Atomic writes**: Stats are written to `.tmp` file first, then atomically renamed
- **File naming**: Files follow pattern `roughenough-stats-YYYYMMDD-HHMMSS.json` using chrono formatting
- **Error handling**: Write failures are logged but don't affect server operation
- **Stats watcher example**: Created `examples/stats_watcher.rs` as proof-of-concept monitoring client

### Technical decisions:
- Used chrono for timestamp formatting after initially trying to avoid the dependency
- Added serde and serde_json dependencies to server crate
- Kept JSON writing logic separate in dedicated module for maintainability
- Preserved all existing stats fields in JSON output for compatibility
- Example client uses simple file polling approach suitable for demonstration

### Modified files:
- `crates/server/Cargo.toml` - Added chrono (with serde feature), serde, and serde_json dependencies
- `crates/server/src/args.rs` - Added `stats_path: Option<String>` field
- `crates/server/src/lib.rs` - Added `json_stats` module export
- `crates/server/src/main.rs` - Added stats directory validation at startup
- `crates/server/src/stats.rs` - Added Serialize/Deserialize derives to stats structs
- `crates/server/src/stats_aggregator.rs` - Added JSON writing to report_stats method
- `crates/server/src/json_stats.rs` - New module for JSON stats output
- `crates/server/examples/stats_watcher.rs` - New example client for monitoring stats

The implementation successfully meets all acceptance criteria and provides a clean, extensible foundation for server metrics monitoring.

