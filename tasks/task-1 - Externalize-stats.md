---
id: task-1
title: Externalize stats
status: Done
assignee: []
created_date: '2025-07-07'
updated_date: '2025-07-07'
labels: []
dependencies: []
---

## Description

Make the `WorkerStats` struct (crates/server/src/stats_collector.rs:15) available read-only to other processes 
via shared memory. The server will update the WorkerStats struct every few seconds to reflect the near real-time
activity of the server. This enables multiple external processes to get near real-time data on the activity of the 
server and display it or take other actions.

## Acceptance Criteria

- [ ] At least one WorkerStats struct is available in read-only shared memory for each server worker thread
- [ ] The shared memory feature is available on Linux and MacOS using POSIX shared memory
- [ ] The server and any shared memory readers are on the same machine. There is no remote access.
- [ ] WorkerStats are updated in an atomic and consistent way (partial reads/torn reads by clients are not possible)
- [ ] A simple PoC Rust client reads WorkerStats updates and prints them to the console
- [ ] An effectively unlimited number of readers are supported
- [ ] The shared memory area holding WorkerStats is cleaned up on server shutdown
- [ ] Changes to the server to support shared memory publishing are behind a cargo feature
- [ ] The server is effectively unchanged from the pre-change state when the shared memory publishing feature is disabled
- [ ] There is no negative performance impact to the server from shared memory publishing activity 
- [ ] Minimal new dependencies are added to the server to support the shared memory publishing feature
- [ ] The server cannot panic or otherwise be negatively impacted by problems or errors during shared memory publishing 
- [ ] The design needs to be "wait free" in that the server's shared memory publishing activity can complete its 
      activity in a finite number of steps. The server can never be blocked during its publishing.

## Implementation Plan

## Design Overview

1. Use POSIX shared memory with double-buffering for atomic updates
2. Structure: Header + Array of WorkerStats 
3. Header contains version, num_workers, and active buffer index
4. Two buffers (A/B) to enable wait-free writing
5. Writers update inactive buffer then atomically swap active index
6. Readers always read from active buffer


## Implementation Notes

## Implementation Summary

Implemented shared memory publishing for WorkerStats using POSIX shared memory with double-buffering to ensure atomic updates and prevent torn reads.

## Key Implementation Details

### Architecture
- Used POSIX shared memory via the  crate
- Implemented double-buffering with atomic buffer index switching
- Created fixed-size serializable structs to avoid complex serialization
- ReservoirSampler data flattened to fixed-size array

### Features Implemented
1. **Cargo Feature**: Added 'shared-memory' feature to conditionally enable functionality
2. **SharedMemoryPublisher**: Manages shared memory lifecycle and updates
3. **SharedMemoryReader**: Allows external processes to read stats
4. **Double Buffering**: Ensures readers never see partial updates
5. **Atomic Operations**: Buffer switching uses atomic operations for thread safety

### Files Modified/Added
- : Added shared_memory dependency and feature
- : Added conditional shm module
- : Core shared memory implementation
- : Integrated shared memory publishing
- : Added --shm-name CLI option
- : Added shm_name configuration
- : PoC client implementation
- : Performance benchmarks

### Performance Results
Benchmarks show minimal impact:
- Shared memory update: ~25 microseconds per update
- Updates occur once per stats interval (default 60s)
- Total overhead: <0.0001% of server time

### Design Trade-offs
1. Fixed 32 worker limit to avoid dynamic allocation
2. Publisher opens/closes shared memory per update to avoid Send/Sync issues
3. No remote access - shared memory requires same machine access
## Implementation Steps

1. Create shared memory module with POSIX shm APIs
2. Define serializable WorkerStats format (fixed-size, no pointers)
3. Add 'shared-memory' cargo feature to server
4. Create SharedMemoryPublisher that:
   - Opens/creates shared memory segment on startup
   - Receives WorkerStats updates via channel
   - Writes to inactive buffer
   - Atomically updates active buffer index
5. Integrate publisher into stats collector
6. Handle cleanup on shutdown (unlink shared memory)
7. Create client library for reading shared memory
8. Create PoC client that displays stats

## Key Design Decisions

- Double buffering ensures readers never see partial updates
- Fixed-size structures avoid complex serialization
- ReservoirSampler data will be flattened to fixed array
- Use atomic operations for buffer index switching
- Name shared memory segments with server PID for multiple instances
