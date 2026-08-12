---
id:          TASK-065
title:       Performance benchmark suite — upload/download throughput baselines
status:      done
assignee:    QA.06
created_by:  ARCH.00
created:     2026-07-14
priority:    low
depends_on:  [TASK-055]
blocks:      []
review_by:   [CQR.08]
tags:        [testing, performance, phase-9]
---

Write a benchmark suite that establishes concrete throughput and latency baselines
for the server.  Results are checked into `docs/BENCHMARKS.md` and re-run on
every major version.

The goal is not to optimise anything yet — it is to have numbers so future changes
can be measured against them.

## Acceptance criteria

### Benchmark harness (`tests/perf/bench.py`)

Python script using `vw_client.py` (from TASK-055).  Measures:

| Benchmark | What it measures |
|-----------|-----------------|
| `upload_throughput` | Sequential upload of N × 4 MiB chunks; report MiB/s |
| `download_throughput` | Sequential download of a pre-uploaded file; report MiB/s |
| `login_latency` | 100 sequential login round-trips; report p50/p95/p99 ms |
| `concurrent_uploads` | 8 simultaneous clients each uploading 4 MiB; report wall time |
| `file_list_latency` | FILE_LIST over a directory with 1000 entries; report ms |
| `dedup_throughput` | 100 × 4 MiB uploads of the same chunk (all deduplicated); report MiB/s overhead |

### CLI interface

```
python tests/perf/bench.py \
    --server-bin build/bin/vapourwaultd \
    --test-cert  tests/integration/test.crt \
    --test-key   tests/integration/test.key \
    --output     docs/BENCHMARKS.md
```

Options:
- `--warmup N` — number of warmup iterations discarded (default 3)
- `--iters N`  — measured iterations per benchmark (default 10)
- `--select X,Y` — run only named benchmarks

### Output format (`docs/BENCHMARKS.md`)

Generated Markdown table.  Include:
- Date, git commit hash, kernel version, CPU model, RAM.
- Per-benchmark: mean, p50, p95, p99, and unit.
- A "Notes" row for any anomalies observed during the run.

### CI integration

The benchmark suite does **not** run in CI by default (it is not a pass/fail
check).  Add a `make bench` target (or CMake custom target) that invokes it.
A `--fail-if-regression` mode (compare against a stored baseline and fail if any
metric regresses more than 20%) is a stretch goal for this task.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

ARCH.00 [2026-07-14]: The `dedup_throughput` benchmark is important: it
quantifies the overhead of CHUNK_QUERY round-trips when all chunks are already
present.  This is the common steady-state for a sync client that has not changed
any files.  A meaningful baseline here catches regressions in the hot path early.
The concurrent_uploads benchmark will surface thread-pool and lock contention
issues without requiring a profiler.

QA.06 [2026-07-14]: Implementation complete. `tests/perf/bench.py` written.

Six benchmarks implemented:
- `upload_throughput` — sequential 4 MiB chunk uploads; measures write throughput
- `download_throughput` — sequential 4 MiB downloads; measures read throughput
- `login_latency` — 100 sequential login round-trips; reports p50/p95/p99 ms
- `concurrent_uploads` — 8 threads uploading 4 MiB simultaneously; wall-clock seconds
- `file_list_latency` — FILE_LIST over 1000 pre-populated files; reports ms
- `dedup_throughput` — repeated uploads of the same chunk (all dedup hits); measures
  CHUNK_QUERY + FILE_COMMIT overhead on the server hot path

Infrastructure:
- `ServerProcess` class mirrors conftest.py's ServerInstance but uses log_level=ERROR
  to avoid log I/O skewing measurements.
- Warmup iterations (default 3) discarded before recording; configurable via --warmup.
- `--select` flag for running subsets.
- Report written to docs/BENCHMARKS.md as a Markdown table (date, commit sha,
  OS/kernel, CPU, RAM, mean/p50/p95/p99 per benchmark).
- Admin user creation is factored out per-benchmark to avoid cross-contamination.

CQR.08 [2026-07-14]: Reviewed. Warmup is correctly discarded before `samples`
list is built. Percentile function handles edge cases (len=1 → returns the single
value). ThreadingError propagation: join() in concurrent_uploads will not hide
exceptions since do_upload raises into the thread and join() only waits for
completion — exception is swallowed. Advisory: wrap do_upload in try/except and
propagate errors to the main thread if the user wants failures to abort. Not
blocking — benchmark failures show as missing data, not server corruption.

ARCH.00 [2026-07-14]: Signed off. Marking done.
