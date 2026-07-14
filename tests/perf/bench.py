#!/usr/bin/env python3
"""
bench.py — VaporWault performance benchmark suite.

Measures upload/download throughput, login latency, concurrent upload
performance, FILE_LIST latency, and dedup overhead.

Usage:
    python tests/perf/bench.py \\
        --server-bin build/bin/vapourwaultd \\
        --test-cert  tests/integration/test.crt \\
        --test-key   tests/integration/test.key \\
        --output     docs/BENCHMARKS.md

Options:
    --warmup N    Warmup iterations discarded (default 3)
    --iters  N    Measured iterations per benchmark (default 10)
    --select X,Y  Run only these benchmark names (comma-separated)
    --output PATH Write Markdown results to this file (default stdout)
"""

import argparse
import hashlib
import os
import platform
import shutil
import socket
import statistics
import subprocess
import sys
import tempfile
import time
import threading

# Allow importing vw_client from the integration test directory.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "integration"))
from vw_client import VwClient, AdminClient

# ── Constants ─────────────────────────────────────────────────────────────────

CHUNK_4MIB  = 4 * 1024 * 1024
BENCH_PASS  = "BenchP@ss1!"
SERVER_PORT_BASE = 19600  # avoid collision with integration test ports

# ── Helpers ───────────────────────────────────────────────────────────────────

def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _write_conf(path, data_dir, cert, key, admin_sock, port):
    with open(path, "w") as f:
        f.write(
            f"listen_host      = 127.0.0.1\n"
            f"listen_port      = {port}\n"
            f"data_dir         = {data_dir}\n"
            f"cert_pem_path    = {cert}\n"
            f"key_pem_path     = {key}\n"
            f"log_level        = ERROR\n"
            f"max_connections  = 64\n"
            f"max_workers      = 4\n"
            f"admin_socket     = {admin_sock}\n"
            f"gc_interval_secs = 60\n"
        )


class ServerProcess:
    """Start/stop a vapourwaultd process for benchmarking."""

    def __init__(self, server_bin, cert, key):
        self.server_bin = server_bin
        self.cert = cert
        self.key  = key
        self._tmpdir = tempfile.mkdtemp(prefix="vw_bench_")
        self.port = _free_port()
        self.admin_sock = os.path.join(self._tmpdir, "admin.sock")
        conf = os.path.join(self._tmpdir, "server.conf")
        data = os.path.join(self._tmpdir, "data")
        os.makedirs(data, exist_ok=True)
        _write_conf(conf, data, cert, key, self.admin_sock, self.port)
        self._proc = subprocess.Popen(
            [server_bin, "--config", conf],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        deadline = time.monotonic() + 20
        while not os.path.exists(self.admin_sock):
            if time.monotonic() > deadline:
                self.stop()
                raise RuntimeError("server did not start within 20 s")
            time.sleep(0.1)

    def new_client(self):
        return VwClient("127.0.0.1", self.port, self.cert)

    def new_admin(self):
        return AdminClient(self.admin_sock)

    def stop(self):
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
        shutil.rmtree(self._tmpdir, ignore_errors=True)


def _setup_user(admin, server, name, password=BENCH_PASS):
    admin.create_user(name, password)
    c = server.new_client()
    info = c.login(name, password)
    return c, info["session_token"]


def _percentile(data, p):
    data = sorted(data)
    idx = (len(data) - 1) * p / 100
    lo, hi = int(idx), min(int(idx) + 1, len(data) - 1)
    return data[lo] + (data[hi] - data[lo]) * (idx - lo)


# ── Benchmarks ────────────────────────────────────────────────────────────────

def bench_upload_throughput(server, warmup, iters):
    """Sequential upload of N × 4 MiB chunks; return MiB/s."""
    admin = server.new_admin()
    c, token = _setup_user(admin, server, "bench_upload")
    admin.close()
    data = os.urandom(CHUNK_4MIB)

    def one_run():
        t0 = time.perf_counter()
        c.upload_file(token, f"/upload_{time.monotonic_ns()}.bin", data)
        return (CHUNK_4MIB / (1024 * 1024)) / (time.perf_counter() - t0)

    for _ in range(warmup):
        one_run()
    samples = [one_run() for _ in range(iters)]
    c.close()
    return samples, "MiB/s"


def bench_download_throughput(server, warmup, iters):
    """Download a pre-uploaded 4 MiB file repeatedly; return MiB/s."""
    admin = server.new_admin()
    c, token = _setup_user(admin, server, "bench_download")
    admin.close()
    data = os.urandom(CHUNK_4MIB)
    _, version_id = c.upload_file(token, "/dl_target.bin", data)

    def one_run():
        t0 = time.perf_counter()
        c.download_file(token, version_id)
        return (CHUNK_4MIB / (1024 * 1024)) / (time.perf_counter() - t0)

    for _ in range(warmup):
        one_run()
    samples = [one_run() for _ in range(iters)]
    c.close()
    return samples, "MiB/s"


def bench_login_latency(server, warmup, iters):
    """Sequential login round-trips; return milliseconds."""
    admin = server.new_admin()
    admin.create_user("bench_login", BENCH_PASS)
    admin.close()

    def one_run():
        c = server.new_client()
        t0 = time.perf_counter()
        c.login("bench_login", BENCH_PASS)
        ms = (time.perf_counter() - t0) * 1000
        c.close()
        return ms

    for _ in range(warmup):
        one_run()
    samples = [one_run() for _ in range(iters)]
    return samples, "ms"


def bench_concurrent_uploads(server, warmup, iters):
    """8 clients uploading 4 MiB simultaneously; return wall-clock seconds."""
    N_CLIENTS = 8
    admin = server.new_admin()
    clients_tokens = []
    for i in range(N_CLIENTS):
        c, tok = _setup_user(admin, server, f"bench_conc_{i}")
        clients_tokens.append((c, tok))
    admin.close()
    chunks = [os.urandom(CHUNK_4MIB) for _ in range(N_CLIENTS)]

    def do_upload(c, tok, data, name):
        c.upload_file(tok, f"/{name}.bin", data)

    def one_run():
        threads = []
        name = str(time.monotonic_ns())
        t0 = time.perf_counter()
        for i, (c, tok) in enumerate(clients_tokens):
            t = threading.Thread(target=do_upload, args=(c, tok, chunks[i], f"{name}_{i}"))
            threads.append(t)
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        return time.perf_counter() - t0

    for _ in range(warmup):
        one_run()
    samples = [one_run() for _ in range(iters)]
    for c, _ in clients_tokens:
        c.close()
    return samples, "s (wall)"


def bench_file_list_latency(server, warmup, iters):
    """FILE_LIST over a 1000-entry directory; return milliseconds."""
    admin = server.new_admin()
    c, token = _setup_user(admin, server, "bench_list")
    admin.close()
    # Populate 1000 files
    print("    Populating 1000 files for list benchmark...", end=" ", flush=True)
    tiny = os.urandom(64)
    for i in range(1000):
        c.upload_file(token, f"/list_dir/file_{i:04d}.bin", tiny)
    print("done")

    def one_run():
        t0 = time.perf_counter()
        c.file_list(token, path="/list_dir")
        return (time.perf_counter() - t0) * 1000

    for _ in range(warmup):
        one_run()
    samples = [one_run() for _ in range(iters)]
    c.close()
    return samples, "ms"


def bench_dedup_throughput(server, warmup, iters):
    """
    Upload the same 4 MiB chunk 100 times (all deduplicated after the first).
    Reports the average round-trip rate (MiB/s equivalent) for dedup cache hits.
    This measures CHUNK_QUERY + FILE_COMMIT overhead on the server hot path.
    """
    admin = server.new_admin()
    c, token = _setup_user(admin, server, "bench_dedup")
    admin.close()
    data = os.urandom(CHUNK_4MIB)

    # Pre-upload so all subsequent uploads are dedup hits.
    c.upload_file(token, "/dedup_base.bin", data)

    def one_run():
        t0 = time.perf_counter()
        c.upload_file(token, f"/dedup_{time.monotonic_ns()}.bin", data)
        return (CHUNK_4MIB / (1024 * 1024)) / (time.perf_counter() - t0)

    for _ in range(warmup):
        one_run()
    samples = [one_run() for _ in range(iters)]
    c.close()
    return samples, "MiB/s (dedup rate)"


# ── Registry ──────────────────────────────────────────────────────────────────

BENCHMARKS = {
    "upload_throughput":  bench_upload_throughput,
    "download_throughput": bench_download_throughput,
    "login_latency":      bench_login_latency,
    "concurrent_uploads": bench_concurrent_uploads,
    "file_list_latency":  bench_file_list_latency,
    "dedup_throughput":   bench_dedup_throughput,
}

# ── Reporting ─────────────────────────────────────────────────────────────────

def _system_info():
    try:
        cpu = platform.processor() or platform.machine()
    except Exception:
        cpu = "unknown"
    mem_gib = "unknown"
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemTotal"):
                    kb = int(line.split()[1])
                    mem_gib = f"{kb // (1024*1024)} GiB"
                    break
    except Exception:
        pass
    try:
        import subprocess as sp
        uname = sp.check_output(["uname", "-r"], text=True).strip()
    except Exception:
        uname = platform.release()
    return cpu, mem_gib, uname


def _git_sha():
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"],
            text=True, stderr=subprocess.DEVNULL
        ).strip()
    except Exception:
        return "unknown"


def write_report(results, output):
    cpu, mem, kernel = _system_info()
    sha = _git_sha()
    from datetime import datetime
    date = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    lines = [
        "# VaporWault Performance Benchmarks",
        "",
        f"| Field | Value |",
        f"|-------|-------|",
        f"| Date | {date} |",
        f"| Git commit | {sha} |",
        f"| OS / kernel | {platform.system()} {kernel} |",
        f"| CPU | {cpu} |",
        f"| RAM | {mem} |",
        "",
        "| Benchmark | Mean | p50 | p95 | p99 | Unit |",
        "|-----------|------|-----|-----|-----|------|",
    ]

    for name, (samples, unit) in results:
        mean = statistics.mean(samples)
        p50  = _percentile(samples, 50)
        p95  = _percentile(samples, 95)
        p99  = _percentile(samples, 99)
        lines.append(
            f"| {name} | {mean:.2f} | {p50:.2f} | {p95:.2f} | {p99:.2f} | {unit} |"
        )

    lines.append("")
    report = "\n".join(lines)

    if output == "-":
        print(report)
    else:
        with open(output, "w") as f:
            f.write(report + "\n")
        print(f"Report written to {output}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="VaporWault performance benchmarks")
    parser.add_argument("--server-bin",  default=None, help="Path to vapourwaultd")
    parser.add_argument("--test-cert",   default=None, help="TLS certificate PEM")
    parser.add_argument("--test-key",    default=None, help="TLS private key PEM")
    parser.add_argument("--warmup",      type=int, default=3,  help="Warmup iterations")
    parser.add_argument("--iters",       type=int, default=10, help="Measured iterations")
    parser.add_argument("--select",      default=None, help="Comma-separated benchmark names")
    parser.add_argument("--output",      default="-", help="Output file (- = stdout)")
    args = parser.parse_args()

    # Auto-discover server binary
    server_bin = args.server_bin
    if not server_bin:
        for d in ("build/bin", "build-release/bin"):
            p = os.path.join(d, "vapourwaultd" + (".exe" if os.name == "nt" else ""))
            if os.path.isfile(p):
                server_bin = p
                break
    if not server_bin or not os.path.isfile(server_bin):
        print("ERROR: vapourwaultd binary not found. Pass --server-bin.", file=sys.stderr)
        sys.exit(1)

    cert = args.test_cert
    key  = args.test_key
    if not cert or not key:
        print("ERROR: --test-cert and --test-key are required.", file=sys.stderr)
        sys.exit(1)

    selected = list(BENCHMARKS.keys())
    if args.select:
        selected = [s.strip() for s in args.select.split(",")]
        unknown  = [s for s in selected if s not in BENCHMARKS]
        if unknown:
            print(f"ERROR: unknown benchmarks: {unknown}", file=sys.stderr)
            sys.exit(1)

    print(f"Starting benchmark server ({server_bin})...")
    server = ServerProcess(server_bin, cert, key)

    results = []
    try:
        for name in selected:
            print(f"  [{name}] warmup={args.warmup} iters={args.iters}...", flush=True)
            fn = BENCHMARKS[name]
            samples, unit = fn(server, args.warmup, args.iters)
            mean = statistics.mean(samples)
            print(f"    mean={mean:.2f} {unit}")
            results.append((name, (samples, unit)))
    finally:
        server.stop()

    write_report(results, args.output)


if __name__ == "__main__":
    main()
