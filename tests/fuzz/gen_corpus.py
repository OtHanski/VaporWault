#!/usr/bin/env python3
"""gen_corpus.py — Generate binary corpus seed files for VaporWault fuzz targets.

Writes seeds to tests/fuzz/corpus/<target>/.  Files that already exist are left
untouched so that crash-reproducing inputs accumulated by the fuzzer are not
overwritten.

Usage:
    python3 tests/fuzz/gen_corpus.py [<corpus-root>]

Default corpus root: the corpus/ directory next to this script.
"""

import os
import struct
import zlib
import sys

# ── Protocol constants (must match src/core/vw_proto.h) ──────────────────────

VW_MAX_MSG_BYTES    = 8 * 1024 * 1024
VW_PROTO_VERSION    = 6
VW_HASH_BYTES       = 32
VW_TOKEN_BYTES      = 32

# Wire message types
VW_MSG_HELLO              = 0x0001
VW_MSG_AUTH_REQUEST       = 0x0101
VW_MSG_AUTH_OTP           = 0x0103
VW_MSG_SESSION_RESUME     = 0x0106
VW_MSG_FILE_LIST          = 0x0201
VW_MSG_CHUNK_QUERY        = 0x0205
VW_MSG_CHUNK_UPLOAD       = 0x0207
VW_MSG_FILE_COMMIT        = 0x020B
VW_MSG_FILE_DELETE        = 0x020D

# Admin message types (must match src/server/vw_admin.h)
VW_ADMIN_USER_CREATE_REQ  = 0x9001
VW_ADMIN_USER_LIST_REQ    = 0x9003
VW_ADMIN_SET_QUOTA_REQ    = 0x9005
VW_ADMIN_OPLOG_TAIL_REQ   = 0x9007
VW_ADMIN_CONN_LIST_REQ    = 0x9009
VW_ADMIN_RELOAD_CERT_REQ  = 0x900B

# Cluster / oplog
VW_MSG_NODE_HELLO         = 0x0701
NODE_HELLO_MIN_LEN        = 8 + 32 + 8 + 2 + 2   # 52 bytes


# ── Encoding helpers ──────────────────────────────────────────────────────────

def u8(v):  return struct.pack('<B', v & 0xFF)
def u16(v): return struct.pack('<H', v & 0xFFFF)
def u32(v): return struct.pack('<I', v & 0xFFFFFFFF)
def u64(v): return struct.pack('<Q', v & 0xFFFFFFFFFFFFFFFF)

def lenstr(s):
    """u16 length prefix + bytes (for wire-protocol strings)."""
    if isinstance(s, str):
        s = s.encode()
    return u16(len(s)) + s

def token(byte_val=0x00):
    """32 bytes of 'byte_val', standing in for a token or hash."""
    return bytes([byte_val] * VW_TOKEN_BYTES)


# ── Wire frame builder ────────────────────────────────────────────────────────

def frame(msg_type, payload=b'', proto_version=VW_PROTO_VERSION):
    """Encode a complete wire frame (8-byte header + payload)."""
    total_len = 8 + len(payload)
    return u32(total_len) + u16(msg_type) + u16(proto_version) + payload


# ── Admin frame builder ───────────────────────────────────────────────────────

def admin_frame(msg_type, payload=b''):
    total_len = 8 + len(payload)
    return u32(total_len) + u16(msg_type) + u16(0) + payload  # reserved=0


# ── Oplog segment builder ─────────────────────────────────────────────────────
#
# Oplog entry layout (from vw_oplog.c):
#   [crc32 : 4 bytes LE]
#   [payload_len : 4 bytes LE]
#   [entry_id : 8 bytes LE]
#   [confirmed : 1 byte]          ← excluded from CRC
#   [payload : payload_len bytes]
#
# CRC32 covers: payload_len(4) + entry_id(8) + payload(payload_len bytes).
# The 'confirmed' byte is intentionally excluded so the server can set/clear
# it without recomputing the CRC.

def crc32_bytes(data):
    return zlib.crc32(data) & 0xFFFFFFFF

def oplog_entry(entry_id, payload=b'', confirmed=1, op_type=1):
    """Build a single oplog entry.

    op_type is prepended to payload as a u8 (the first byte of payload in the
    real format); pass op_type=None to use payload verbatim.
    """
    if op_type is not None:
        payload = bytes([op_type & 0xFF]) + payload

    payload_len_val = len(payload)
    # CRC covers: payload_len(4) + entry_id(8) + payload bytes
    crc_data = u32(payload_len_val) + u64(entry_id) + payload
    crc = crc32_bytes(crc_data)

    return (u32(crc) + u32(payload_len_val) + u64(entry_id) +
            bytes([confirmed & 0xFF]) + payload)

def oplog_segment(*entries):
    """Concatenate multiple oplog entries into one segment blob."""
    return b''.join(entries)


# ── NODE_HELLO payload builder ────────────────────────────────────────────────

def cluster_hello(node_id=1, auth_token=None, watermark=0,
                  proto_version=VW_PROTO_VERSION, hostname=b'node1'):
    if auth_token is None:
        auth_token = bytes(32)
    if isinstance(hostname, str):
        hostname = hostname.encode()
    return (u64(node_id) + auth_token + u64(watermark) +
            u16(proto_version) + u16(len(hostname)) + hostname)


# ── Seed definitions ──────────────────────────────────────────────────────────

SEEDS = {
    # ── fuzz_proto_recv ───────────────────────────────────────────────────────
    'fuzz_proto_recv': {
        # Valid seeds — frames the server would accept
        'hello_valid': frame(VW_MSG_HELLO, u16(VW_PROTO_VERSION)),

        'auth_request_valid': frame(VW_MSG_AUTH_REQUEST,
            lenstr('alice') + token(0xAB)),   # sha256(pw) placeholder

        'session_resume': frame(VW_MSG_SESSION_RESUME, token(0x01)),

        'file_list': frame(VW_MSG_FILE_LIST, token() + lenstr('/docs')),

        'chunk_query_1hash': frame(VW_MSG_CHUNK_QUERY,
            token() + u16(1) + token(0xDE)),

        'chunk_upload': frame(VW_MSG_CHUNK_UPLOAD,
            token() + token(0xBE) + u64(42) + u32(0) +
            u32(4) + b'DATA'),

        'file_delete': frame(VW_MSG_FILE_DELETE, token() + u64(7)),

        'file_commit_one_chunk': frame(VW_MSG_FILE_COMMIT,
            token() + lenstr('/file.txt') + u32(1) + token(0xCC)),

        # Boundary seeds — frames that trigger specific validation paths
        'too_short_7': b'\x00' * 7,          # < 8 bytes → rejected before parse

        'header_only': frame(VW_MSG_HELLO, b''),  # empty payload, valid header

        'oversized': u32(VW_MAX_MSG_BYTES + 1) + u16(VW_MSG_HELLO) + u16(VW_PROTO_VERSION),

        'truncated': frame(VW_MSG_AUTH_REQUEST, lenstr('alice') + token())[:10],

        'unknown_type': frame(0xDEAD, b'\x00' * 8),

        'wrong_version': frame(VW_MSG_HELLO, u16(0xFFFF)),
    },

    # ── fuzz_path_validate ────────────────────────────────────────────────────
    'fuzz_path_validate': {
        # Valid paths
        'valid_simple':        b'/file.txt',
        'valid_root':          b'/',
        'valid_deep':          b'/a/b/c/d/e',
        'valid_one_component': b'/hello',
        'valid_spaces':        b'/my file.txt',
        'valid_unicode':       '/résumé.pdf'.encode(),

        # Boundary / invalid
        'invalid_traversal':   b'/../etc/passwd',
        'invalid_backslash':   b'/path\\file',
        'invalid_comp_trav':   b'/a/b/../c',
        'invalid_double_slash':b'/a//b',
        'invalid_empty':       b'',
        'invalid_nul':         b'/path\x00file',
        'invalid_no_slash':    b'relative/path',
        'boundary_long':       b'/' + b'x' * 4095,
    },

    # ── fuzz_oplog_replay ─────────────────────────────────────────────────────
    'fuzz_oplog_replay': {
        # Valid seeds — well-formed segments vw_oplog_open should replay cleanly
        'single_valid': oplog_segment(
            oplog_entry(1, b'\x00' * 8, confirmed=1)),

        'two_valid': oplog_segment(
            oplog_entry(1, b'\x01' * 8, confirmed=1),
            oplog_entry(2, b'\x02' * 8, confirmed=1)),

        'three_valid': oplog_segment(
            oplog_entry(1, b'\x01' * 4, confirmed=1),
            oplog_entry(2, b'\x02' * 4, confirmed=1),
            oplog_entry(3, b'\x03' * 4, confirmed=1)),

        'unconfirmed_tail': oplog_segment(
            oplog_entry(1, b'\x01' * 8, confirmed=1),
            oplog_entry(2, b'\x02' * 8, confirmed=0)),  # unconfirmed tail → truncated on open

        'noop_entry': oplog_segment(
            oplog_entry(1, b'', op_type=0, confirmed=1)),   # op_type=0, empty payload

        'large_payload': oplog_segment(
            oplog_entry(1, b'\xFF' * 255, confirmed=1)),

        # Boundary / corrupt seeds
        'empty':         b'',

        'partial_header': b'\x00' * 10,   # 10 bytes — truncated before full 17-byte header

        'bad_crc': (
            u32(0xDEADBEEF) +             # wrong CRC
            u32(4) +                       # payload_len=4
            u64(1) +                       # entry_id=1
            bytes([1]) +                   # confirmed=1
            b'\x01\x02\x03\x04'           # payload
        ),

        'garbage': bytes(range(256)),      # 256 bytes of non-entry data

        'oversize_payload_len': (
            u32(0x00000000) +              # crc placeholder
            u32(0xFFFFFFFF) +             # payload_len = 4 GiB → segment is far shorter
            u64(1) +
            bytes([1])
        ),
    },

    # ── fuzz_cluster_hello ────────────────────────────────────────────────────
    'fuzz_cluster_hello': {
        # Valid seeds — well-formed NODE_HELLO payloads
        'valid_basic':     cluster_hello(node_id=1, hostname=b'node1'),

        'valid_long_host': cluster_hello(node_id=2,
                               hostname=b'cluster-node-datacenter-1.example.internal'),

        'valid_no_hostname': cluster_hello(node_id=3, hostname=b''),

        'valid_watermark': cluster_hello(node_id=4, watermark=0xFFFFFFFFFFFFFFFF,
                               hostname=b'primary'),

        'valid_ipv6_host': cluster_hello(node_id=5, hostname=b'2001:db8::1'),

        'valid_max_proto': cluster_hello(node_id=6, proto_version=0xFFFF,
                               hostname=b'p'),

        # Boundary / invalid seeds
        'too_short_51': bytes(51),            # one byte short of minimum (52)

        'min_size_52': bytes(52),             # exactly minimum size; hostname_len=0 from zeros

        'all_zeros': bytes(52),               # same as min_size_52 but named semantically

        'hostname_overflow': (                # valid prefix but hostname_len > remaining bytes
            u64(9) +
            bytes(32) +                        # auth_token
            u64(0) +                           # watermark
            u16(VW_PROTO_VERSION) +
            u16(200) +                         # hostname_len=200 but only 0 bytes follow
            b''
        ),

        'zero_node_id': cluster_hello(node_id=0, hostname=b'x'),
    },

    # ── fuzz_admin_dispatch ───────────────────────────────────────────────────
    'fuzz_admin_dispatch': {
        # Valid seeds — well-formed admin frames
        'user_create': admin_frame(VW_ADMIN_USER_CREATE_REQ,
            u8(0) + lenstr('testuser') + lenstr('hunter2')),

        'user_create_admin': admin_frame(VW_ADMIN_USER_CREATE_REQ,
            u8(1) + lenstr('admin2') + lenstr('S3cr3t!')),

        'user_list': admin_frame(VW_ADMIN_USER_LIST_REQ),

        'set_quota': admin_frame(VW_ADMIN_SET_QUOTA_REQ,
            lenstr('testuser') + u64(10 * 1024 * 1024 * 1024)),

        'oplog_tail_10': admin_frame(VW_ADMIN_OPLOG_TAIL_REQ, u32(10)),

        'oplog_tail_100': admin_frame(VW_ADMIN_OPLOG_TAIL_REQ, u32(100)),

        'conn_list': admin_frame(VW_ADMIN_CONN_LIST_REQ),

        'reload_cert': admin_frame(VW_ADMIN_RELOAD_CERT_REQ),

        # Boundary seeds
        'header_only':  u32(8) + u16(VW_ADMIN_USER_LIST_REQ) + u16(0),

        'truncated':    admin_frame(VW_ADMIN_USER_CREATE_REQ,
                            u8(0) + lenstr('u'))[:9],  # truncated mid-payload

        'unknown_type': admin_frame(0x9FFF, b'\x00' * 4),
    },
}


# ── Writer ────────────────────────────────────────────────────────────────────

def write_seeds(corpus_root):
    written = 0
    skipped = 0

    for target, seeds in SEEDS.items():
        out_dir = os.path.join(corpus_root, target)
        os.makedirs(out_dir, exist_ok=True)

        for name, data in seeds.items():
            out_path = os.path.join(out_dir, name)
            if os.path.exists(out_path):
                skipped += 1
                continue
            with open(out_path, 'wb') as f:
                f.write(data)
            written += 1

    print(f"Wrote {written} new seeds, skipped {skipped} existing.")


if __name__ == '__main__':
    script_dir = os.path.dirname(os.path.abspath(__file__))
    corpus_root = sys.argv[1] if len(sys.argv) > 1 else os.path.join(script_dir, 'corpus')
    write_seeds(corpus_root)
