/**
 * mbedtls_config.h — VaporWault project-specific mbedTLS configuration
 *
 * This header replaces the default mbedTLS config_default.h.
 * It enables only the primitives and protocols required by VaporWault and
 * explicitly excludes weak or legacy algorithms.
 *
 * Passed to the mbedTLS build via:
 *   MBEDTLS_CONFIG_FILE="${CMAKE_SOURCE_DIR}/third_party/mbedtls_config.h"
 * (set in third_party/CMakeLists.txt)
 *
 * Owner: BLD.05 in coordination with PRT.04.
 * Any change to this file that affects the wire protocol must be reviewed
 * by PRT.04 and SEC.07 before merging.
 */

#ifndef VAPOURWAULT_MBEDTLS_CONFIG_H
#define VAPOURWAULT_MBEDTLS_CONFIG_H

/* ------------------------------------------------------------------ */
/* TLS layer                                                           */
/* ------------------------------------------------------------------ */

/** Enable the TLS/SSL module. */
#define MBEDTLS_SSL_TLS_C

/** TLS 1.3 ephemeral key exchange (forward secrecy). */
#define MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED

/** TLS 1.3 protocol support. */
#define MBEDTLS_SSL_PROTO_TLS1_3

/**
 * PSA Crypto API — required by TLS 1.3 in mbedTLS 3.x.
 * The TLS 1.3 implementation uses PSA internally for key operations.
 */
#define MBEDTLS_PSA_CRYPTO_C

/**
 * Retain the peer certificate after the handshake.
 * Required for TLS 1.3 in mbedTLS 3.x (check_config.h enforces this).
 */
#define MBEDTLS_SSL_KEEP_PEER_CERTIFICATE

/** TLS session tickets (resumption without server-side state). */
#define MBEDTLS_SSL_SESSION_TICKETS

/** Application-Layer Protocol Negotiation extension. */
#define MBEDTLS_SSL_ALPN

/** TLS ticket support (stateless resumption — the TLS 1.3 mechanism).
 *  MBEDTLS_SSL_CACHE_C is intentionally omitted: it is the TLS 1.2
 *  server-side session cache, which is unavailable when TLS 1.3 is the
 *  only enabled protocol version. */
#define MBEDTLS_SSL_TICKET_C

/* ------------------------------------------------------------------ */
/* Network I/O                                                         */
/* ------------------------------------------------------------------ */

/** Portable network layer (BSD socket wrappers). */
#define MBEDTLS_NET_C

/* ------------------------------------------------------------------ */
/* Entropy and random number generation                                */
/* ------------------------------------------------------------------ */

/** Entropy accumulator (feeds the DRBG). */
#define MBEDTLS_ENTROPY_C

/** CTR-DRBG (AES-based deterministic RNG — primary RNG). */
#define MBEDTLS_CTR_DRBG_C

/** HMAC-DRBG (used internally by some key-generation paths). */
#define MBEDTLS_HMAC_DRBG_C

/* ------------------------------------------------------------------ */
/* Symmetric ciphers                                                   */
/* ------------------------------------------------------------------ */

/** Generic cipher abstraction layer. */
#define MBEDTLS_CIPHER_C

/** AES block cipher. */
#define MBEDTLS_AES_C

/** GCM authenticated-encryption mode (AES-128-GCM, AES-256-GCM). */
#define MBEDTLS_GCM_C

/** ChaCha20 stream cipher. */
#define MBEDTLS_CHACHA20_C

/** Poly1305 message-authentication code. */
#define MBEDTLS_POLY1305_C

/** ChaCha20-Poly1305 AEAD. */
#define MBEDTLS_CHACHAPOLY_C

/* ------------------------------------------------------------------ */
/* Hash / MAC                                                          */
/* ------------------------------------------------------------------ */

/** Generic message-digest abstraction layer. */
#define MBEDTLS_MD_C

/** HKDF (HMAC-based Key Derivation Function) — used in TLS 1.3 handshake. */
#define MBEDTLS_HKDF_C

/** SHA-256 (used in TLS 1.3 handshake, certificate verification). */
#define MBEDTLS_SHA256_C

/** SHA-512 (used in certificate chains with SHA-384 signatures). */
#define MBEDTLS_SHA512_C

/** SHA-1 (required for HOTP/TOTP HMAC-SHA1; not used for TLS). */
#define MBEDTLS_SHA1_C

/* ------------------------------------------------------------------ */
/* Asymmetric key operations                                           */
/* ------------------------------------------------------------------ */

/** Big-number (multi-precision integer) arithmetic. */
#define MBEDTLS_BIGNUM_C

/** Elliptic-curve cryptography core. */
#define MBEDTLS_ECP_C

/** ECDH key exchange (used in TLS 1.3 ephemeral handshake). */
#define MBEDTLS_ECDH_C

/** ECDSA signatures (certificate verification). */
#define MBEDTLS_ECDSA_C

/** NIST P-256 curve (primary curve for key exchange and certificates). */
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED

/** NIST P-384 curve (for certificates signed with SHA-384). */
#define MBEDTLS_ECP_DP_SECP384R1_ENABLED

/** X25519 (Curve25519 ECDH) — TLS 1.3 prefers this for key shares. */
#define MBEDTLS_ECP_DP_CURVE25519_ENABLED

/** RSA (certificate parsing and verification; key exchange not used). */
#define MBEDTLS_RSA_C

/** PKCS#1 v1.5 — required when MBEDTLS_RSA_C is defined. */
#define MBEDTLS_PKCS1_V15

/** Abstract public-key interface. */
#define MBEDTLS_PK_C

/** Public-key parser (PEM/DER). */
#define MBEDTLS_PK_PARSE_C

/** Public-key writer (PEM/DER) — needed by ACME to serialise generated keys. */
#define MBEDTLS_PK_WRITE_C

/** PKCS #5 (password-based key derivation; used by PEM decryption). */
#define MBEDTLS_PKCS5_C

/* ------------------------------------------------------------------ */
/* X.509 / PKI                                                         */
/* ------------------------------------------------------------------ */

/** X.509 certificate parsing. */
#define MBEDTLS_X509_CRT_PARSE_C

/** X.509 certificate use (verification). */
#define MBEDTLS_X509_USE_C

/** X.509 object creation (base for CRT write and CSR write). */
#define MBEDTLS_X509_CREATE_C

/** X.509 CSR writer — needed by ACME to generate certificate signing requests. */
#define MBEDTLS_X509_CSR_WRITE_C

/* ------------------------------------------------------------------ */
/* Encoding / ASN.1 / utility                                          */
/* ------------------------------------------------------------------ */

/** OID database (maps OIDs to algorithm names, etc.). */
#define MBEDTLS_OID_C

/** ASN.1 parser. */
#define MBEDTLS_ASN1_PARSE_C

/** ASN.1 writer. */
#define MBEDTLS_ASN1_WRITE_C

/** Base-64 encode/decode. */
#define MBEDTLS_BASE64_C

/** PEM (Privacy-Enhanced Mail) file parser. */
#define MBEDTLS_PEM_PARSE_C

/** Platform abstraction layer (memory, I/O). */
#define MBEDTLS_PLATFORM_C

/* ------------------------------------------------------------------ */
/* Explicitly excluded — do NOT re-enable without SEC.07 sign-off     */
/* ------------------------------------------------------------------ */

/*
 * Legacy TLS protocol versions — disabled to enforce TLS 1.3 only.
 * #define MBEDTLS_SSL_PROTO_TLS1     — excluded: TLS 1.0 is broken
 * #define MBEDTLS_SSL_PROTO_TLS1_1   — excluded: TLS 1.1 is broken
 * #define MBEDTLS_SSL_PROTO_TLS1_2   — excluded: server requires TLS 1.3
 *
 * Weak / legacy ciphers:
 * #define MBEDTLS_DES_C              — excluded: 3DES is deprecated
 * #define MBEDTLS_RC4_C              — excluded: RC4 is broken
 */

#endif /* VAPOURWAULT_MBEDTLS_CONFIG_H */
