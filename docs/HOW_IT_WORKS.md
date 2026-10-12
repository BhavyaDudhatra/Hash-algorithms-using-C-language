# How It Works

This page explains the two modes of `main.c` in plain language, so you can
read the C code next to the spec.

## Mode 1 — Plaintext → Hash

```
plaintext (max 4095 chars)
  → pick algorithm 1–21
  → pad message
  → compress / squeeze
  → hex-encode digest
```

### Padding (Merkle–Damgård family)

MD5, SHA-1, SHA-2, RIPEMD-160, BLAKE2, Whirlpool all:

1. Append `0x80`.
2. Append zeros until 8 (or 16/32) bytes remain in the last block.
3. Append original length **in bits** (little-endian for MD5/BLAKE, big-endian for SHA/RIPEMD/Whirlpool).

In `main.c` look at `pad_len = (len + 1 + 8 + 63) & ~63` — that rounds up to a
full 64-byte block. SHA-512 uses 128-byte blocks; Whirlpool adds a 32-byte
length field.

### Compression

| Family | Core | Where in code |
|:--|:--|:--|
| MD5 | 64 steps, 4 rounds, `rotl32` | `md5_raw` |
| SHA-1 | 80 steps, `rotl(a,5)` + `rotl(b,30)` | `sha1_raw` |
| SHA-256/224 | 64 steps, `rotr` + `Ch/Maj`, `K[64]` | `sha256_calc` |
| SHA-512/384/... | 80 steps, 64-bit version | `sha512_calc` |
| SHA-3/SHAKE | Keccak-f[1600], 24 rounds, rate 72–168 | `keccakf` + `sponge_raw` |
| BLAKE2b/2s | G-function, sigma schedule, IV xor | `blake2b_compress` / `blake2s_compress` |
| BLAKE3 | 7-round compress, chunk + parent chaining | `b3_compress`, `b3_chunk_cv` |
| RIPEMD-160 | Twin left/right lines, 5 rounds | `ripemd160_raw` |
| Whirlpool | 10-round Miyaguchi–Preneel, S-box + MDS table `WP_C0` | `wp_compress` |
| CRC32/64 | Bitwise shift + polynomial | `calculate_crc32/64` |

### Hex encoding

`bytes_to_hex` maps each byte to two `0–9a–f` chars. Digest bytes compared in
crack mode are the **raw** bytes (`fn_raw`); what you see/paste is the **hex**
(`fn`).

## Mode 2 — Hash → Plaintext (brute force)

```
hex hash → raw bytes
  → for len = 1..10:
  →   split 96^len space into 4096-chunks
  →   N threads pull chunks atomically
  →   hash each candidate, memcmp vs target
  →   first match wins
```

- **Alphabet:** printable ASCII `32–127` inclusive = 96 symbols (`CRACK_ALPHA_*`).
- **Lengths:** `CRACK_MIN_LEN 1` to `CRACK_MAX_LEN 10`.
- **Chunking:** `CRACK_CHUNK 4096` candidates per work item. `crack_next_range()`
  hands out `[start, start+count)` via `__sync_fetch_and_add` on `g_crack_next`.
- **Length 10 trick:** `96¹⁰` needs 66 bits, so the index is split into a
  leading digit (`hi`) + 64-bit remainder. No combination lost to overflow.
- **Threads:** `GetSystemInfo` → CPU count, capped at 64 (`CRACK_MAX_THREADS`,
  the `WaitForMultipleObjects` limit). Each thread hashes into a stack buffer —
  no heap in the hot loop.
- **Progress:** main thread waits 1 s at a time and prints
  `... tried N candidates total (length L)`.
- **Attempts counter:** `g_crack_attempts`, updated in batches of 65536.

### Search-space math (why long passwords win)

| Length | Candidates (`96ⁿ`) | Rough feel |
|:--|:--|:--|
| 1 | 96 | instant |
| 2 | 9,216 | instant (`"hi"` found in 8,106 tries) |
| 3 | 884,736 | seconds |
| 4 | ~85 M | seconds–minutes |
| 5 | ~8.1 B | hours |
| 6+ | 7.8×10¹¹+ | days → infeasible |
| 10 | ~6.6×10¹⁹ | infeasible — that *is* the lesson |

Only crack **short strings you generated yourself**. Anything realistically
long is the demo of why brute-force fails.

## Code map

```
main.c
├── helpers: rotr/rotl, load/store BE/LE, bytes_to_hex
├── MD5 / SHA-1
├── SHA-2: sha256_calc, sha512_calc + IVs
├── SHA-3/SHAKE: keccakf, sponge_raw
├── BLAKE2b/2s, BLAKE3 (chunk + parent stack)
├── RIPEMD-160, Whirlpool (WP_C0 table), CRC32/64
├── ALGOS[] table (name, hex fn, raw fn, digest len)
├── mode_hash()   — menu 1
└── mode_crack()  — menu 2, threads + chunk queue
```
