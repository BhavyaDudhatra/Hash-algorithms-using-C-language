# Supported Algorithms + Test Vectors

All digests below were produced by `main.c` in this repo and cross-checked
against published vectors for `""`, `"abc"`, and `"hello"`.

Menu numbers match the CLI (`1–21`).

| # | Name | Family | Digest | Hex chars | Notes |
|:--|:--|:--|:--|:--|:--|
| 1 | MD5 | Legacy (RFC 1321) | 128-bit | 32 | Broken — collisions. Study only. |
| 2 | SHA-1 | Legacy (FIPS 180-4) | 160-bit | 40 | Broken — collisions. Study only. |
| 3 | SHA-224 | SHA-2 | 224-bit | 56 | Truncated SHA-256 with different IV. |
| 4 | SHA-256 | SHA-2 | 256-bit | 64 | General default. |
| 5 | SHA-384 | SHA-2 | 384-bit | 96 | Truncated SHA-512 with different IV. |
| 6 | SHA-512 | SHA-2 | 512-bit | 128 | 64-bit words, 128-byte blocks. |
| 7 | SHA-512/224 | SHA-2 | 224-bit | 56 | Distinct IV from SHA-512. |
| 8 | SHA-512/256 | SHA-2 | 256-bit | 64 | Distinct IV from SHA-512. |
| 9 | SHA3-224 | SHA-3 (FIPS 202) | 224-bit | 56 | Keccak sponge, rate 144. |
| 10 | SHA3-256 | SHA-3 | 256-bit | 64 | Keccak sponge, rate 136. |
| 11 | SHA3-384 | SHA-3 | 384-bit | 96 | Keccak sponge, rate 104. |
| 12 | SHA3-512 | SHA-3 | 512-bit | 128 | Keccak sponge, rate 72. |
| 13 | SHAKE128 | XOF (FIPS 202) | 256-bit* | 64 | *Demo truncates XOF to 32 bytes. |
| 14 | SHAKE256 | XOF | 512-bit* | 128 | *Demo truncates XOF to 64 bytes. |
| 15 | BLAKE2b | BLAKE (RFC 7693) | 512-bit | 128 | 64-bit, 12 rounds. |
| 16 | BLAKE2s | BLAKE | 256-bit | 64 | 32-bit, 10 rounds. |
| 17 | BLAKE3 | BLAKE3 | 256-bit | 64 | Chunk chaining + parent nodes. |
| 18 | RIPEMD-160 | Legacy | 160-bit | 40 | Dual line, study only. |
| 19 | Whirlpool | ISO/IEC 10118-3 | 512-bit | 128 | Miyaguchi–Preneel + AES-like S-box. |
| 20 | CRC32 | Checksum | 32-bit | 8 | **Not a secure hash.** Integrity only. |
| 21 | CRC64 | Checksum | 64-bit | 16 | **Not a secure hash.** ECMA polynomial `0xC96C5795D7870F42`. |

## Test vectors (`main.c` output)

### `"hello"`

```
MD5         5d41402abc4b2a76b9719d911017c592
SHA-1       aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d
SHA-224     ea09ae9cc6768c50fcee903ed054556e5bfc8347907f12598aa24193
SHA-256     2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
SHA-384     59e1748777448c69de6b800d7a33bbfb9ff1b463e44354c3553bcdb9c666fa90125a3c79f90397bdf5f6a13de828684f
SHA-512     9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043
SHA-512/224 fe8509ed1fb7dcefc27e6ac1a80eddbec4cb3d2c6fe565244374061c
SHA-512/256 e30d87cfa2a75db545eac4d61baf970366a8357c7f72fa95b52d0accb698f13a
SHA3-224    b87f88c72702fff1748e58b87e9141a42c0dbedc29a78cb0d4a5cd81
SHA3-256    3338be694f50c5f338814986cdf0686453a888b84f424d792af4b9202398f392
SHA3-384    720aea11019ef06440fbf05d87aa24680a2153df3907b23631e7177ce620fa1330ff07c0fddee54699a4c3ee0ee9d887
SHA3-512    75d527c368f2efe848ecf6b073a36767800805e9eef2b1857d5f984f036eb6df891d75f72d9b154518c1cd58835286d1da9a38deba3de98b5a53e5ed78a84976
SHAKE128    8eb4b6a932f280335ee1a279f8c208a349e7bc65daf831d3021c213825292463
SHAKE256    1234075ae4a1e77316cf2d8000974581a343b9ebbca7e3d1db83394c30f221626f594e4f0de63902349a5ea5781213215813919f92a4d86d127466e3d07e8be3
BLAKE2b     e4cfa39a3d37be31c59609e807970799caa68a19bfaa15135f165085e01d41a65ba1e1b146aeb6bd0092b49eac214c103ccfa3a365954bbbe52f74a2b3620c94
BLAKE2s     19213bacc58dee6dbde3ceb9a47cbb330b3d86f8cca8997eb00be456f140ca25
BLAKE3      ea8f163db38682925e4491c5e58d4bb3506ef8c14eb78a86e908c5624a67200f
RIPEMD-160  108f07b8382412612c048d07d13f814118445acd
Whirlpool   0a25f55d7308eca6b9567a7ed3bd1b46327f0f1ffdc804dd8bb5af40e88d78b88df0d002a89e2fdbd5876c523f1b67bc44e9f87047598e7548298ea1c81cfd73
CRC32       3610a686
CRC64       9b1edae5dbb937b1
```

### `"abc"` (standard check vector)

```
MD5         900150983cd24fb0d6963f7d28e17f72
SHA-1       a9993e364706816aba3e25717850c26c9cd0d89d
SHA-256     ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
SHA3-256    3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532
BLAKE2s     508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982
BLAKE3      6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85
```

### Empty string `""`

```
MD5         d41d8cd98f00b204e9800998ecf8427e
SHA-1       da39a3ee5e6b4b0d3255bfef95601890afd80709
SHA-256     e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
SHA3-256    a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a
BLAKE3      af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262
```

### Avalanche demo

```
MD5("hello")  5d41402abc4b2a76b9719d911017c592
MD5("hell0")  0945d6165dcab0fd5120e7a0d651f8fe  (verified — run menu 1 yourself)
MD5("Hello")  8b1a9953c4611296a827abf8c47804d7
```

Reproduce any line:

```bash
./hasher
# 1 → hello → 4   (SHA-256)
# 1 → abc   → 10  (SHA3-256)
```
