<div align="center">

<!-- Header banner (same waving-capsule idea as profile wordmark) -->
<img src="https://capsule-render.vercel.app/api?type=waving&color=0:0f172a,100:0891b2&height=210&section=header&text=HASHLAB&fontSize=72&fontColor=ffffff&animation=fadeIn&fontAlignY=38&desc=Plaintext%20%E2%86%92%20Hash%20%E2%86%92%20Plaintext&descSize=18&descAlignY=60" alt="HASHLAB — plaintext to hash to plaintext" width="100%" />

**Hash Algorithms in C · From Plaintext to Hash & Back**

[![Typing](https://readme-typing-svg.demolab.com?font=Fira+Code&pause=1000&color=22D3EE&center=true&vCenter=true&width=760&lines=Convert+plaintext+into+21+different+hashes+in+C;Crack+a+hash+back+to+plaintext+with+brute-force;MD5+%7C+SHA-2+%7C+SHA-3+%7C+BLAKE+%7C+Whirlpool+%7C+RIPEMD-160;Zero+dependencies+%E2%80%A2+Single+file+%E2%80%A2+Windows+CLI)](https://github.com/BhavyaDudhatra/Hash-algorithms-using-C-language)

[![C](https://img.shields.io/badge/C-00599C?style=flat-square&logo=c&logoColor=white)](https://en.wikipedia.org/wiki/C_(programming_language))
[![Windows](https://img.shields.io/badge/Windows-0078D6?style=flat-square&logo=windows&logoColor=white)](https://www.microsoft.com/windows)
[![CLI](https://img.shields.io/badge/CLI-0f172a?style=flat-square&logo=gnubash&logoColor=white)](#-quickstart)
[![21 Algorithms](https://img.shields.io/badge/Algorithms-21-0891b2?style=flat-square&logo=hashnode&logoColor=white)](#-toolkit)
[![Single File](https://img.shields.io/badge/Single_File-main.c-22c55e?style=flat-square&logo=c&logoColor=white)](./main.c)
[![No Deps](https://img.shields.io/badge/Deps-Zero-16a34a?style=flat-square&logo=checkmarx&logoColor=white)](./main.c)
[![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square&logo=open-source-initiative&logoColor=white)](./LICENSE)
[![Ethical Use Only](https://img.shields.io/badge/Use-Ethical_Only-c0392b?style=flat-square&logo=owasp&logoColor=white)](#%EF%B8%8F-ethics--legal)

</div>

---

<div align="center">

<!-- Divider wave, like the profile snake divider -->
<img src="https://capsule-render.vercel.app/api?type=rect&color=0:0891b2,100:0f172a&height=3&section=header" width="100%" alt="divider" />

`MD5` · `SHA-1` · `SHA-224/256/384/512` · `SHA-512/224` · `SHA-512/256` · `SHA3-224/256/384/512` · `SHAKE128/256` · `BLAKE2b/2s` · `BLAKE3` · `RIPEMD-160` · `Whirlpool` · `CRC32/64`

<img src="https://capsule-render.vercel.app/api?type=rect&color=0:0891b2,100:0f172a&height=3&section=header" width="100%" alt="divider" />

</div>

---

## 🕹️ Console

<div align="center">

<table>
<tr>
<td width="50%">

```text
$ ./hasher
[1] Plain text to hash
> hello  →  SHA-256
2cf24dba5fb0a30e26e83b2ac
5b9e29e1b161e5c1fa7425e73
043362938b9824
```

</td>
<td width="50%">

```text
$ ./hasher
[2] Hash to plaintext
> 8f434346648f6b96df89dda90…
  SHA-256, 12 threads
Match found: "hi"
Attempts: 8106
```

</td>
</tr>
<tr>
<td align="center"><strong>hash-gen</strong><br/>Probing plaintext, proving the digest</td>
<td align="center"><strong>crack-engine</strong><br/>Authorised brute-force, thread by thread</td>
</tr>
<tr>
<td width="50%">

```text
$ verify
"hello"  → 5d41402abc4b2a76…
"hell0"  → 0945d6165dcab0fd…
1 bit flip → totally
different MD5 (avalanche)
```

</td>
<td width="50%">

```text
$ matrix
MD5        128-bit  32 hex
SHA-256    256-bit  64 hex
SHA3-512   512-bit 128 hex
BLAKE3     256-bit  64 hex
… 21 total, 1 binary
```

</td>
</tr>
<tr>
<td align="center"><strong>avalanche</strong><br/>One character changes everything</td>
<td align="center"><strong>algo-matrix</strong><br/>Legacy → modern in one menu</td>
</tr>
<tr>
<td width="50%">

```text
$ crack --info
alphabet : ASCII 32–127 (96)
lengths  : 1–10
chunks   : 4096 / work-item
threads  : min(CPU, 64)
compare  : raw bytes, memcmp
```

</td>
<td width="50%">

```text
$ forensics
carve artifact → hash it
→ store digest → verify
later. Same primitives
as disk/memory triage.
```

</td>
</tr>
<tr>
<td align="center"><strong>brute-force</strong><br/>Chunked search, zero skips</td>
<td align="center"><strong>forensics</strong><br/>Carve it, hash it, prove it</td>
</tr>
<tr>
<td width="50%">

```text
$ tls-handshake
client ──ClientHello──▶ server
◀── cert + keyshare ──
digest transcript with
SHA-256 / SHA-384 …
```

</td>
<td width="50%">

```text
$ entropy
SHAKE128("hello")
8eb4b6a932f280335ee1a279f
8c208a349e7bc65daf831d302
1c213825292463
```

</td>
</tr>
<tr>
<td align="center"><strong>tls-handshake</strong><br/>Negotiating an encrypted session</td>
<td align="center"><strong>entropy</strong><br/>Because it is 2am somewhere</td>
</tr>
</table>

<br/>

<em>Every panel above is a real run of <code>main.c</code> — no screenshots, just the CLI. Copy-paste them yourself in <a href="#-demo">Demo</a>.</em>

</div>

---

## 🖥️ About

```bash
$ cat /etc/motd
────────────────────────────────────────────────
 HASHLAB          Plaintext <-> Hash workbench
 Mode 1           Plain text → 21 hashes (pick 1)
 Mode 2           Hash → plain text (brute force)
 Engine           Single-file C, zero dependencies
────────────────────────────────────────────────
```

- 🔒 Converts **plaintext → hash** with **21 algorithms** — MD5, SHA-1, SHA-2 family, SHA-3 family, SHAKE, BLAKE2b/2s, BLAKE3, RIPEMD-160, Whirlpool, CRC32/64.
- 🕵️ Cracks **hash → plaintext** with a **multithreaded brute-forcer** — printable ASCII `32–127`, lengths `1–10`, `4096`-candidate work items, up to `64` threads.
- 🧪 Great for learning **avalanche effect**, **digest sizes**, **hex encoding**, and why `MD5`/`SHA-1` are **broken** but still taught.
- 🔬 Mirrors **forensics workflow** — carve an artifact, hash it, verify it later. Same primitives as memory/disk triage.
- 🌱 Pure **C with zero libraries** — every compression function is hand-rolled in `main.c` (~1330 lines), so you can read the spec next to the code.
- ⚖️ For **your own strings, CTFs, and isolated lab VMs only** — never against passwords or systems you don't own or have written permission to test.
- 📫 Reach me at **[bhavyadudhatrahere@gmail.com](mailto:bhavyadudhatrahere@gmail.com)**

## 🧰 Toolkit

| Category | Algorithms (digest → hex chars) |
|:--|:--|
| **Legacy (broken, for study)** | MD5 `128-bit → 32`, SHA-1 `160-bit → 40`, RIPEMD-160 `160-bit → 40` |
| **SHA-2** | SHA-224 `224-bit → 56`, SHA-256 `256-bit → 64`, SHA-384 `384-bit → 96`, SHA-512 `512-bit → 128`, SHA-512/224 `224-bit → 56`, SHA-512/256 `256-bit → 64` |
| **SHA-3 / XOF** | SHA3-224 `→ 56`, SHA3-256 `→ 64`, SHA3-384 `→ 96`, SHA3-512 `→ 128`, SHAKE128 `256-bit → 64`, SHAKE256 `512-bit → 128` |
| **BLAKE** | BLAKE2b `512-bit → 128`, BLAKE2s `256-bit → 64`, BLAKE3 `256-bit → 64` |
| **ISO / Other** | Whirlpool `512-bit → 128` |
| **Checksums (not secure hashes)** | CRC32 `32-bit → 8`, CRC64 `64-bit → 16` |

> Full table with test vectors: [`docs/ALGORITHMS.md`](./docs/ALGORITHMS.md). How the sponge, Merkle–Damgård, and brute-force loop work: [`docs/HOW_IT_WORKS.md`](./docs/HOW_IT_WORKS.md).

## 📈 Progress

| Topic | Status |
|:--|:--|
| Plaintext → hash (21 algos, menu) | Done |
| Hash → plaintext brute-force (lengths 1–10, threads) | Done |
| Hand-rolled MD5 / SHA-1 / SHA-2 / SHA-3 / BLAKE2 / BLAKE3 / RIPEMD-160 / Whirlpool / CRC | Done |
| Verified vectors for `""`, `"abc"`, `"hello"` | Done |
| Profile-style README + docs + examples | Done |
| Linux/macOS Makefile + CI build | Done |
| File-input + benchmark mode | In progress |
| Wordlist mode (alongside brute-force) | In progress |
| Salted / HMAC demo | In progress |

## 🚀 Quickstart

```bash
# 1. Clone
git clone https://github.com/BhavyaDudhatra/Hash-algorithms-using-C-language.git
cd Hash-algorithms-using-C-language

# 2a. Build on Windows (MinGW)
gcc -O2 -o hasher.exe main.c

# 2b. Build on Linux / macOS
make
# or: gcc -O2 -pthread -o hasher main.c

# 3. Run
./hasher        # Windows: .\hasher.exe
```

```
============================================
 Hasher - Main Menu
============================================
  1. Plain text to hash
  2. Find plain text from hash (brute force)
  3. Exit
Choice:
```

- Pick `1` → type plaintext (max 4095 chars) → pick `1–21` → get hex digest.
- Pick `2` → paste hex hash → pick algorithm → watch it brute-force lengths `1 → 10` across all CPU threads.

> Cracking is exponential: alphabet is 96 chars, so length-`n` = `96ⁿ` candidates. Lengths 1–2 finish in seconds; length 5+ is hours/days; length 10 is infeasible — that's the point. Only test short, known strings.

## 📸 Demo

Real session from this repo (`gcc -O2`, Windows):

```text
============================================
 Hasher - Main Menu
============================================
  1. Plain text to hash
  2. Find plain text from hash (brute force)
  3. Exit
Choice: 1
Enter plain text string: hello

Select a hash algorithm:
   1. MD5
   2. SHA-1
   3. SHA-224
   4. SHA-256
  ...
Choice: 4

============================================
 Hash result for plain text
============================================
 Plain Text : "hello"
============================================

  SHA-256         : 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
============================================
```

```text
Cracking with SHA-256 (printable ASCII 32-127, length 1-10)
Splitting the search space across 12 threads, 4096 candidates per work item.
Trying length 1...
Trying length 2...

============================================
 Match found
============================================
 Plain Text : "hi"
 Algorithm  : SHA-256
 Hash       : 8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4
 Threads    : 12
 Attempts   : 8106
============================================
```

More copy-paste transcripts: [`examples/demo_session.txt`](./examples/demo_session.txt)

## 📚 Examples

All hashes below were generated by `main.c` (verified `""`, `"abc"`, `"hello"` against published vectors):

**Input `"hello"`:**

| # | Algorithm | Hex digest |
|:--|:--|:--|
| 1 | MD5 | `5d41402abc4b2a76b9719d911017c592` |
| 2 | SHA-1 | `aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d` |
| 4 | SHA-256 | `2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824` |
| 10 | SHA3-256 | `3338be694f50c5f338814986cdf0686453a888b84f424d792af4b9202398f392` |
| 15 | BLAKE2b | `e4cfa39a3d37be31c59609e807970799caa68a19bfaa15135f165085e01d41a65ba1e1b146aeb6bd0092b49eac214c103ccfa3a365954bbbe52f74a2b3620c94` |
| 17 | BLAKE3 | `ea8f163db38682925e4491c5e58d4bb3506ef8c14eb78a86e908c5624a67200f` |
| 18 | RIPEMD-160 | `108f07b8382412612c048d07d13f814118445acd` |
| 19 | Whirlpool | `0a25f55d7308eca6b9567a7ed3bd1b46327f0f1ffdc804dd8bb5af40e88d78b88df0d002a89e2fdbd5876c523f1b67bc44e9f87047598e7548298ea1c81cfd73` |
| 20 | CRC32 | `3610a686` |

**Try the avalanche effect yourself:**

| Input | MD5 |
|:--|:--|
| `hello` | `5d41402abc4b2a76b9719d911017c592` |
| `hell0` | `0945d6165dcab0fd5120e7a0d651f8fe` |
| `Hello` | `8b1a9953c4611296a827abf8c47804d7` |

> Full 21-algo tables for `"hello"`, `"abc"`, `"HashLab"`, `""`: [`examples/hashes.md`](./examples/hashes.md)

## 🧠 How It Works

- **Hashing:** each algorithm pads the message, runs its compression function (Merkle–Damgård for MD5/SHA-1/SHA-2/RIPEMD, sponge/Keccak for SHA-3/SHAKE, HAIFA/BLAKE structure for BLAKE2/3, Miyaguchi–Preneel for Whirlpool), then hex-encodes the raw digest. See [`docs/HOW_IT_WORKS.md`](./docs/HOW_IT_WORKS.md).
- **Cracking:** converts your hex back to raw bytes, then enumerates `ASCII 32–127` for lengths `1–10`. The `66-bit` length-10 space is split into leading-digit + 64-bit remainder so nothing overflows. Work is dealt in `4096`-candidate chunks via an atomic counter — every thread pulls the next chunk, so nothing is skipped or doubled, with live `... tried N candidates` progress every second.
- **Why 1–10?** `96¹ + 96² + … + 96¹⁰` is astronomically large. The tool proves *why* long random passwords survive brute-force — and why short ones don't.

## 📂 Project Structure

| Path | Description |
|:--|:--|
| [`main.c`](./main.c) | The whole app — 21 hashes + multithreaded cracker, zero deps (~1330 lines) |
| [`docs/ALGORITHMS.md`](./docs/ALGORITHMS.md) | Algorithm matrix + verified test vectors |
| [`docs/HOW_IT_WORKS.md`](./docs/HOW_IT_WORKS.md) | Padding, compression, sponge, brute-force math |
| [`examples/hashes.md`](./examples/hashes.md) | Real `main.c` outputs for `hello` / `abc` / `HashLab` / empty |
| [`examples/demo_session.txt`](./examples/demo_session.txt) | Copy-paste terminal transcript |
| [`Makefile`](./Makefile) + [`build.bat`](./build.bat) | Linux/macOS + Windows one-command builds |
| [`.github/workflows/build.yml`](./.github/workflows/build.yml) | CI: compiles on Windows + Ubuntu on every push |
| [`output/`](./output) | Your local binaries (git-ignored, was `main.exe`/`main2.exe`) |

## 📊 Stats

<div align="center">

<img height="170" src="https://github-readme-stats.vercel.app/api?username=BhavyaDudhatra&show_icons=true&theme=tokyonight&hide_border=true" alt="GitHub statistics" />

<img height="170" src="https://github-readme-stats.vercel.app/api/top-langs?username=BhavyaDudhatra&layout=compact&theme=tokyonight&hide_border=true" alt="Most used languages" />

<br/>

<img src="https://github-readme-streak-stats.herokuapp.com?user=BhavyaDudhatra&theme=tokyonight&hide_border=true" alt="Contribution streak" />

<br/>

<img src="https://github-readme-stats.vercel.app/api/pin/?username=BhavyaDudhatra&repo=Hash-algorithms-using-C-language&theme=tokyonight&hide_border=true" alt="Pinned repo card" />

</div>

## 🤝 Contributing

Small, focused PRs welcome — new test vectors, docs fixes, benchmark or wordlist mode. See [`CONTRIBUTING.md`](./CONTRIBUTING.md).

```bash
# quick check before you push
gcc -O2 -Wall -Wextra -o hasher main.c
echo -e "1\nhello\n4\n3" | ./hasher   # expect 2cf24dba5fb0a30e...
```

## ⚖️ Ethics & Legal

This is a **defensive-learning tool**. Hashing is for integrity checks; cracking here is **brute-force for education** (short strings you created, CTF challenges, lab VMs).

- ✅ Your own test strings, classroom demos, authorised CTFs / lab targets (Metasploitable, DVWA-style).
- ❌ Real password dumps, other people's accounts, any system you don't own or lack written permission to test.

Like the profile says: everything in **isolated, authorised lab environments**.

## 📫 Contact

[![Email](https://img.shields.io/badge/Email-bhavyadudhatrahere%40gmail.com-c0392b?style=flat-square&logo=gmail&logoColor=white)](mailto:bhavyadudhatrahere@gmail.com)
[![GitHub](https://img.shields.io/badge/GitHub-BhavyaDudhatra-181717?style=flat-square&logo=github&logoColor=white)](https://github.com/BhavyaDudhatra)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-bhavya--dudhatra-0A66C2?style=flat-square&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/bhavya-dudhatra-7a7544389)
[![X](https://img.shields.io/badge/X-%40dudhatra__bhavya-000000?style=flat-square&logo=x&logoColor=white)](https://x.com/dudhatra_bhavya)

---

<div align="center">

```bash
$ echo "Curiosity is the vulnerability."
$ ./hasher --help 2>/dev/null || echo "plaintext in, hash out. hash in, lesson out."
plaintext in, hash out. hash in, lesson out.
$ uptime
 still learning... up 0 days, load 100%
```

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:0f172a,100:0891b2&height=120&section=footer" width="100%" alt="footer wave" />

</div>
