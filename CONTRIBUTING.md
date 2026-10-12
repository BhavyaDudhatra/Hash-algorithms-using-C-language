# Contributing

Thanks for checking out HASHLAB! Small, focused PRs are best.

## What fits here

- New **test vectors** (`docs/ALGORITHMS.md`, `examples/hashes.md`) — must be actual `main.c` output.
- Docs fixes, clearer comments, build fixes (`Makefile`, `build.bat`, CI).
- New **read-only demo modes** (benchmark, file-hash, HMAC demo) — keep `main.c` single-file, zero-dependency.
- Please **don't** add: password lists, stolen hashes, network exfil, or anything that targets real accounts.

## Ethical-use rule

Only demo with **strings you created**, classroom examples, CTF challenges, or
isolated lab VMs (same rule as the profile: authorised environments only).
PRs that facilitate abuse will be closed.

## Quick check

```bash
# Windows
gcc -O2 -Wall -Wextra -o hasher.exe main.c

# Linux / macOS
make linux

# Smoke test — must print HASH_OK / contain the SHA-256 of "hello"
printf '1\nhello\n4\n3\n' | ./hasher | grep 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
```

Keep style consistent with the existing C (explicit widths, `static` helpers,
no new third-party code) and update `README.md` + `docs/` if you change the menu.
