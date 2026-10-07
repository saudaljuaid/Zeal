# Zeal's current substrate

Zeal is an operating system under development. Its long-term unit of
composition is a sealed system called a cell. A cell has an immutable boot
image, private memory, a lifecycle, and explicit
communication authority. Manifest roots can supervise approved runtime cells
through bounded ring-3 management operations. The implemented hierarchy is
root → child supervisor → grandchild worker, with four globally available
runtime child slots. All cells execute under one privileged supervisor and one
global scheduler. See [hosting policy](hosting-policy.md),
[management ABI](hosting-abi.md), and [application protocol](hosting-apps.md).

| Layer | Implementation | Responsibility |
| --- | --- | --- |
| Boot and traps | Assembly | BIOS loading, long mode, register capture, privilege return |
| Supervisor | C | Address spaces, allocation, scheduling, checked copies, IPC, atomic lifecycle orchestration |
| Policy | Rust, `no_std` | Lifecycle, hierarchy, generation, resource accounting, capabilities and authority |
| Cells | Zig | Writable RAM block service, bounded filesystem, applications, supervisor/worker and probes |

## Manifest and image validation

`cells/manifest.toml` is the human-edited source. `tools/manifest.py` compiles
it into a fixed-width, little-endian v2 artifact. The field schema and bounded
limits are declared once in `include/zeal/manifest_schema.def`; the compiler
reads those record declarations when constructing the artifact. The kernel
validates the artifact again with `kernel/manifest.c` before it creates any
cell address space. There is no general parser in the kernel.

The 40-byte header contains magic `0x4c41455a`, version, exact total size, cell
and grant counts, template/domain counts, and zeroed reserved words. Each 64-byte cell record contains
a nonzero stable identity, diagnostic name, image identity, ABI version, entry,
image/stack/writable budgets, boot configuration, restart limit/delay, and
active flag. Each 16-byte grant names a holder identity, target identity,
operation-right mask, and zeroed flags. Integers have explicit 32- or 64-bit
widths. Variable byte strings are limited to 15 ASCII characters plus a NUL.
Records contain no pointers, padding, or implicit host-endian values.

The kernel rejects unsupported versions, incorrect or truncated sizes,
nonzero reserved fields, unsupported counts, duplicate identities, malformed
names, unknown images or grants, ABI/entry mismatches, image overruns,
unsupported lifecycle settings, impossible memory budgets, invalid rights,
and duplicate holder/target grant pairs. Arithmetic is bounded before record
offsets are calculated. The build compiler applies the same explicit limits,
and the privileged validator treats every boot byte as untrusted.

The schema supports four manifest roots, 16 initial grants, eight approved
templates, eight root domain records, and a 1320-byte maximum boot artifact.
Templates are sealed creation configurations, separate from live runtime records;
only identity 400 has a creation domain in the hosting configurations. Images are at most 65,536 bytes and must have the sealed entry at
`0x40000000`. The default
block → filesystem → client chain, fault probes, and standalone boots all use
this artifact. A standalone build changes active flags in the compiled
manifest; it does not use a separate hardcoded configuration path.

## Protection and memory ownership

The supervisor runs at ring 0. Cells run at ring 3 with IOPL zero and no I/O
bitmap permissions. Every active cell has private page tables, immutable image
backing, and physically separate writable backing. A user virtual address may
be shared between cells; its physical page is not. The low identity map and
all supervisor structures remain supervisor-only. CR0.WP enforces read-only
image pages, and writable cell mappings are NX.

Each cell has these address ranges:

| Range | Access |
| --- | --- |
| `0x40000000` plus rounded image budget | Private, read and execute |
| `0x40020000` plus rounded stack budget | Private, read/write, NX |
| `0x40030000` plus rounded heap budget | Private, read/write, NX |
| Gaps around these ranges | Unmapped guards |

The manifest's writable budget includes stack and heap bytes. The stack is
rounded up to 4 KiB pages first; the remaining writable byte budget is rounded
up separately for the heap. The image budget is rounded up to image pages.
Consequently the mapped total may exceed the byte budget by less than one page
for each separately rounded region. Rounding is checked against both the
per-cell and global page limits.

The fixed private page pool has 128 pages (512 KiB), up to 20 pages per cell.
The four roots retain their original 80-page allocation: 16 KiB stack plus 64 KiB heap
each. At most 48 additional pages can be committed to descendants, with
separate logical reservations and actual physical ownership. Supported stack budgets are 4–16 KiB; heap budgets are 0–64 KiB; total
writable budgets are at most 80 KiB. The pool allocator first finds every
required page, then clears and claims them together, so exhaustion leaves no
partial allocation. A restart clears the same owned backing; it does not
allocate again. Stopping a cell clears and releases its pages for reuse.

The 512 KiB writable pool is separate from image backing, page tables, kernel
stacks, and capability/queue tables. Those fixed supervisor costs are statically
allocated and are not charged to a cell budget. The boot image and all static
supervisor memory remain below the 4 MiB identity-mapped boot region. The
supported emulator configurations use 32–128 MiB of RAM; 32 MiB is the tested
minimum for this image and device model.

Checked syscall copies validate overflow, canonical user ranges, mappings,
and write permissions before copying. They never expose cell pointers to
another cell. A cold boot zeros all writable pages before resetting the frame
and restoring the image. The probe checks both stack and heap sentinels after
each restart.

## Communication authority

ABI v4 uses `int 0x80`, preserving the finite `sleep` and `recv_wait`
calls and existing structure layouts while adding bounded storage operations.
`include/zeal/abi.h`, Rust FFI layouts, and Zig's
`cells/abi.zig` define the same call numbers, message layout, capability
records, and result codes; tests compare the compiled C and Zig layout reports.
Endpoint lookup uses stable manifest identities. Endpoints identify a cell
generation; endpoints grant no authority by themselves.

The manifest creates initial capabilities. A capability records its holder
endpoint, target endpoint and generation, operation rights, parent grant,
issuer, and a unique epoch. `send` requires both a target endpoint and a
capability handle. The supervisor maps each message operation to one right and
checks the exact holder, target, target generation, and requested right before
queueing a copied message. Cells still validate protocol senders and payloads,
but those checks do not replace supervisor enforcement.

The capability table holds 32 entries and the manifest may define 16 initial
grants. Rights cover the sixteen defined message operations; a separate high
bit permits delegation. Delegation requires a live capability held by the caller
with that bit set. New rights must be a subset of the parent, and the delegated
target and generation remain the parent's target. A holder cannot amplify
rights or delegate through a capability without delegation permission. Table
exhaustion returns `Z_NO_SPACE` without inserting a partial grant. Epochs never
wrap or repeat; exhaustion is a terminal resource error.

Explicit revocation is allowed to the capability holder, its issuer, or an
ancestor holder. It invalidates the selected grant and all derived grants.
Cell fault, stop, or quarantine invalidates grants involving its endpoint and
removes its queued messages. Target restart also invalidates grants naming the
old generation. Reused table slots receive new epochs, so stale handles do not
become valid again.

Each queued message retains the authority handle and target endpoint that
authorized it. Revocation compacts the bounded queues, retaining unrelated
messages in FIFO order. Receive checks the authority again before delivery,
which closes the enqueue-to-delivery race. Revocation cannot undo work already
delivered to a service.

The manifest grant list is the root authority source. When endpoints return
ready after a restart, Rust policy issues fresh-generation root capabilities
from that list. Runtime grants are discarded and never reconstructed. Existing
clients must look up the new endpoint and obtain fresh authority before sending.

## Scheduling, failure, and recovery

The PIT supplies 100 Hz interrupts and the supervisor rotates runnable cells.
Each live cell can own one generation-bound finite sleep or receive wait.
Waiting cells remain ready endpoints but consume no runnable turns; timer
deadlines or valid messages make them runnable again. The supervisor checks
receive authority and private destination memory before deferred delivery.
If no cell is runnable, it enables interrupts and halts until a timer wakes it
to process waits and lifecycle deadlines. See [wait contracts](waits.md) for
zero-duration behavior, ordering, cancellation, and the 1000-tick bound.

A cell that makes no syscall for five charged ticks is failed; this bounds the
infinite-loop probe but is not a real-time guarantee. A looping cell that
continues making syscalls may continue receiving its fair share. Sleeping,
receiving, and supervisor idle time do not charge the execution watchdog.

Cell exceptions and watchdog failures cancel pending waits, revoke authority,
clear the failed cell's queue, discard messages from the failed generation, and leave unrelated
queues and address spaces intact. Rust policy restarts after 4, 8, and 16
ticks. Three restarts are allowed per cell lifetime; a fourth fault quarantines
the cell. Generation and deadline overflow fail closed. Intentional exit is a
separate stopped state. A kernel-origin exception stops the machine with a
diagnostic and is never treated as a recoverable cell fault.

The application reads `/hello` through the RAM block service and bounded
filesystem. The recovery scenario delegates a `file_read` capability at
runtime, checks an allowed read and a forbidden `read` operation, revokes the
grant, rejects the stale handle, restarts the filesystem, rejects its old
endpoint generation, obtains a fresh manifest grant, and verifies reads resume.
The application remains in its original generation and reports unchanged
stack and heap sentinels throughout recovery.

## Writable storage and generation-safe handles

The block cell owns 512 bytes in its manifest-budgeted private writable memory.
It initializes `/hello`'s 14 bytes and zeros the remainder on every cold boot.
Eight-byte reads and writes reject overflow and out-of-range addresses before
copying. The filesystem stores metadata and handles without caching file data;
every byte operation crosses the isolated block-service boundary.

The flat filesystem has four fixed 128-byte extents, including read-only
`/hello`, 16-byte maximum names, and eight open handles. Create-or-open, explicit
offset read/write, and close use ABI v4's bounded 32-byte payloads. Creation
zeros an entire free extent through the block service before publishing it;
writes grow length only after the matching block acknowledgment. Gaps are
unsupported and multi-chunk operations can leave an acknowledged prefix.

Handles bind the exact owner endpoint and its generation to a filesystem
generation, monotonically increasing 24-bit serial, and slot. Closed, forged,
cross-owner, reused-slot, and earlier-generation handles stay stale; exhaustion
never wraps. Operation capability checks remain independent of handle
possession. Kernel delivery revalidates queued authority, while already
received service work can finish after revocation.

Filesystem restart discards writable metadata and handles but can leave bytes
private in a healthy block cell; reuse clears those bytes before exposure.
Block restart clears storage and causes filesystem metadata and handle
invalidation without resetting the filesystem serial. Interrupted writes may
already have changed bytes, and lost replies have an unknown outcome rather
than exactly-once behavior. See [storage contracts](storage.md) for limits,
protocol fields, result semantics, and bounded retry/receive rules.

Scenario 20 creates, writes, closes, reopens, and byte-verifies `/note` through
both services. It rejects an unauthorized write and old file handles, then
resumes verified work after separate block and filesystem restarts. Structured
records bind application progress to the participating service generations and
request identities. Healthy application memory and the existing recovery,
authority, and wait demonstrations remain part of the verification suite.

## Current boundary and open work

Storage is volatile and the filesystem has the fixed flat limits above.
The supervisor is single-CPU and preserves general registers only.
General recursive hosting, arbitrary executable loading, hardware NVMe, DMA isolation, device ownership and reset,
persistent storage, SMP, and extended CPU context are not implemented. These
need separate contracts and tests; this milestone makes no DMA-containment or
general recursive-supervision or nested-kernel claim. Hardware recovery must stop device DMA and
interrupts and re-establish device state before CPU restart can be meaningful.
