# Research validation

Run `make test`. Failure in any layer returns a nonzero result. The suite keeps
serial traces and a machine-readable result file under `build/research/`.
GitHub Actions runs the same targets and retains these artifacts on failure.

## Host checks

The Rust policy tests exercise ABI layout, all directed authority edges,
generation exhaustion, deadline overflow, repeated faults, restart limits,
stale endpoints, intentional exit, and malformed states. An independent
lifecycle model checks 299,593 bounded trace nodes and 65,536 deterministic
adversarial steps. These are bounded checks, not a proof over all executions.

The production C broker runs under AddressSanitizer and UndefinedBehaviorSanitizer.
Checks cover queue saturation, wraparound FIFO order, copying instead of aliasing,
forged sender replacement, payload zeroing, authority rejection, stale senders,
and revocation that preserves unrelated messages. A separate list-based model
checks 100,000 deterministic broker operations. Pointer checks compare production
range validation with a separate arithmetic oracle at boundaries and over
100,000 generated address/length pairs.

Zig tests cover service protocol state, exact byte lengths, malformed operations,
wrong senders, oversized requests, and rebinding during outstanding work. Artifact
tests reject corrupt boot sectors, overlarge payloads, invalid ELF identities,
writable cell segments, and truncated or out-of-bounds headers.

## Emulator checks

The runner boots a real raw image under TCG and checks CPU exception vectors,
error bits, fault addresses, generation changes, restart delays, quarantine,
application survival, and resumed verified reads after storage and filesystem
fault injection. A `RESEARCH_PASS` line alone is insufficient: the external
runner validates the event trace and emulator exit status independently.

Cases include invalid instructions, supervisor memory writes, code writes,
execution from an NX stack, CLI, port I/O, a non-cooperating loop, invalid syscall
pointers, forged endpoints, null reads, stack guards, unmapped reads, disabled x87
and SSE instructions, and direction-flag preservation across a syscall. A probe
writes a stack sentinel before faulting and checks that each cold boot cleared it. The
suite also rejects noncanonical return stacks and checks that unconfigured
SYSCALL/SYSENTER entry paths fault inside the cell on AMD and Intel models. The
kernel-fault control must produce a kernel diagnostic and a failure exit, never
a successful recovery. CPUs without long mode or NX must fail before cell boot.

All scenarios run twice by default. Platform checks cover `max` and `qemu64`
CPUs with 32–128 MiB RAM. Separate images boot block, filesystem, and application
cells alone. Their absent dependencies must cause waiting, not a kernel failure.
Two additional probe-only boots check supervisor timer progress while every cell
is either backing off, quarantined, stopped, or dormant.

The demo injects a RAM driver failure at tick 20 and a filesystem failure at tick
40. It requires fresh service generations and new IPC activity before marking
each recovery. The application must remain in its original generation. At tick
120, it checks that the failed probe exhausted its restart budget or exited after
successful syscall checks, and that healthy cells remain ready.

These checks do not establish real-hardware correctness, DMA containment, NVMe
reset safety, SMP correctness, persistent data integrity, or side-channel
isolation. Those require their own future test campaigns.
