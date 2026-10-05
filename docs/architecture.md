# The first substrate

Zeal's long-term unit of composition is a sealed system, called a cell. A cell
has an immutable boot image, private memory, a lifecycle, and explicitly granted
communication edges. The same contract should eventually describe both leaf
services and cells that host child systems. This milestone implements leaf
cells; recursive hosting is not implemented.

| Layer | Implementation | Responsibility |
| --- | --- | --- |
| Boot and traps | Assembly | BIOS loading, long mode, register capture, privilege return |
| Supervisor | C | Address spaces, timer scheduling, checked memory copies, bounded IPC |
| Policy | Rust, `no_std` | Lifecycle transitions, epochs, restart budget, directed authority |
| Cells | Zig | RAM block service, immutable filesystem, application, adversarial probes |

## Protection

The supervisor executes at ring 0. All cells execute at ring 3 with IOPL zero
and no I/O bitmap permissions. Each cell has its own CR3, image pages, and stack
pages. The supervisor's low identity mapping is supervisor-only. Cells share
virtual addresses, never physical storage:

| Range | Access |
| --- | --- |
| `0x40000000..0x40010000` | Private immutable image, read and execute |
| `0x40020000..0x40024000` | Private stack, read and write, non-executable |
| Gaps around these ranges | Unmapped guards |

CR0.WP enforces read-only mappings in supervisor mode too. The supervisor writes
image backing through its private physical alias during cold boot. Floating
point and vector execution are disabled until context preservation is added.
Compiler targets emit general-register code only. This is a CPU isolation
boundary; it does not yet isolate DMA, shared caches, firmware, or hardware
failures. Drivers receive no raw hardware access in this milestone.
All optional CR4 facilities are disabled, and alternative SYSCALL/SYSENTER
entry paths are disabled. User return frames require the ABI's selectors and
canonical addresses; the supervisor strips privileged return flags.

The PIT supplies 100 Hz interrupts. Scheduling rotates ready cells on timer
interrupts and syscalls. A cell that makes no syscall for five of its charged
timer ticks is failed by the supervisor. This bounds the infinite-loop probe.
It is a research watchdog, not a real-time guarantee; a looping cell that keeps
calling syscalls can continue receiving its fair share.

## Communication

ABI version 1 uses `int 0x80`; `rax` is the operation, `rdi`, `rsi`, and `rdx`
are arguments, and `rax` returns a signed result. Definitions live in
`include/zeal/abi.h` and `cells/abi.zig`; both sides check their layouts.

Messages contain an endpoint, operation, length, and at most 32 bytes of data.
The broker replaces the sender field and zeros unused payload bytes. All queues
are bounded to eight messages. No cell pointers cross a protection boundary.
Checked ranges reject overflow, unmapped gaps, supervisor addresses, and writes
to image pages before a kernel copy occurs.

The fixed directed authority graph permits block → filesystem,
filesystem → block/application, and application → filesystem. The adversarial
probe has no send authority. Endpoints encode a slot and generation; possession
alone does not grant authority. The broker checks the current sender's edge,
the target's phase, and its epoch. This static graph is a bootstrap capability
policy; dynamic delegation and per-operation rights remain future work.

## Cold boot and recovery

On a user exception or watchdog failure, the supervisor records the fault,
empties the failed cell's queue, drops messages sourced by that cell, and makes
its endpoint unavailable. Unrelated queues and address spaces stay intact.
Rust policy schedules recovery after 4, 8, and 16 ticks. Before re-entry, the
generation advances, image and stack backing are cleared, the immutable image
is copied again, and the register frame is reinitialized.

Three restarts are allowed per cell lifetime. A fourth fault quarantines the
cell. A healthy interval does not reset this budget. Generation exhaustion or
deadline overflow also quarantines; endpoints never wrap. Intentional exit
uses a separate terminal stopped state. Old endpoints remain invalid after
recovery. A kernel-origin exception is a trusted failure and stops the machine
with a diagnostic; it cannot be misreported as a recoverable cell crash.

The storage chain reads `/hello` from RAM sector zero through the filesystem.
Each response validates sender generation, operation, payload length, and
content. Pending operations are retried after dependency rebinding. There is
no persistence or claim of transaction durability across a restart.

## Next milestones

1. Boot manifests, cell-defined memory budgets, and dynamically granted endpoints.
2. Recursive supervisors using the same boot/lifecycle contract.
3. PCI discovery, interrupt routing, NVMe queues, and an IOMMU-backed DMA boundary.
4. Persistent filesystem recovery, SMP scheduling, and complete extended CPU state.

Hardware driver recovery must first stop DMA and interrupts, revoke device
ownership, and re-establish a clean device state. Restarting a CPU task alone
does not establish an NVMe containment guarantee.
