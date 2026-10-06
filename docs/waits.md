# Finite waits and wakeup scheduling

Zeal is an operating system under development. This milestone adds bounded
sleep and blocking receive to its single-CPU, general-register-only supervisor.
It does not add an unbounded wait or a general-purpose scheduler framework.

## Syscall contract

ABI v2 introduced two additive call numbers; ABI v3 retains these calls and
layouts while extending storage operation rights. The
`int 0x80` calling convention uses `rax` for the call number and signed result,
`rdi` for the first argument, and `rsi` for the second. C, Rust, and Zig declare
the same call numbers, bounds, and results; compiled layout checks compare
their definitions. No existing structure or call changes incompatibly.

| Call | Number | Arguments | Successful completion |
| --- | --- | --- | --- |
| `sleep` | 11 | `rdi = duration` | `Z_OK` at or after the deadline |
| `recv_wait` | 12 | `rdi = writable message address`, `rsi = timeout` | `Z_OK` after copying one authorized message |

Durations and timeouts are unsigned scheduler tick counts from 0 through
`Z_WAIT_MAX_TICKS = 1000`. The PIT supplies 100 ticks per second in the supported
emulator configuration. Ticks measure the supervisor's clock, so these are
deadline guarantees rather than exact wall-clock delays.

`sleep(0)` succeeds and yields a runnable scheduling turn, like `yield`.
`recv_wait(address, 0)` has the same behavior as existing nonblocking `recv`:
deliver an available authorized message or return `Z_AGAIN = -4`. Neither
zero-duration operation records a pending wait. Existing `recv` remains
nonblocking.

An out-of-bound duration or a nonzero duration for which `now + duration`
overflows `uint64_t` returns `Z_INVALID = -1` without suspending. Deadline
validation precedes receive delivery, including the immediate-message path.
The supervisor never wraps a deadline or treats an overflow as an indefinite
wait. An invalid receive destination returns `Z_BAD_ADDRESS = -5`. A finite
receive reaching its deadline returns the distinct `Z_TIMEOUT = -8` and does
not copy a message to the destination. Expiry is checked before deferred
destination validation, so a due timeout returns `Z_TIMEOUT` without accessing
the buffer. The global tick clock also fails closed instead of wrapping.

## Ownership and completion

Each cell owns at most one pending wait, stored in privileged C state. It
records the cell's current generation, kind, absolute deadline, and, for
receive, the destination virtual address. The saved syscall frame belongs to
that same cell and generation. Lifecycle readiness and runnable scheduling
are distinct: a waiting cell remains a live endpoint with its capability
authority, but is excluded from runnable rotation.

The initial receive checks destination memory and searches the queue. If no
valid message is available, it publishes the pending wait before returning
to the scheduler. Queue checking, arming, enqueue, cancellation, and completion
run with interrupts disabled on the single CPU. An enqueue cannot fall into
a gap between checking the queue and publishing the wait. The completion
path checks the queue again; sends to a live waiting cell remain authorized.

Successful enqueue attempts completion of the target's pending receive.
Timer processing completes due sleeps and receives. A timeout wins once
`now >= deadline`; a message arriving at that tick cannot successfully complete
the old receive. If the message arrived and was delivered before the deadline,
the message completion wins even if the cell next runs at or after the deadline.
The pending wait is cleared once and its saved syscall result is set before
the cell becomes runnable.

Deferred delivery rechecks the wait's generation, capability validity, and
the entire writable message destination before copying. Checked copies resolve
the receiver's private backing rather than whichever cell's address space is
currently active. A failed deferred destination check returns `Z_BAD_ADDRESS`
and leaves the authorized message available for a later valid receive. A wait
cannot complete into a replacement generation.

## Revocation and cancellation

Receive preserves FIFO order among messages whose authority is still valid.
Queued entries retain the capability and target generation that authorized
them. Explicit capability revocation removes the selected grant's queued
messages and descendants while preserving unrelated entries. Delivery
revalidates authority again; a message withdrawn by revocation cannot produce
successful delivery. Removing messages does not cancel a receiver's wait:
it continues waiting for another valid message until its original deadline.

Fault, intentional stop, quarantine, and cold boot clear the affected cell's
pending wait. A dependency failure removes messages and authority involving
its old generation; unrelated cells retain their own waits, queues,
capabilities, and memory. Restart resets the cell's frame and writable memory,
so it inherits neither the old deadline nor a delayed syscall result. No
cancelled wait is returned to an already replaced caller.

## Scheduling and idle

The scheduler rotates fairly among runnable cells. Sleep and blocking receive
consume no runnable turns while pending. The execution watchdog charges only
timer ticks received while a cell is actually executing; waiting time and
supervisor idle time cannot trigger that watchdog.

When no cell is runnable, the supervisor executes `sti; hlt; cli`. Enabling
interrupts immediately before halting lets a pending or later PIT interrupt
wake the CPU without a check-to-halt race. The timer advances the clock;
supervisor polling then handles wait deadlines and lifecycle restart
deadlines before selecting a runnable cell. Waiting, stopped, quarantined,
and restarting cells retain their separate states.

## Demonstration and evidence

The RAM block and bounded filesystem services use finite blocking receive.
QEMU scenario 19 arms a probe receive on an empty queue, verifies application
reads while it waits, delivers a later application message, then checks a
zero-timeout receive, a two-tick timeout, and a three-tick sleep. Service
failure and dependency restart cancel pending receives while the client
keeps its generation and memory. A standalone scenario 19 probe proves that
the supervisor idles and wakes on timer interrupts while its only cell waits.

Structured `wait-arm`, `wake`, and `wait-cancel` records include cell identity,
generation, tick, kind, and deadline. Wake records also include the signed
result encoded as a 64-bit hexadecimal value and a reason: 1 sleep,
2 message, 3 timeout, or 4 checked-copy failure. Cancellation records include
the failure, stop, or reset reason. `idle-enter` and `idle-wake` records pair
the entry tick with a later tick and timer reason 6. `wait-progress`,
`wait-delivered`, and `wait-contract` connect supervisor events with verified
application and probe behavior.

Tracing is bounded to the first 256 armed waits per manifest cell during one
supervisor boot, across restarts, including their matching wake or
cancellation, and 16 paired idle episodes. Untraced
waits obey the same production paths. Serial evidence is diagnostic, not part
of the syscall ABI. `make test` preserves QEMU traces and machine-readable
results under `build/research/`.

The bounds remain four manifest cells, eight queued messages per cell,
32 capability records, 1000-tick finite waits, one CPU, and general registers
only. Real hardware, precise real-time scheduling, persistent storage, NVMe,
DMA isolation, SMP, shells, and recursively hosted systems remain outside
this milestone.
