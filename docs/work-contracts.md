# Native work contracts

Scenario 24 implements one isolated broker (approved template 3, supervisor
image 5) beneath authenticated root identity 400. Its approved leaf workers use
template 4, worker image 6. These templates are declared in `cells/contracts.toml`;
existing templates 1/2 and scenarios 21–23 keep their original behavior.
Scenario 25 explicitly selects templates 5/6 and profile 2 using the same core;
see [immutable-input byte analysis](file-analysis-contracts.md).
ABI 4 and manifest 2 remain compatible. No kernel syscall, privileged contract
object or second creation engine is added.

`cells/contract_core.zig` owns the finite service table;
`cells/contract_dispatch.zig` owns exact service admission;
`cells/contract_wire.zig` defines the byte protocol. The isolated runtime invokes
the same core through a controlled lifecycle/transport seam. Its callbacks use
actual checked domain status, creation, IPC, status, stop, reap and rebind calls.
Direct host tests invoke this production code. Kernel behavior is tested
separately by production C/Rust cases and actual QEMU execution.

## Ownership, profile and backing

The broker obtains its self endpoint, parent requester, template, logical
instance and creation domain from trusted BootInfo. Requests authenticate the
exact parent endpoint generation through kernel IPC. A role, image, numeric
identity, contract reference or matching input does not grant authority.
For scenario 24, the broker holds request/reply bootstrap channels only; workers have a narrow
reply-only channel to their owner and no filesystem/raw block rights.

Profile 1 selects the approved two-page worker, fixed scalar input/result rule,
two maximum concurrent backings and one maximum retry. Every u64 input is a
bounded declared input. The result is FNV-1a over `Zeal bounded ring-3 worker`
and the eight little-endian input bytes, with initial value
`0xcbf29ce484222325` and multiplier `0x100000001b3`, modulo 2^64.
The broker and requester independently recompute it, and the Python oracle
recomputes it from authenticated delivery evidence. Fixed demonstration inputs
also exercise finite sleeps or a first-attempt `ud2`; the checking rule is
unchanged. This is pure deterministic work, not arbitrary code or retry-safe I/O.

There are exactly two service records, including retained terminal records.
Before publishing an offer, the broker validates owner/profile/transaction,
record/serial availability and the actual delegated domain. It then creates one
worker through the production creation engine, checks status and exact channel
rights, and waits for that execution's cold-memory/bootstrap acknowledgement.
The worker enters ring 3 and waits without computing the offered input.
Only explicit acceptance dispatches work.

The broker has two descendant slots/four descendant pages and four own pages.
For normal live/settled contracts:

`backed worker slots/pages + available descendant slots/pages = 2/4`

The root ledger separately conserves
`owned allocations + reserved subdomain allowance + available credit = 4/48`.
The broker's own 4 pages are charged once at the root; its delegated 4-page
allowance is reserved separately. A worker consumes its immediate domain's
credit and is not charged again at the root. Two actual workers have distinct
physical page ownership. Reserved credit is not free physical memory or a CPU
reservation. Terminal metadata consumes a service record but has zero normal
worker allocation; a third record request cannot allocate another worker.

## Three lifetimes and references

The broker execution, contract service record, and worker logical/execution
attempt are distinct lifetimes. A 64-bit service reference contains:

| Bits | Meaning |
| --- | --- |
| 0–7 | Disjoint service tag `0x80` |
| 8 | Record slot, 0 or 1 |
| 9–31 | Nonzero 23-bit serial, at most `0x7fffff` |
| 32–63 | Complete broker execution endpoint: 24-bit generation and 8-bit slot |

The exact issuer endpoint and requester generation are checked independently.
The issuer slot must be 1–8, and its generation 1–`0xffffff`. Larger kernel
generations close service issuance instead of truncating. Serial exhaustion
closes issuance rather than wrapping. Reap does not reset the serial. Broker
cold boot clears its private table and uses its new execution scope; old tokens
stay stale, including tokens from a different broker slot with the same
generation. Tokens cannot decode as kernel endpoint, IPC, instance/control,
creation-domain or file-handle authority.

A worker restart preserves its logical instance/control and actual private
allocation, while retiring the old endpoint/channels. The contract retains its
accepted input and token but records a fresh attempt/RPC identity. Broker or
requester retirement has a wider boundary: existing kernel owner-generation
cleanup retires and reaps the broker's worker subtree. There are no durable
receipts, adoption, authority transfer or restored terminal records across a
broker cold boot.

## Fixed byte protocol

Packets reuse authorized IPC operations 15/16. They are exactly 32 payload bytes,
with explicit little-endian integers and no heap, strings, JSON or arbitrary
operation names in cells.

| Offset | Width | Meaning |
| --- | --- | --- |
| 0 | 8 | Nonzero requester transaction or worker RPC identity |
| 8 | 1 | Version 1 |
| 9 | 1 | Command |
| 10 | 1 | Kind: request 0, response 1, snapshot 2, failure 3 |
| 11 | 1 | Exact command-specific profile, attempt or snapshot-part field |
| 12 | 4 | Reserved zero bytes |
| 16 | 8 | Service token, or zero where explicitly permitted |
| 24 | 8 | Command-specific input/offer transaction/result/part value |

| Command | Request |
| --- | --- |
| OFFER 1 | Detail=profile 1, token=0, data=input |
| ACCEPT 2 | Detail=profile 1, exact token and input |
| STATUS 3 | Detail=0; exact token/data=0, or token=0/data=offer transaction |
| CANCEL 4 | Detail=0, exact token, data=0 |
| RECEIPT 5 | Detail=0, exact token, data=0; requires terminal state |
| REAP 6 | Detail=0, exact token, data=0; requires terminal, unbacked record |
| WORK 7 | Broker-to-worker only: detail=attempt 1/2, exact token/input/RPC |
| 8 | Reserved fault command; invalid at the service/worker dispatcher |
| BOOTSTRAP 9 | Worker reply only: id=1, detail=0, token=0, data=logical instance |

Malformed envelope/version/length/sender/operation/reserved bytes are ignored
before service mutation. A valid envelope with invalid command-specific fields
receives bounded failure when its owner reply channel is available. Unknown
commands do not become kernel syscalls. Failure codes are denied=1, invalid=2,
stale=3, record/resource pressure=4, counter exhaustion=5, resource failure=6,
transport failure=7, cleanup failure=8, not terminal=9 and not ready=10.

Status/receipt and successful OFFER/ACCEPT/CANCEL return one frozen snapshot as
eight ordered packets (detail 0–7), all matching exact issuer, requester,
transaction, command and token. The fields are flags, input, requester endpoint,
issuer endpoint, worker instance, current/last attempt endpoint, worker RPC and
verified result. Flags pack state/profile/retry/attempt/reason/backing slots/
backing pages in successive bytes; bit 56 is verified, and higher bits are zero.
For attempt 0, the endpoint identifies the offered backing execution. For a
nonzero attempt, it identifies the last assigned dispatch execution, even when a
fresh rebind is followed by RPC-counter exhaustion before another dispatch. A
terminal endpoint grants no live execution.
A snapshot is usable only after all eight matching parts arrive and validate.
It reflects capture before transmission, not an unreliable notification.
REAP acknowledges with one response packet. A missing/partial response leaves authoritative STATUS/RECEIPT available for
resynchronization, without repeating successful work. The fixed emulator
requester explicitly recovers its deliberate whole-response discards; its
unexpected collection-timeout path fails the isolated demonstration rather than
providing a general automatic retry library. Partial collection followed by a
fresh query is exercised by production transport/dispatcher host cases.

Requester transaction, broker serial, worker RPC and attempt identities are
separate namespaces. Transaction correlation includes the complete authenticated
sender generation. Different actors may choose request 1. OFFER exact replay
returns the retained record/current state; changed profile/input is invalid.
Successful prevalidation consumes the offer transaction high-water and serial
before creation, so an unpublished creation failure retires both identities.
Owner/shape/profile, record capacity, issuer/serial and domain-preflight failures
consume neither. An earlier consumed transaction without a retained record is
stale. After explicit record reap, its old transaction cannot allocate again.
This is narrow control-path idempotence, not universal replay protection or
exactly-once side effects.

## Transitions, settlement and cancellation

`FREE → OFFERED → RUNNING → COMPLETED`

`RUNNING → RECOVERING → RUNNING` permits exactly one fresh retry.
OFFERED/RUNNING/RECOVERING can become CANCELLED or FAILED.
COMPLETED/CANCELLED/FAILED return to FREE only through explicit record reap
after their actual backing charges are zero.

Exact duplicate acceptance in RUNNING/RECOVERING/COMPLETED returns current state
without another allocation/attempt. Changed input/profile is invalid; accepting
CANCELLED/FAILED is not ready. STATUS has no work side effect. Repeated cancel
preserves an already settled terminal decision; it cannot erase a completed
receipt. Live record reap is denied, and repeated reap is stale.

Worker result admission checks sender execution, token, state, RPC, attempt,
operation/header and independently recomputed input result. Successful
verification precedes real checked stop, zero-page terminal status, worker reap
and stale-control confirmation. Only then does the broker publish COMPLETED
with a verified result and zero backing. Admission records the actual execution
generation, fault count and restart count. After checked stop has frozen the
worker's execution, terminal status must retain the same tuple before successful
publication. An intervening fault/restart produces FAILED/lifecycle, zero result
and no verified receipt while checked cleanup still returns resources. Saturated
fault counters fail admission closed. This fences retirement across the status
sample and settlement without introducing a new kernel transaction object.
Pages return at stop; the kernel slot/
control state returns at worker reap; service metadata returns at contract reap.

Cancellation uses real stop/reap, retiring runnable state, waits, restart plans,
related queues and authority. If successful result settlement already committed,
cancel returns that terminal state. If cancellation commits first, queued or
already-dequeued private results cannot change it or refund resources twice.
Private result storage checks exact live binding before occupying a slot and
again at consumption, and frees predecessor delivery state before record reuse.
Unrelated contract replies and FIFO inbox traffic are preserved.

A lifecycle invariant failure publishes no successful receipt or fictitious
refund. Actual remaining charges are read from the domain and remain visible
as FAILED/lifecycle. One explicit cancellation can retry partial cleanup, with
at most two cleanup attempts total. Further failure retains its honest charges
and denies record reap; checked retirement of the entire broker is the owner's
cleanup boundary. This exceptional path is tested separately from normal
complete settlement.

## Recovery, transport and evidence limits

A recoverable fault retires attempt authority immediately while retaining real
backing. The runtime reconciles checked lifecycle observations before owner
snapshots and before consuming staged results. Pre-command observation does not
start a fresh retry ahead of an already dequeued owner cancellation. A checked
status sample defines the service observation boundary; the protocol does not
claim an atomic kernel/service transaction spanning multiple syscalls. The broker can observe BACKOFF or detect a newer READY endpoint if it
missed the short backoff interval. It queries the stable control, rejects old
endpoint/channel authority, and explicitly rebinds through its live creation
domain before a new attempt. The restarted worker cold-checks memory and waits
for current channels; absent channels do not themselves cause a crash.
The new endpoint generation and RPC must be fresh, with the same input,
instance/control and one maximum retry. A second fault, or an unavailable quarantined/stopped worker observed without
an owner cancellation, becomes FAILED and cleans up. Both kernel terminal phases
are eligible for checked worker reap; unavailable execution is not reported as
owner consent to cancel. There is no implementation hot swap or independent scheduler.

Each enqueue has at most four attempts with one-tick backpressure sleeps.
Requester collection has sixteen finite ten-tick receive steps. Worker bootstrap
acknowledgement uses sixteen one-tick receive steps; the existing cold-bootstrap
gate permits 160 one-tick rebind waits. The broker has eight FIFO deferred inbox
entries, two worker-result staging slots and an eight-iteration result window
that allows owner control to commit before validation. Accepted attempts expire
after 160 broker receive iterations. These are finite state-machine bounds, not
CPU reservations, wall-clock leases or latency guarantees. Partial reply enqueue
retains the owner-scoped record for resynchronization.

Structured trusted seams include admitted template/domain configuration, actual
creation/publication/frame/page initialization, first hardware ring-3 trap,
authenticated IPC enqueue/copy delivery, status, stop, reap, restart, fresh channel
mint epochs and domain changes. Broker/worker progress is joined to those seams.
Scenario 24 has a fixed quota of 2,048 hosting trace events, 256 hosting reports,
and 2,048 storage events/reports; exhaustion fails. Old hosting storage quotas
remain 1,024, and legacy storage quotas 512.

The dedicated oracle independently reads the tested manifest/linked images,
reconstructs tree/resource/page/channel ledgers, checks all contract transitions
and snapshots, recomputes receipts, and retains removal/coordinated counterfeit
controls and discovered false-positive witnesses. The original root-300 storage
application byte-verifies `/hello`, `/alpha` and `/beta` through actual filesystem
and block services in generation 1 throughout. Measured recovery ticks run from
fault to the first requester-verified current-attempt receipt after rebind;
broker terminal-publication ticks are reported separately. They are observations
including requester waits/IPC, not a hard recovery guarantee.
