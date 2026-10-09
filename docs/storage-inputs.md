# Immutable inputs and object-scoped admission

The filesystem service owns a bounded volatile input table in
`cells/snapshot.zig`. Its production dispatcher is
`storage_runtime.Server.processWith`; the ring-three adapter performs block
IPC and the host adapter drives the same dispatcher against production
`storage.Fs` and `storage.Block`. A snapshot is a service record, not a kernel
file object. Knowing its reference, the source path, or a worker identity does
not authorize IPC.

## Backing and separate lifetimes

| Retained resource | Capacity and lifetime |
| --- | --- |
| Snapshot records | Two, including capturing, failed, closed and settled metadata |
| Immutable byte buffers | Two fixed 128-byte buffers, one per record; no heap |
| Explicit readers | Two full endpoint bindings per record, for worker and checker |
| Checker designation | One exact endpoint per record, explicitly selected by owner |
| Capture transaction metadata | Owner endpoint, creation transaction, source handle, block endpoint, file index, length and revision |
| Storage deferred inbox | Existing eight 48-byte messages; capture does not allocate another inbox |
| Current block transfer | One existing transaction and one eight-byte chunk buffer |
| Ordered analysis reader | One fixed 128-byte private accumulator and one eight-byte response at each participating analysis cell |
| Analysis output scratch | One caller-owned 128-byte output buffer during each collection; the accumulator copies into it only after complete EOF validation |
| Snapshot RPC sequence | One nonwrapping 64-bit transaction counter per client |
| Owner creation high-water marks | Eight full endpoint/transaction pairs, 128 bytes; one latest generation per runtime slot, retained across object reap and owner retirement |
| Filesystem reply proof cache | Eight full nonwrapping capability handles, 64 bytes; records only whether a current route epoch has already been queried for kernel trace evidence |

The two fixed snapshot buffers remain part of the filesystem's private memory
allocation throughout its lifetime. `backing()` accounts 128 bytes for each
capturing or live record. Closing or checker settlement zeros every byte,
clears both reader bindings and reduces occupied byte backing to zero. This
returns temporary input occupancy, rather than freeing filesystem pages.
Owner-retained closed/settled metadata continues to occupy its record until
explicit reap. `retained()` counts that metadata honestly.

A source handle can close after capture without closing its immutable input.
A reader binding is neither a source handle nor a kernel capability. The
worker attempt and contract record have their own lifetimes. Kernel routes
retire through actual hosted subtree cleanup; service bindings retire through
owner revoke, close, checker settlement or owner/dependency retirement. The
contract's retained receipt survives worker retirement. Owner input reap and
contract reap release their respective retained table entries separately.

## Coherent capture

An authenticated owner creates an input using its own valid existing file
handle. The owner needs `snapshot_control` authority independently of handle
possession. A copied handle fails the filesystem's exact owner check. The
approved owner endpoint is the current scenario owner root; role lookup only
locates it. The kernel's configured operation grant authorizes communication.
Deferred predecessor-owner control traffic is rejected after retirement.

Creation reserves a record and a fresh serial after validating owner,
transaction, source handle, file extent, dependency, table space and counter
space. The captured length comes from the actual filesystem metadata. Each
chunk comes from that handle's production `prepareRead` plan and the actual
block service reply. No application expected string supplies capture bytes.
Lengths zero through 128 are supported, with at most sixteen eight-byte block
reads. Empty capture needs no byte transfer.

The filesystem dispatches one service operation at a time on the single CPU.
A capture runs synchronously to publication. Its nested block waits place
unrelated dequeued traffic in the existing finite FIFO; they do not dispatch
file writes, truncation, file closes or snapshot controls between capture chunks. After
capture returns, ordinary dispatch drains the deferred traffic in FIFO order.
This is the capture barrier: file writes ordered before capture are included;
writes dispatched after capture change only the source. This does not make a
client's separate multi-chunk write sequence an atomic transaction.

The block service accepts mutations only from the exact current filesystem
endpoint and processes its bounded kernel queue in FIFO order. A previously
enqueued write whose acknowledgement was lost is therefore processed before
later capture reads, or is removed by authority/generation retirement. It
cannot arrive between later capture chunks as an independently dispatched
writer. An overwrite with a lost acknowledgement can already be present in
the actual source bytes; an unacknowledged growth remains hidden by the
filesystem's previous visible length. Capture observes those actual visible
bytes without claiming that the earlier write rolled back.

The capture also fences the complete block endpoint, source handle, file
index, exact length and full 64-bit file revision at every append and final
publication. A nonempty acknowledged file write or a length-changing truncation increments
that revision. Revision exhaustion rejects either mutation before touching
block bytes or publishing a new length. Already published immutable inputs
retain their captured bytes through source truncation and subsequent regrowth. A dependency, handle, length or revision change makes the capture
unusable. A failed or interrupted capture zeros its prefix and retains failed
transaction metadata for authoritative recovery and explicit reap. Publication
requires exactly the declared length; a successful prefix never publishes.

Block endpoint changes first invalidate filesystem metadata and then every
capturing/live input, clearing bytes and readers and retaining failure `STALE`.
The live service preserves its serial across this retirement. A filesystem
cold boot starts an empty table under its new full endpoint. Owner generation
retirement clears that owner's records in a finite two-entry pass, preserving
the live filesystem serial. Neither event silently substitutes a new capture.

## References, recovery and operation scope

An immutable reference is the pair `{issuer: u64, token: u64}`. The issuer is
the complete current filesystem endpoint, including all generation bits. Its
endpoint tag is two (zero-based filesystem runtime slot one); malformed, zero or
out-of-range endpoint generations cannot issue references. The token is
`serial << 8 | type`, with type `0xa1` or `0xa2` selecting its record. Serials
one through `0x00ffffffffffffff` are nonwrapping. Exhaustion sets the next
serial to zero permanently. Complete issuer, token and exact owner or reader
endpoint are checked against the active record; file handles, contract tokens,
IPC capabilities, endpoint numbers and predecessor references cannot be used
interchangeably.

Invalid prevalidation, full table and serial exhaustion consume no serial or
record. A capture that has reserved a record consumes one serial even if its
block transfer later fails. Creation transaction identity is scoped to the
exact owner endpoint. Exact duplicate create returns its original record
without another block capture, even if the source later changes or closes.
Changing the handle under that transaction returns `INVALID`. A fresh status
transaction names the creation transaction as its subject. Losing a creation
reply therefore permits owner-scoped recovery without another allocation.

After its original record is reaped, replaying an old creation transaction
returns `STALE` instead of allocating another view of possibly changed bytes.
The eight-entry high-water table is indexed by runtime slot and contains the
full owner endpoint plus last reserved creation transaction. It rejects a
retired older endpoint generation and consumed transaction numbers. Active
exact duplicates still recover their original record regardless of later
transaction numbers. Only a validated fresh record reservation updates the
high-water mark; prevalidation, capacity and exhaustion failures consume
nothing. Reap preserves it; owner retirement seals its generation with the
maximum transaction sentinel, so even a fresh transaction cannot revive that
retired actor's records. A higher owner generation
starts a separate transaction namespace after an explicitly authorized new
capture. A transaction value of `u64::MAX` exhausts fresh creation in that
owner generation without wrapping or aliasing a predecessor.

Only the exact owner may bind, designate a checker, revoke, close or reap.
The owner may read its own view when it also holds read operation authority.
Other readers need an explicit live exact endpoint binding. The two explicit
slots accommodate the actual worker and independent checker. A duplicate
same-endpoint bind is idempotent. Revoking the exact reader is idempotent and
cannot affect a successor reference or another reader. A replacement worker
needs explicit old-binding revoke and new-generation bind to the same input.

The production dispatcher validates the actual currently authorized
filesystem-to-peer snapshot reply route before a new bind or checker
designation. The sealed admission recipe pairs that reply leg with the
approved request leg. A guessed future endpoint, unpublished connection or
retired predecessor therefore cannot be prebound and later inherit an input
merely by occupying its predicted slot/generation. This readiness check is a
kernel-call seam in host dispatcher tests; the pure table still models only
object policy, separately from the compiled kernel admission/lifecycle tests.

The owner separately designates the checker with `bind_check`. That object
permission permits a narrowly admitted `snapshot_release`; an ordinary
worker read binding never does. Successful result settlement includes the
exact current worker endpoint in release. The filesystem atomically requires
both the designated checker and that worker's current explicit binding, then
zeros bytes, clears readers and commits `settled`. Owner revocation before
this service action rejects successful settlement. Owner close before release
commits `closed`, and a later checker release cannot convert it to success.
Cancellation/failure cleanup uses release reader zero and cannot be reused as
successful result settlement for a different reader. Settled metadata retains
the exact released reader solely for duplicate release matching.

An exact settled release retry is harmless after response loss. Cleanup zero
may also confirm already returned byte backing after a partial worker cleanup;
it preserves the original settled reader. A changed nonzero reader in the
retry is `INVALID`. Owner close is idempotent on the same
reference and preserves an already committed settled decision. Reap accepts
closed, failed or settled records. Old close/reap retries return `STALE` after
reuse and cannot clear the new serial. Reap is not proof that a timed-out
earlier mutation rolled back; owner status resolves retained unknown outcomes.

## Explicit compatible wire extension

Existing ABI-four storage layouts and legacy templates remain unchanged.
Scenario 25 selects the additional approved recipe/templates explicitly. The
operation rights are `snapshot_control=17`, `snapshot_read=18`,
`snapshot_reply=19`, and `snapshot_release=20`. The worker has read 18 to the
exact filesystem and the filesystem has reply 19 to the exact worker. It has
no open, write, raw block, control, release or general delegation right. The
broker has read 18 and release 20, with its separate reply route. Kernel
operation rights constrain actual routes; filesystem policy constrains the
exact immutable object and permitted reader/checker action.

Before its first snapshot reply through a route epoch, the production
filesystem queries that actual reply capability and requires its own exact
holder, the exact target, parent zero, and approved rights. The owner root's
reply route has file-result 14 plus snapshot-reply 19; admitted hosted readers
have exactly reply 19. A wrong route or failed query prevents the reply.
The eight-entry capability-handle cache bounds duplicate trace queries; it
confers no authority. Every check first finds a currently authorized exact
endpoint route. A new generation in a reused slot or a replacement route epoch
at the same endpoint must be queried again. Every send still checks a current
operation capability. Ordinary ABI query fields
are holder, target, rights and parent; actual issuer/epoch/derivation are
proved by the kernel's capability-query and admission trace, rather than by
inventing an issuer member in the unchanged query structure.

Every packet has exact 32-byte length and explicit little-endian integers.
The authenticated `Message.sender` is supplied by the kernel, never the
payload. Control requests contain transaction at bytes 0–7, subject at 8–15,
peer endpoint at 16–23, action at byte 24 and zero padding at 25–31. Actions
are create 1, status 2, bind 3, revoke 4, close 5, reap 6, bind_check 7 and
inventory 8.
Create subject is the source handle, status subject is the original creation
transaction and other subjects are snapshot tokens. Bind/check/revoke require
the exact peer endpoint; other actions require peer zero.

Inventory is read-only and requires subject one and peer zero. Its
authenticated reply uses the token field as a counter summary, rather than
an object reference: retained record count in bits 0–7, occupied byte backing
in bits 8–23, explicit reader binding count in bits 24–31 and zero upper bits.
Length carries live record count, block carries the current dependency and
state is empty. These counters cover the complete two-entry table of the
one configured owner. Inventory allocates no record and consumes no snapshot
serial. Final inventory zero proves actual record, backing and reader
conservation after reap. Worker/checker IPC admission does not grant this
owner control operation. The distinct inventory action and low count bytes
cannot be interpreted as a typed snapshot token.

For control, the reference issuer is the exact kernel-authorized destination
endpoint and its delivery generation. The typed client `objectControl`
retains the original reference's issuer as that destination. It does not
substitute a newly looked-up filesystem endpoint while reusing an old token.
Old-generation queued controls, original-route retries and private service
inboxes retire on filesystem cold boot. Deliberately changing a reference's
issuer selects a different namespace; token bytes alone are not a reference.

Control replies contain transaction at 0–7, token at 8–15, captured block
endpoint at 16–23, length at 24, signed status at 25, action at 26, state at
27, zero padding at 28–30 and reply kind 1 at 31. The reference issuer is the
complete authenticated filesystem sender. States are empty 0, capturing 1,
live 2, closed 3, failed 4 and settled 5. A retained failed record is not a
usable input.

Read requests contain transaction at 0–7, token at 8–15, full issuer at
16–23, unsigned 16-bit offset at 24–25, count at 26 and zero padding at
27–31. Counts are zero through eight. Release requests use the same first
24 bytes and put the exact current worker endpoint, or cleanup zero, in
24–31. Read/release replies contain transaction at 0–7, token at 8–15,
offset at 16–17, count at 18, signed status at 19, at most eight zero-padded
data bytes at 20–27, zero padding at 28–30 and kind 2 at 31. Release replies
have offset/count/data zero. Negative statuses never carry data.

Reply matching checks complete filesystem endpoint, transaction, object token,
reply kind, offset, count bound and padding. The ordered production reader
additionally requires every declared chunk count, no gap/overlap/duplicate,
and one zero-byte EOF at the exact captured length before completing. Binary
NUL, non-ASCII and repeated bytes retain their ordinary byte values. Offsets
above 128, overflow and overlarge chunk counts cannot expose retained bytes.

## Revocation and bounded failure observation

Each send has at most four attempts before enqueue, each transaction at most
eight ten-tick receive attempts. Enqueued mutating requests are not silently
retransmitted. Native snapshot clients keep the same transaction pending after
a timeout wakeup while attempts remain, and check the exact original filesystem
endpoint before sending and after every wake. A replacement or absent endpoint,
other receive error, full inbox, or exhausted attempt budget fails the RPC;
the original reference issuer is never rebound. Unrelated messages and timeout
wakeups consume the same eight-step budget. The block-transfer state still ends
on its first timeout. Capture uses at most sixteen such block transactions. Inbox
pressure ends the pending transfer and fails capture rather than overwriting
traffic or polling forever. Analysis clients share their caller's existing
eight-message inbox for unrelated traffic; they do not cycle those messages
back through a pending reply wait. A full inbox is an explicit failure.

Kernel revocation removes or revalidates queued messages under the existing
capability policy. Service-owned revoke removes the reader binding when the
filesystem dispatches that owner operation. A read dequeued before revoke can
finish; bytes already delivered into private worker memory cannot be erased
retroactively. The successful release fence requires the current worker
binding at the filesystem's serialization point. Once release commits,
later control work cannot change that settled input decision. Kernel worker
route retirement and the contract's generation/fault/restart STOP fence remain
separate necessary completion steps.

`cells/snapshot_tests.zig` directly exercises production dispatcher capture,
ordinary deferred mutation, immutable-source behavior, binary boundaries,
creation loss recovery, capacity and counter exhaustion, malformed replies,
dependency and revision interruption, owner retirement, revocation and exact
checker settlement. Python's independent generated model drives production
`snapshot.zig`/`storage.zig` through `snapshot_model_driver.zig`; that host
evidence is distinct from scenario-25 emulator evidence.
