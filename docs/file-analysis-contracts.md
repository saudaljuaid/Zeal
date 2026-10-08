# Immutable-input byte-analysis contracts

Scenario 25 selects `cells/analysis.toml`, approved broker template 5 and worker
6, and sealed storage recipe 2. Scenario 24, its scalar profile 1, and every old
manifest/template keep their original behavior. The production broker core and
dispatcher support both profiles; the selected isolated runtime admits its own
approved profile only. ABI 4 and manifest 2 retain their structure layouts and
old operation numbers. No new syscall or privileged file/contract object exists.

The filesystem owns two immutable input records; the broker owns two work
records. Kernel operation capabilities authorize actual endpoint interaction.
Filesystem policy restricts a reader to an owner's exact immutable input and
current binding. Broker policy controls acceptance, attempts, result checking
and terminal publication. Neither a filename, role, image, handle, snapshot
reference nor contract token substitutes for these distinct checks.

## Captured input and checking rule

The owner opens an existing file through its own operation-authorized route and
captures 0–128 actual bytes through the filesystem/block path. Capture is a
single filesystem dispatch: concurrent application traffic is preserved in its
eight-message FIFO rather than dispatched between capture chunks. Publication
checks the original handle/owner, file revision and exact dependency generation.
A lost capture reply is recovered by the same owner and creation transaction,
without allocating another record. See [input objects](storage-inputs.md) for
coherent capture, typed full-generation references, failures and exhaustion.

Profile 2 computes a tuple over binary bytes without a terminator, Unicode
interpretation or text normalization:

* Length is the captured number of bytes, 0–128.
* Newline count is the number of bytes equal to `0x0a`.
* Digest is FNV-1a 64: begin with `0xcbf29ce484222325`; for each byte in increasing
  offset, xor its unsigned value, then multiply by `0x100000001b3` modulo 2^64.
  The empty input retains the initial digest. All wire integers are little endian.

FNV-1a is a noncryptographic checksum. It is not collision-resistant
authentication, attestation, a signature or proof of arbitrary correctness.
The checking profile has no file writes, arbitrary side effects or payments.
The broker recomputes from the immutable service's actual bytes, rather than
trusting a requester-supplied expected checksum. The owner independently reads
that same captured view before acceptance and retains its exact tuple for
receipt verification. The external Python oracle reconstructs source and
snapshot bytes from authenticated real block/filesystem transfers independently.

## Offer, acceptance and finite wire extension

Input capture, owner bindings, route installation, broker preparation reads and
worker creation are preparation costs. They are separate from accepted worker
computation. Pure owner/shape/offer high-water/table/serial/domain prevalidation rejects
unallocatable offers before spending any snapshot RPC identity. A broker
preparation read determines the actual snapshot length
and checks exact EOF. Before offer publication, a two-page worker is allocated,
its private cold state and real ring-3 entry observed, and its bootstrap reply
matched. The offer binds snapshot token, full filesystem issuer, captured length,
profile 2, requester and actual logical worker/execution. Capture generation is
the full issuer endpoint; block generation is retained in the input record and
owner's capture response. The filesystem refuses publication across either
capture dependency or file-revision changes.

The owner explicitly designates the broker as checker and binds the offered
worker endpoint to this input. Binding grants no kernel rights. The sealed recipe
has already installed exact snapshot request/reply capabilities; the worker has
only read operation 18, while the broker separately has read 18/release 20.
Input liveness/length is rechecked by the broker immediately before first
dispatch or retry; exact duplicate acceptance does not repeat that read. This
check cannot promise future authority across IPC boundaries. The owner
validates the exact worker-bind reply before sending ACCEPT, and actual worker
reads plus successful release enforce the current service binding.
The worker receives no file-open, file-write, arbitrary file-handle, raw-block,
general delegation or release authority. Both route directions are checked and
queried. See [checked admission](storage-admission.md).

The approved worker performs no usable input read or analysis before a complete
accepted descriptor. This is a broker/approved-worker protocol guarantee;
operation capabilities alone do not encode acceptance or snapshot identity.
Rejected unbound-read probes transfer no bytes. STATUS/RECEIPT do not execute
work. Wrong profile/input/token/issuer and altered duplicate acceptance fail;
exact duplicate acceptance remains narrowly idempotent.

All contract envelopes retain version 1, operation 15/16 and exactly 32 bytes
with four reserved zero bytes. Profile 2 explicitly extends command-specific
semantics and never silently selects itself in old templates:

| Packet | Meaning |
| --- | --- |
| OFFER 1 | detail=2, token=full filesystem issuer, data=snapshot token |
| ACCEPT 2 | detail=2, token=contract, data=the exact offered snapshot token |
| INPUT 10 | broker-to-worker, full FS issuer in data |
| INPUT_LENGTH 12 | same RPC/contract/attempt; length bits 0–15, test delay 0–32 ticks in bits 16–23, first-attempt diagnostic fault bit 24; higher bits zero |
| WORK 7 | third ordered descriptor packet, snapshot token in data |
| WORK result 7 | worker-to-broker digest, exact RPC/contract/attempt |
| ANALYSIS_TUPLE 11 | second ordered result, length bits 0–15 and newline count bits 16–31; higher bits zero |
| REBIND_INPUT 13 | broker-to-owner notice, exact replacement endpoint in data |
| AUTHORIZE_INPUT 14 | owner-to-broker exact notice transaction/contract/endpoint acknowledgement after explicit object rebind |

INPUT, INPUT_LENGTH and WORK must agree on authenticated full parent endpoint,
RPC, contract and attempt and arrive in order. Worker RPC high-water does not
wrap. One snapshot-client sequence spans boot denial probes and all reads of
that execution; reset or replay cannot alias a privately held predecessor reply.
Root workload pause/acknowledgement also uses INPUT with an explicit root-to-root
route, zero token and phase 1/2; it grants no hosted-worker authority.

Scalar status remains exactly eight packets. Profile 2 appends part 8 containing
full input issuer and part 9 containing length/newline counters. The result
field remains the full 64-bit digest. Ten ordered matching parts must arrive
before an analysis snapshot is usable. The legacy eight-part collector admits
only scalar profile 1; the analysis collector explicitly supplies both extension
fields for profile 2. Newline/result fields are zero outside completed receipts. Terminal metadata retains input identity,
profile, logical worker, exact execution, RPC, attempt, tuple and outcome.

## Ordered reads, retry and cancellation

Workers use the shared production `snapshot_client.Reader`: exact ordered
chunks of at most eight bytes, complete expected counts, and one exact EOF.
Matching requires full FS sender generation, reply kind, client transaction,
input token, offset and count. The descriptor and current worker endpoint bind
contract/attempt separately; each worker backs one contract and one attempt at
a time. Read packets need no duplicate contract token to establish that binding.
Missing/gapped/overlapping/duplicate/stale/malformed packets cannot complete a
full reader or tuple collector. A partial-prefix digest is not a declared result.

The broker uses the same two private result slots as the scalar runtime, selected
through a union. Each byte-profile slot holds either a digest packet or a complete
candidate tuple during eight bounded delivery windows. It cannot overwrite a
sibling or current candidate. Retirement clears only the affected old attempt's
slot before a replacement result can occupy it. Every candidate is rechecked
against current state, endpoint, RPC and attempt at consumption.

A worker fault retires its IPC routes and parent routes. The broker reconciles
real lifecycle status, retains the same immutable input and permits at most one
retry. Checked kernel rebind provisions fresh current routes. The owner then
explicitly revokes the old reader endpoint and binds the replacement to the same
input, acknowledging the exact replacement notice. No matching slot or image
implicitly grants input authority, and no retry recaptures a changed file.
A second fault, exhausted counter, failed rebind, absent dependency or expired
attempt fails and settles actual backing without manufacturing success.

An exact owner CANCEL already dequeued into the broker's private inbox takes
precedence during verification, input-release waits and replacement authorization.
It prevents later success or retry dispatch. A prior committed terminal decision
remains immutable. Cleanup is bounded to two attempts; a partial failure exposes
actual retained charges and no verified result. Broker retirement performs real
subtree cleanup. Service input records still require the owner's explicit
close/reap unless owner-generation retirement or cold service boot clears them.

## Settlement and separate release points

A successful candidate follows this order:

1. Match the full current-attempt tuple and independently collect the actual
   immutable bytes through the checker binding.
2. Observe any dequeued cancellation and obtain the actual worker generation,
   fault count and restart count admission fence.
3. Send separately authorized release 20 for this exact input and exact worker
   binding. At the filesystem serialization point it checks both current checker
   and worker, clears all 128 byte slots and both reader bindings, and retains
   owner-scoped metadata as SETTLED. Owner revocation before this point wins.
4. Perform checked worker STOP, verify zero pages/reservation and the unchanged
   admitted generation/fault/restart tuple, then REAP and prove stale control.
5. Publish a verified terminal contract with zero worker charges and full tuple.
   A dequeued cancellation during release publishes cancellation after cleanup;
   no candidate result becomes verified. A fault/restart prevents successful
   publication, including after input release has already committed.
6. The owner queries retained input/contract metadata, explicitly closes/reaps
   the input record, then reaps the contract. Record reuse gets a fresh serial.

Input byte backing and service-reader bindings return at successful release.
Worker IPC routes/pages return at STOP; its retained kernel slot/control returns
at REAP. The broker's own routes/pages return when the owner stops/reaps it.
Owner file handles return at file-close; files/block backing and original root
workload authority remain. Contract and owner input metadata are bounded retained
records until explicit reap, not universal zero resource use.

Release response loss is unknown until resolved. Exact settled release is
idempotent for the same checker/input/worker. Cleanup peer zero cannot convert a
prior cancellation into a successful worker settlement. A closed/revoked invalid
input cannot publish success; independent state and byte backing are reported
honestly even when subsequent cleanup fails.

Revocation removes/revalidates kernel-queued requests under existing policy.
Filesystem revoke takes effect at its dispatcher boundary. Work already dequeued
by the service or bytes already delivered into private worker memory cannot be
retroactively erased. Successful release and checked STOP are separate ordering
points, not a distributed atomic revocation promise.

## Capacities and evidence boundaries

Existing limits remain: eight runtime slots, two descendant levels, 128 private
pages, 32 capabilities, eight kernel messages, 32-byte payloads, four existing
RPC records, eight deferred messages, two broker records/two result slots and
one retry. Files remain four by 128 bytes with eight handles and 512-byte block
backing. The filesystem adds two 128-byte immutable records and two reader
bindings per record, with no heap. Temporary ordered reader and output buffers
are each 128 bytes; checker collection uses one 128-byte scratch buffer. Owner
state retains two Input/Held descriptors and their tuples, not a duplicate file
fixture used for capture. The compiled layout probe reports a 216-byte input record, 584-byte snapshot
table, 1,400-byte filesystem Server, 152-byte ordered Reader, 128-byte two-slot
result collector and 280-byte broker table. These service-private types are not
a public ABI. The permanent owner transaction watermarks retain eight full
endpoint/transaction pairs (128 bytes), and reply proof caching retains eight
full capability references (64 bytes), even after input inventory is empty.
Kernel admission's extra runtime route metadata is 192 bytes. No universal
zero-memory claim follows from returning temporary objects and rights.

Snapshot RPC sends are at most four attempts before enqueue and eight ten-tick
receive steps. Capture has at most sixteen block transfers. Analysis collection
has at most sixteen data chunks and one EOF. Descriptor/result packet counts
are fixed. Worker bootstrap waits at most 64 one-tick steps for explicit channels;
replacement authorization has sixteen ten-tick receives. Requester snapshots
have 32 ten-tick receives and terminal queries at most 80 samples separated by
three-tick sleeps. The existing broker attempt limit remains 160 receive windows.
These bounds are finite protocol costs, not wall-clock or CPU guarantees.

Scenario 25 has 4,096 hosting trace events, 384 hosting reports and 8,192 storage
trace events/reports. Those observation quotas include full raw wire fields and
checked copy delivery. Old scenario quotas/repetitions remain unchanged; exhaustion
fails. Its main QEMU path uses binary `/alpha`, `/beta` and `/hello`, changes the
source only while the independent root workload acknowledges a verified pause,
and checks ordinary changed bytes versus the immutable accepted view. It includes
loss recovery, offered/active cancellation, privately staged late rejection,
one fault/rebind retry, a separate live obligation, explicit input/contract reap,
final owner inventory and actual capability/page conservation.

Host production tests additionally exercise binary boundaries, capture pressure
and partial loss, unknown prior writes, owner/service/dependency retirement,
revocation/result races, second failure, counter exhaustion and cleanup failures.
Independent Python models compare different map/history representations after
every generated production step. Host evidence is not emulator proof. The full
local/CI gate remains `make test`; neither a redundant marker nor a correct
digest can excuse contradictory authoritative raw fields.
