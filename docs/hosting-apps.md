# Bounded hosting applications

The hosting demonstration uses the existing probe root, identity 400, as a ring-3
controller in scenarios 21–23. The original probe behavior remains selected in
scenarios 0–20. The controller creates the approved supervisor template, and that
supervisor creates the approved worker template at depth two. Scenarios 21–22
reserve two descendant slots and four pages for two independently owned
grandchildren; scenario 23 reserves one descendant slot and two pages so that a
separate pressure worker can fill the final runtime slot. The controller also
creates a worker directly, outside the supervisor's subtree. Supervisor and worker
images are sealed catalog entries; they have no active manifest root records.

These applications use Zeal's checked management calls and bounded IPC. The C
supervisor remains responsible for allocation, address spaces and scheduling. A
Zig supervisor has lifecycle authority over its direct children and a reserved
creation domain; it does not run a privileged kernel or an independent scheduler.

## Protocol

IPC operations 15 and 16 are `HOST_REQUEST` and `HOST_REPLY`. Every hosting packet
has exactly 32 payload bytes, with little-endian fields:

| Offset | Size | Meaning |
| --- | --- | --- |
| 0 | 8 | Nonzero request identity |
| 8 | 4 | Command |
| 12 | 4 | Reserved, must be zero |
| 16 | 8 | Argument |
| 24 | 8 | Request auxiliary value or reply result |

The kernel-provided sender endpoint includes its execution generation. Requests
are accepted only from the exact configured parent endpoint. A reply must match
the exact child endpoint, operation, request identity, command and argument. Its
result is recomputed by the receiver. Request counters retire identities even
when work fails; after the last `u64` identity, further requests fail rather than
wrapping. Worker and supervisor request admission reject duplicate and earlier
identities before processing commands. An invalid dispatcher request consumes a
request identity deliberately but occupies no pending record.

| Command | Name | Behavior |
| --- | --- | --- |
| 1 | challenge | Compute the scalar challenge result |
| 2 | nested | Supervisor verifies a grandchild challenge and combines results |
| 3 | sleep | Worker acknowledges, installs a finite sleep, then checks its sentinel |
| 4 | nested_sleep | Supervisor arms a sleeping grandchild and queues authorized work |
| 5 | fault | Deliberate application `ud2` for the recovery scenario |
| 6 | grandchild_fault | Supervisor faults its worker and reports observed backoff |
| 7 | copied_authority | Worker demonstrates rejection of a copied parent's IPC token |
| 8 | timeout | Worker demonstrates a finite blocking receive timeout |
| 9 | copied_control | Worker demonstrates rejection of another owner's lifecycle token |
| 10 | copied_creation | Worker demonstrates rejection of another owner's creation domain |
| 11 | cpu_probe | Worker executes one of five bounded privilege-fault probes |

The challenge is FNV-1a over the ASCII bytes `Zeal bounded ring-3 worker`, followed
by the eight little-endian bytes of the argument. The initial value is
`0xcbf29ce484222325`, and each byte applies `(value ^ byte) * 0x100000001b3`
modulo 2^64. A nested request with argument `x` requires the grandchild to process
`x ^ 0x8ac91367ef04d2b5`; the supervisor returns the XOR of the parent and worker
challenge results. When it owns two grandchildren, it sends both salted
challenges before awaiting either response, verifies both results independently,
and requires agreement before replying.
The root verifies both computations, and the external oracle independently
recomputes results from the authenticated IPC trace.

## Dispatcher and private state

The production dispatcher has four pending records and an eight-message deferred
parent inbox. Replies for different child endpoints or two requests to one child
are routed into their matching records. Waiting for one response does not remove
another completed response. Authenticated parent requests received during a
grandchild call enter a FIFO inbox. Invalid and unsolicited packets are rejected.
Inbox pressure returns an explicit failure.

Each enqueue has at most four attempts. An accepted request is never resent.
Backpressure uses one-tick sleeps. Response waiting uses finite ten-tick receives
and at most sixteen receive steps, including unrelated traffic and timeout
windows. Failure releases the application's pending record; retired endpoints
cannot complete their predecessor's work. Management create and rebind request
identities share a separate monotonic sequence within each creator execution.

Both dynamic applications cold-check memory before acquiring execution-scoped
channels. A restarted worker waits in one-tick sleeps for its live owner to
explicitly rebind the new endpoint, just as the supervisor waits for its new
channel and delegated creation authority. The bootstrap gate allows at most 160
attempts and requires stable endpoint, parent endpoint and logical instance.
Before processing work, the application queries its channel and checks the exact
current holder, parent target and reply-only rights.

The supervisor handles zero-credit and other checked bounded allowances as well
as the demonstration's one- and two-worker reservations. It creates at most four
workers, limited separately by available slots and complete two-page private
allocations, and reports the exact remaining credit. A supervisor with no worker
credit remains available for direct challenges; unsupported nested requests reach
the parent's existing finite timeout.

Each dynamic execution checks zero private heap words and a zero stack sentinel
before writing them. Its heap sentinel is
`0x9e60328ab74fc1d5 ^ endpoint`, followed by its complement. This mapping is
injective over execution endpoints.
The stack sentinel is `0x736a21c45e98bd02 ^ endpoint`. A worker checks these values
after its real timed sleep and before processing subsequent work. Distinct
workers using the same image therefore have independent state and different
sentinels. Cold restart keeps the logical instance but changes the endpoint and
starts with cleared writable backing.

Both dynamic templates attempt file and raw block requests using their narrow
parent reply channels. These sends and searches for storage rights must return
`DENIED`. Their bootstrap recipes provision request/reply channels only.

## Demonstration sequencing

Scenario 21 creates the hierarchy and sibling, verifies direct and nested RPC,
and demonstrates a real finite receive timeout. The hierarchy remains active
while the independent root storage application makes progress. The controller
then stops and reaps its owned instances and verifies a completely returned
resource ledger.

Scenario 22 installs a twenty-tick sibling sleep and a thirty-tick grandchild sleep.
The parent waits one finite tick after each sleep acknowledgement so that the
worker receives a user turn to install its actual wait before traffic is queued.
The supervisor queues authorized grandchild work during the grandchild sleep;
the root queues two distinct challenges during the sibling sleep. The supervisor
then faults. The root observes backoff and the new execution generation, rejects
the old endpoint and channel, and explicitly rebinds current-generation authority
before the restarted supervisor can create a replacement grandchild. The first
verified nested RPC after that rebind ends the measured recovery interval.
Storage chunk verification continues during that interval.

The sibling retains its own sentinel, endpoint, channel, original sleep deadline
and both FIFO messages. Both replies are recomputed separately. A subsequent
phase faults the new grandchild, waits until the supervisor observes its delayed
backoff, and destroys the supervisor's subtree. A ten-tick observation period
exceeds the worker's pending restart delay. The surviving sibling then completes
fresh verified work before final teardown.

Scenario 23 exercises missing and wrong-type authority, unknown templates,
excessive and overflowing requests, invalid input/output ranges and lengths,
copied IPC/control/creation tokens, global slot pressure, and creation-domain
revocation. It stops and reaps a worker, reuses its runtime slot, checks fresh
logical/control/endpoint/channel identities and cold memory, rejects predecessor
tokens, and resumes verified work. Revoking creation authority leaves the
owner's separate query/stop/reap controls usable.

The replacement leaf also faults and automatically restarts under its live root
owner. Its logical instance and control remain stable, while its execution
generation and channel change. The root rejects predecessor endpoints and
capabilities, explicitly rebinds the new execution and verifies fresh RPC.

Five additional workers are then created and reaped sequentially in the free
runtime slot, using the same approved worker image and the same finite budgets.
Each first processes a verified challenge and then attempts one CPU operation:
an immutable-image write, a supervisor-memory read, port I/O, a stack-guard
write, or execution from NX private heap memory. Actual x86 fault records carry
the vector, error bits and address. The owner queries backoff and stops/reaps the
instance before its delayed restart. The live supervisor and recovered sibling
complete fresh verified work after all five faults.

## Independent storage workload

Identity 300 selects a separate storage-only branch in scenarios 21–23. It opens
`/hello`, `/alpha` and `/beta`, creates the two writable files through the existing
filesystem and block services, and writes different multi-chunk payloads:

* `/alpha`: `Zeal alpha private file 01.`
* `/beta`: `Distinct beta bytes survive.`

The application retains all three file handles and continuously reads and
byte-verifies every chunk and EOF. One-tick sleeps between subsequent read chunks
allow independent hosting progress. Block, filesystem and root-client endpoint
generations remain unchanged in these preservation scenarios. This workload uses
the existing bounded volatile storage; it introduces no new storage clients or
persistence guarantee.

## Verification artifacts

`cells/hosting_tests.zig` imports production wire, dispatcher, worker-admission
and storage application modules for host testing. Its focused tests cover sender
generation checks, exact packet validation, interleaved replies, two outstanding
sibling requests, pending/inbox pressure, malformed and late responses, finite
retry/timeout limits, replay rejection, every one-bit reply mutation, bounded
exhaustive response permutations with scoped endpoint retirement, and counter
exhaustion. The real emitted
images also pass `tools/check_cell.py` under the restricted scalar CPU contract.
Emulator evidence and oracle results are produced by the supported complete test
runner; application completion reports alone are insufficient evidence.
