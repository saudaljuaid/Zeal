# Bounded hierarchy and authority policy

Zeal is an operating system under development. This policy provides bounded
composition of isolated ring-3 cells under the existing privileged supervisor
and global scheduler. Assembly still implements privilege transitions; C owns
address spaces, physical allocation, checked copying, queues, waits and atomic
orchestration; Rust without `std` decides lifecycle, hierarchy, resources and
authority; Zig implements the isolated applications. A supervisor cell has no
privileged kernel, page-table manager or independent scheduler.

## Fixed limits and representation

`include/zeal/hosting_policy.h` is the C/Rust policy contract. Its layouts are
checked by compiled Rust and C tests. The management syscall wire contract is
ABI v4 in `include/zeal/abi.h` and `cells/abi.zig`; sealed templates and root
allowances are serialized in manifest v2, described in `docs/manifest.md`.

There are eight runtime slots. Slots 0–3 remain permanently reserved for the
original manifest roots. Slots 4–7 are runtime children. The tree has at most
two child levels, root → supervisor → worker. The four dynamic slots also bound
all direct and indirect children globally. At most eight templates, eight
logical instance/control metadata records and eight creation domains exist.
A retained terminal instance still occupies its runtime slot and metadata.
Consequently only four logical dynamic instances can coexist in this design,
even though the metadata arrays have eight entries. Slot pressure dominates
independent instance/control pressure; the kernel never separates a retained
control from the slot required to describe it.
The compiled sealed-image catalogue declares each image's application role
explicitly, and the runtime registry records that role separately from image
identity, diagnostic identity, logical instance and execution slot. Boot role
does not use an image-number arithmetic convention. Multiple instances may
share one immutable worker image while retaining different private backing
and authority; host fixtures also verify two sealed image identities with the
same worker role. Image/role/identity alone grants no creation or IPC authority.

The hosting manifest authorizes only the original probe root, identity 400,
with four descendant slot credits, 48 descendant page credits, both approved
templates and absolute depth two. Roots 100/200 remain storage services;
root 300 remains the storage application. The supervisor template uses an
8 KiB stack plus 8 KiB heap (four pages) and permits the worker template one
level below itself. The worker uses a 4 KiB stack plus 4 KiB heap (two pages).
Private stack and heap sizes are rounded separately before charging. Every
private page is 4096 bytes, a cell has at most 20 such pages, and the global
private pool has 128 pages, preserving the original roots' 80-page allowance.
Descendant reservations remain bounded by 48 pages even in a host fixture
with fewer active root allocations.

Every logical supervisor owns at most one domain; a leaf owns none. A
supervisor with zero descendant credits still receives a typed, zero-credit
domain, so depth and credit checks can reject a request made with otherwise
valid authority. The eight domain entries cover the general policy bound of
four root domains plus four dynamic supervisors; the current validated
hosting manifest has one root domain and therefore at most five domains.
The slot limit prevents an additional supervisor before these arrays could
leak beyond their bound.

The compiled static sizes are: policy table 1880 bytes, runtime record
152 bytes, C runtime registry and policy together 3168 bytes, broker 6480
bytes, wait table 256 bytes, and each saved CPU frame 176 bytes. The aligned
private-page pool occupies 528384 bytes, including ownership metadata and
padding; 524288 of these bytes are the 128 writable pages themselves. Image
backing, page tables, supervisor stacks, frames and other tables are finite
preallocated supervisor overhead. They are not represented as private page
credits. The build's footprint report and linker check constrain the complete
supervisor footprint separately.

## Distinct lifetimes and token types

A successful creation establishes one logical instance until termination and
final reap. Its execution endpoint names one incarnation. Automatic restart
preserves the logical instance and its direct owner's lifecycle control but
changes the execution generation. Destruction and slot reuse create a new
logical instance and control, even if the sealed image is identical.

The positive 64-bit handles use a monotonic epoch in bits 8–62 and disjoint
low-byte type/record ranges:

| Object | Low byte | Authority |
| --- | --- | --- |
| Execution endpoint | 1–8 | Names an execution; grants no management rights |
| IPC capability | 1–32 | Existing holder/target/issuer/rights-checked broker grant |
| Logical instance | 0x41–0x48 | Diagnostic reference; grants no management rights |
| Lifecycle control | 0x51–0x58 | Exact direct owner may query, stop and reap |
| Creation domain | 0x61–0x68 | Exact execution holder may create within its allowance |
| Unpublished transaction | 0x71–0x78 | Privileged orchestration token only |

The existing endpoint and capability resolvers reject every hosting token's
low-byte range. The hosting resolvers require an exact object type, stored
epoch and holder. Converting the low-byte tag cannot manufacture a different
object: every newly allocated instance, control, transaction and domain has
a different epoch from the common hosting epoch counter. Lifecycle controls
have explicit query/stop/reap right bits; query-only controls fail stop/reap.
There is no lifecycle-control delegation or ambient ancestor destroy right.

Ownership records bind the exact parent's endpoint, parent slot and, for a
dynamic parent, logical instance. Root parents use logical-instance zero as
the explicit non-dynamic sentinel, together with their exact endpoint and
permanently reserved slot. Diagnostic identity, role and image do not confer
authority. A copied parent's IPC or creation token fails a child's holder
check. A parent generation change cannot inherit the retired execution's
controls or creation domain.

Slot execution-generation history is stored permanently in the policy table
for the lifetime of the boot. Reap clears a runtime record but preserves that
history. First publication into a fresh dynamic slot uses generation one;
every subsequent publication uses a strictly greater generation. The dynamic
path never calls the cold-root `z_policy_init` on a reused slot. Stop and reap
do not invent a new incarnation. A failed unpublished spawn does not advance
slot history; failed restart preparation may retire a generation before any
user turn, and the history is still never decreased.

Epochs and endpoint generations stop at `INT64_MAX >> 8`. A counter may
advance to the explicit exhausted sentinel but cannot wrap. Exhausted slots
cannot publish another execution. Diagnostic dynamic identities stop before
`UINT32_MAX`. Create and rebind use one strictly increasing, nonzero request
namespace per creator endpoint/domain; accepting `UINT64_MAX` makes that
namespace terminal. Retrying a consumed request returns stale. Rejected
requests before reservation consume no identity. An accepted preparation or
rebind may deliberately retire epochs/request identities after an ordinary
mechanism failure; resource credit must still be returned.
Creation-epoch exhaustion closes creation/rebind authority independently of
the original roots' execution lifecycle. A due root restart still receives
cold backing and a valid frame, with creation authority zero; it cannot
inherit its retired generation's token or publish a half-initialized READY
execution merely because a factory cannot mint another epoch.
Static manifest IPC-grant refresh has a separate 16-byte privileged retry
state. Under ordinary capability-table pressure it retries at most once per
four ticks, using checked deadlines. Rust classifies exhaustion against the
exact pending static-root batch; too few remaining epochs, or an
unrepresentable next retry deadline, closes that refresh without reusing an
old grant. Existing valid grants remain valid. Refresh derives only the
original manifest root entitlements and never recreates a same-generation
explicitly revoked grant or an ad hoc runtime recipe channel.

## Conserved delegated credit

For every domain, separately for slots and pages:

```
owned allocations + reserved subdomain allowances + available = committed limit
```

A child uses one owned slot in its parent's domain. Its own private pages are
charged there separately from any allowance delegated to it. The child's
subdomain receives the requested descendant limits; those entire limits are
reserved in the parent and unavailable to an unrelated sibling. A grandchild
consumes owned credit inside that reservation, rather than adding the same
allocation again at the root. Allowed template masks and absolute depth only
attenuate through the chain. A caller cannot create an unrelated new domain,
increase a limit, transfer credit between branches or enlarge private memory
through a request field.

The policy validates bounded additions and availability before mutating a
ledger. C checks the same rounded allocation against actual, unique physical
page ownership before publication. Logical page reservations and free
physical pages are different quantities: a domain can reserve credit without
allocating physical backing yet. Physical allocation failure remains an
ordinary transaction failure even when logical credit exists.

A child in recoverable backoff retains its own private allocation and its
entire subdomain reservation. Its descendants are destroyed and automatically
reaped. Their refunds return to the still-reserved child domain; they do not
also become free root credit. The direct external owner can inspect the same
logical child throughout recovery.

Stop, voluntary exit and terminal quarantine release private pages and the
remaining subdomain reservation after mandatory mechanism cleanup. They
retain the instance/control and charge one owned slot until the live direct
owner reaps it. Repeated stop succeeds without a second refund. Reap of a live
instance is denied; successful reap invalidates its control and frees the
owned slot; repeated reap is stale. Mandatory owner retirement automatically
reaps every descendant whose direct owner can no longer act. It leaves no
orphaned tombstone, control or domain. Only the affected subtree root under a
still-live external owner may remain terminal and queryable.

## Atomic creation and recovery

C's `kernel/hosting.c` calls the same production engine in the kernel and
sanitized host tests. The kernel validates exact request length, readable
input and writable output ranges before reserving anything. The Rust prepare
operation checks the live caller generation, typed domain, ancestor
revocation, approved template, depth, request high-water mark, free dynamic
slot, metadata/domain capacity and both resource ledgers. It creates an
unpublished reservation and returns future identities. These identities do
not resolve to a runnable execution.

C allocates unique physical backing, clears every writable page, initializes
the sealed address space and ring-3 frame, and installs exactly the approved
bidirectional RPC recipe. It then copies the result to the checked output.
The single publication point is `z_host_commit`, which rechecks the same
parent generation and reservation before making the execution READY. All of
these actions share the interrupt-masked single-CPU entry; no child user turn
lies between output copy and publication. Ordinary rollback removes the
frame, backing, pending wait, queued work, both recipe grants, reservation and
unpublished records. Epochs and consumed request identities remain retired.

On fault, the policy first makes the entire affected subtree nonrunnable.
C performs bounded bottom-up wait cancellation, grant invalidation and queue
compaction, then clears/releases descendant backing and frames. Compaction
preserves unrelated valid FIFO entries. A sibling outside the subtree retains
its memory, endpoint, authority and exact wait deadline. A stopped descendant
in delayed backoff cannot later restart or complete a cancelled wait.

A recoverable child's restart retains its logical allocation, cold-clears
private memory, constructs a new frame and advances its endpoint generation.
Its creation token and parent channel remain absent. The live direct owner
must explicitly rebind with its still-live original creation entitlement and
the stable child control. The policy checks the original recipe entitlement,
logical instance, parent generation, current child execution and revocation.
Only then can C issue fresh narrow IPC grants and, for a supervisor, a fresh
creation token. The restarted supervisor's new endpoint starts a new request
namespace; a same-generation rebind preserves the existing high-water mark.

Rebind failures retain consumed epochs and the parent's request high-water
mark. C restores only the surviving child's provisional token state. It never
restores a whole stale snapshot over owner, child or unrelated fault cleanup.
Restart callback errors and retirement release any partial initialization
that no longer belongs to a live record, without releasing promised backing
held by a surviving backoff instance.

Creation revocation propagates through delegated domains and prevents new
creation or further rebind. It does not destroy existing children, revoke
separate lifecycle controls, block mandatory cleanup or invalidate already
issued narrow IPC grants. Explicit stop/reap remains available to the live
direct owner. Restart never recreates revoked ad hoc authority merely because
a template image exists.

## Authoritative status and verification

Cell status is a bounded 104-byte record containing logical/control identity,
current endpoint when READY, current execution generation, exact parent,
template/depth, lifecycle phase/fault/restart counts, last reason and charged
resources. Domain status is a bounded 72-byte record containing exact holder,
instance, limit/owned/reserved/available ledgers, depth/mask/recipe and revocation.
Status queries remain authoritative across lost replies or a state transition;
notifications are not required for cleanup or recovery. Physical addresses and
supervisor pointers are not exposed through these status contracts.
The generation field is the last assigned execution generation. A failed
restart initialization deliberately retires its candidate generation, exposes
no usable endpoint, releases its backing/reservation and leaves terminal
status with initialization reason 5. Unrelated cells, FIFO work and wait
deadlines continue unchanged.

Rust tests compare the production policy with an independent logical tree
model that derives credit by traversing direct-child relationships rather
than copying mutable production ledgers. Six deterministic seeds run 18000
generated operations, and all six-action prefixes of length zero through six
check 55987 tree/lifecycle states. The model includes reservation, rejected
and aborted creation, faults, time advance, restart, stop, reap, revocation,
rebind and slot reuse. Failure reports retain the reproducible seed/prefix and
recent action sequence.

`tests/hosting.c` exercises the actual C engine with production memory,
broker and wait mechanisms under AddressSanitizer/UndefinedBehaviorSanitizer.
It covers checked copies, readonly/guard/overflow ranges, each creation and
restart failure boundary, partial allocation, owner/target/unrelated retirement
during output copy, exact ledger/physical ownership, retained control pressure,
atomic IPC pair pressure, exhaustion, fresh rebind, stale handles, sibling FIFO
and wait preservation, and 256 repeated create/fault/recover/destroy/reap cycles.
Its nested creation matrix also faults either the supervisor caller or its
root ancestor at all nine architecture/copy boundaries, with both failing
and succeeding callback outcomes: 36 checked retirement cases use the same
production engine and verify recovery/new creation after exact rollback.
An independent compact logical-tree model also drives 7500 production C
operations across three fixed seeds (`0x5ea105`, `0x726f6c6c6261636b`,
`0x9e3779b97f4a7c15`). It derives ledgers and physical ownership from logical
relationships, models finite sleep/receive and FIFO traffic, compares every
step, and includes failed partial allocation/output copy, backoff/restart,
fresh rebind, revocation, stop/reap and reuse. A failing assertion reports its
seed and exact step for deterministic replay.
These host cases establish deterministic corner cases; only the dedicated
QEMU hosting scenarios establish real ring-3 execution, actual challenge RPC,
child isolation and byte-verified storage progress. Their external oracle and
negative controls are separate from the existing storage-recovery oracle.
