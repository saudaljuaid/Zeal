# Bounded lifecycle management ABI v4

Cells invoke checked management operations through the existing `int 0x80`
entry. Assembly continues to own privilege entry and return. C validates user
copies and orchestrates allocation, publication, cleanup, waits, and scheduling.
Rust owns hierarchy, resource-accounting, lifecycle, and typed authority policy.
Zig supervisors invoke this interface from ring 3. Every cell remains under one
privileged supervisor and the existing global scheduler.

## Calls and checked buffers

The call number is in RAX; arguments are in RDI, RSI, and RDX. Results use the
existing signed errors: 0 success; -1 invalid; -2 denied; -3 stale; -4 again;
-5 bad address; -6 too large; -7 no space; -8 finite wait timeout.

| Call | Number | RDI | RSI | RDX |
| --- | ---: | --- | --- | --- |
| Create | 13 | CreateRequest pointer | Exactly 32 bytes | CreateResult output pointer |
| Child status | 14 | Control token | CellStatus output pointer | Exactly 104 bytes |
| Stop subtree | 15 | Control token | 0 | 0 |
| Reap terminal child | 16 | Control token | 0 | 0 |
| Rebind current execution | 17 | RebindRequest pointer | Exactly 32 bytes | CreateResult output pointer |
| Revoke creation domain | 18 | Domain token | 0 | 0 |
| Own domain status | 19 | Domain token | DomainStatus output pointer | Exactly 72 bytes |

Inputs must be readable and outputs writable within the caller's private
address space. Read-only images, unmapped guards, overflowed ranges, and crossed
private regions are invalid destinations. Reserved fields are zero. Template
and allowance values are fixed-width; an image pointer, filename, identity, or
caller-supplied parent claim cannot substitute for creation authority.

The kernel validates and reserves before publication, initializes private
backing and the ring-3 frame, installs only the approved narrow channel recipe,
and copies the complete result to the owner before publishing a runnable child.
All ordinary failures roll back allocations, charges, domains, controls,
channels, waits, and unpublished registry state. Identity epochs consumed by an
unpublished preparation are deliberately retired and never decremented.

## Structure layout

These are native little-endian x86-64 ABI structures with eight-byte alignment.
C, Rust policy structures, and Zig are checked as compiled artifacts. Each
u64 below occupies eight bytes and each u32 occupies four; order is significant.

| Structure | Bytes | Ordered fields |
| --- | ---: | --- |
| BootInfo | 80 | u32 abi, role; u64 generation, scenario, endpoint, parent_endpoint, instance, creation, parent_channel; u32 template_id, depth, identity, reserved |
| CreateRequest | 32 | u64 authority, request; u32 template_id, descendant_slots, descendant_pages, reserved |
| CreateResult | 48 | u64 instance, control, endpoint, channel, creation; u32 slot, identity |
| RebindRequest | 32 | u64 authority, control, request, reserved |
| CellStatus | 104 | u64 instance, control, endpoint, domain, parent_instance, parent_endpoint, generation; u32 slot, template_id, depth, phase, faults, restarts, reason, own_pages, reserved_slots, reserved_pages, available_slots, available_pages |
| DomainStatus | 72 | u64 domain, holder, instance; u32 slot_limit, page_limit, owned_slots, owned_pages, reserved_slots, reserved_pages, available_slots, available_pages, max_depth, template_mask, recipe, revoked |

The original message remains 48 bytes with a 32-byte payload. Operations 15 and
16 are hosting request and hosting reply; the operation-rights mask is now
`0x000fffff`. Operations 17–20 are snapshot control, read, reply and
checker release. They are provisioned only by explicit new grants and the
approved scenario-25 recipe; see [checked storage admission](storage-admission.md).
All preexisting operation and syscall numbers are stable. Initial
root storage grants retain their narrow rights. Bootstrap data names the
child's own endpoint, logical instance, diagnostic identity, and exact parent
endpoint; dynamic applications do not infer themselves from a root role lookup.

## Three distinct lifetimes

A logical instance exists from committed creation until final reap. Its stable
control token permits its direct owner to query it across allowed automatic
restarts. The execution endpoint names one published incarnation and changes
on restart and later slot reuse. A creation-domain token is execution-scoped:
a restarted supervisor obtains fresh current-generation creation authority
only after its still-live owner explicitly rebinds it.

Tokens use disjoint type ranges in their low byte. Logical-instance objects
use `0x41`–`0x48`, controls `0x51`–`0x58`, creation domains `0x61`–`0x68`, and
internal unpublished transactions `0x71`–`0x78`. Endpoints use slot bytes 1–8.
A high-byte monotonic epoch accompanies each typed object; accepted epochs and
execution generations do not exceed `INT64_MAX >> 8`. Exhaustion is terminal:
no object or endpoint counter wraps into an old valid value. Internal
transaction tokens are never user creation authority.

Control rights are query=1, stop=2, reap=4. Direct ownership binds both parent
logical instance and exact parent endpoint generation. Knowledge of an endpoint
or diagnostic identity grants no lifecycle right. A child cannot stop its
parent or sibling, and copying a parent's IPC capability does not transfer its
holder generation. Lifecycle and creation tokens fail the existing IPC,
endpoint, and filesystem-handle type checks.

Status is authoritative, including after a lost application message. Its phase
uses the existing policy values: dormant=0, ready=1, backoff=2, quarantined=3,
stopped=4. A current execution endpoint is zero while it cannot run. Generation
reports the current or last assigned execution generation, including terminal
status. A failed restart preparation deliberately retires its assigned
generation; it cannot publish an endpoint or make a stopped instance run.
The last reason is 0 initially, 2 for stop/exit, 5 for failed architecture
initialization, or `0x10000 | fault_vector` for a fault. A repeated stop of an
already quarantined instance preserves its actual fault reason.
Parents use finite receives or sleeps between status checks.

## Reservations, stop, and reaping

Every creation domain conserves its committed slot and page limits separately:

`owned allocations + reserved subdomain allowance + available credit = limit`

A supervisor's own pages are charged separately from the allowance reserved
for its descendants. A grandchild allocation consumes its immediate domain's
allowance; ancestors do not charge that same allocation again. Logically
reserved credit is separate from actual unique physical-page ownership.

A recoverable child retains its own pages and assigned allowance through
backoff. Its failure retires all descendants owned by the old execution before
another user turn: waits are cancelled, related queued work and authority are
invalidated, pages are cleared/released, and descendant records automatically
reaped bottom-up. Grandchild credit returns inside the supervisor's still-held
reservation. Cold restart obtains a strictly newer execution generation and
clears private writable memory. Fresh channel and creation authority require
an explicit current-generation rebind from a live recipe entitlement.

Stop applies to ready, waiting, or backoff children and cancels delayed restart.
It clears/retires descendants and releases the stopped child's private pages
and delegated reservation. Its bounded terminal record and slot remain charged
until reap. Repeated stop is harmless; reap requires terminal state. Reap
invalidates control and instance identity, returns the retained slot charge,
and permits reuse with a new logical identity, new control epoch, and strictly
newer published generation. Old controls remain stale after reap.

Creation revocation prevents future creation and fresh rebinding in that domain
and delegated descendant domains. Existing direct-owner query/stop/reap
control remains valid, so revocation cannot prevent mandatory cleanup. It does
not implicitly stop already-running children. An owner's generation retirement
automatically reaps descendants whose dead direct owner could no longer reap;
there are no orphaned terminal records awaiting authority from a dead execution.

The finite boundary is eight execution slots, four permanently reserved roots,
four dynamic child slots, depth at most two below a root, eight logical instance
records, eight domains, eight templates, 32 IPC capability entries, eight queued
messages per cell, and 128 private writable pages. Preallocated image backing,
page tables, frames, and supervisor tables are finite static overhead; page
allowances do not represent total kernel memory charges.
