# Volatile storage and file handles

Zeal's isolated Zig block cell owns writable RAM storage. The isolated Zig
filesystem cell owns names, lengths, and handles, and performs every file-byte
read and write through capability-authorized IPC to that block cell. It keeps
no file-data cache. Assembly handles CPU entry and privilege transitions;
privileged C performs scheduling, checked copies, and bounded IPC; Rust without
`std` owns lifecycle and authority policy.

## Fixed limits

| Resource | Limit |
| --- | --- |
| Block backing | 512 bytes in the block cell's manifest-budgeted private writable memory |
| Transfer chunk | 0–8 bytes |
| Files | Four, including `/hello`; at most three writable files |
| File extent and maximum length | 128 bytes per file, fixed extent per table slot |
| Filename | 2–16 bytes including leading `/` |
| Open handles | Eight across all owners and files |
| Supervisor queue and filesystem's deferred inbox | Eight messages each |
| Message payload | 32 bytes |

Names begin with `/`; every remaining byte must be ASCII `A–Z`, `a–z`, `0–9`,
`_`, `-`, or `.`. Names are case sensitive and have no terminator on the wire.
An inner slash, NUL, space, non-ASCII byte, missing leading slash, or overlong
name is invalid. This is a flat namespace: there are no directories, deletion,
truncation, permissions framework, or persistent filesystem format.

A cold block boot clears all 512 bytes and initializes bytes 0–13 to the
14-byte string `Zeal survives.`. The filesystem starts with that read-only
`/hello` file in extent zero. The existing verified `/hello` demonstration
continues to read the actual block backing. Generic block operations are
bounded byte-addressed reads and writes; `/hello` immutability is enforced by
the filesystem, and applications receive no raw-block authority.

A block address and count are unsigned 32-bit values. The block rejects a
count greater than eight, addition overflow, or a range outside `[0,512)`
before copying or changing bytes. An empty operation at address 512 succeeds.
A successful block chunk transfers its entire count; a rejected chunk changes
nothing.

## File operations

`file_open` opens an existing name or creates an empty file, then issues a new
handle. Opening again issues another handle; it does not truncate the file.
For creation, the filesystem first writes sixteen zero chunks through the
block service to clear the entire selected extent. Only acknowledged clearing
publishes the name and handle. A failed or interrupted clear can modify an
unpublished free extent, but does not publish metadata, consume a handle, or
alter another file. File-table exhaustion, handle-table exhaustion, or handle
counter exhaustion returns `NO_SPACE` without creating a file.

`file_chunk_read` takes a handle, explicit offset, and requested count. It
returns up to eight bytes and the returned count. EOF is a successful zero-byte
result. Offsets from the current length through 128 return EOF, including for
an empty file; offsets above 128 are rejected. A read crossing EOF returns the
remaining bytes. Overflow and overlarge counts are rejected.

`file_write` takes a handle, explicit offset, count, and bytes. It overwrites
existing bytes and can grow the length when starting at or before the current
EOF. It never truncates. A gap, including an empty write beyond EOF, is
unsupported and returns `INVALID`. A resulting length above 128 is rejected.
An empty write at an allowed offset succeeds without growth. `/hello` writes
return `DENIED`. The filesystem updates length only after accepting the
matching successful block reply.

`file_close` releases one handle, leaving the file and its contents intact.
The same name can then be reopened. Closing an invalid or already closed
handle returns `STALE`. Files are not deleted, so all occupied file slots stay
occupied until a filesystem or dependency reset.

Each accepted chunk is all-or-none at the block boundary. A sequence of chunks
is not one atomic transaction: a later failure can leave a committed prefix,
and clients must use each acknowledged count. Failed bounds, name, handle,
owner, or authority checks do not change unrelated files or expose old extent
contents.

## Ownership and operation authority

A file handle belongs to the exact calling endpoint, including its generation.
Its 64-bit token contains the filesystem generation in the high 32 bits, a
24-bit monotonically increasing serial, and an eight-bit slot number plus one.
The filesystem compares the complete token and owner with its active handle
entry. Forged tokens, other cells, newer generations of the same owner, closed
handles, and stale reused slots are rejected. Handles from an earlier
filesystem generation are rejected even if slots and serials are reused there.

Serials 1 through `0xffffff` can be issued. Exhaustion is terminal within that
filesystem lifetime; dependency rebinding never resets the serial. Filesystem
generations above `0xffffffff` cannot issue handles. Neither counter wraps
into an old valid token.

Possessing a file handle grants no IPC authority. Every open, read, write, and
close requires its own operation right in the existing capability system.
The supervisor checks holder, target generation, and operation at send and
again at queue delivery. A delegated legacy `file_read` grant cannot authorize
`file_write`, raw block operations, or any other unrelated operation. Replies
also require their own operation rights.

Revocation preserves an open file handle but prevents subsequent operations
through the revoked capability. Kernel-queued messages retain their capability
and are revalidated or removed on revocation. Work already received by a
service can finish, including a request held in the filesystem's bounded
private deferred inbox. Revocation does not retroactively undo delivered work.
A caller with another live appropriate capability can continue using its own
still-valid handle. Delegation never transfers file-handle ownership.

## ABI v3 protocol and bounded waits

ABI v3 retains syscall numbers and structure layouts, and adds operation rights
for the storage protocol. The compiled C, Rust, and Zig contracts and manifest
validator agree on fourteen operation bits. The legacy `/hello` operations and
capability handoff remain supported.

| Operation | Number |
| --- | --- |
| `block_read`, `block_write`, `block_reply` | 7, 8, 9 |
| `file_open`, `file_chunk_read`, `file_write`, `file_close`, `file_result` | 10, 11, 12, 13, 14 |

All integer fields are explicitly little-endian. Open contains a nonzero
64-bit request identity followed by exactly 2–16 filename bytes; its payload
length is 10–24. Other storage requests and replies have exact length 32:

| Payload bytes | Field |
| --- | --- |
| 0–7 | Nonzero request identity, unsigned 64-bit |
| 8–15 | File handle, unsigned 64-bit; zero for block requests/replies |
| 16–19 | Explicit byte offset, unsigned 32-bit |
| 20–23 | Request count or signed reply result, 32-bit |
| 24–31 | At most eight data bytes, zero padded |

Read requests have zero data. Write requests contain exactly the count's bytes
and zero padding. Close has zero offset, count, and data. Successful open and
close return zero; open returns the issued handle. Read and write return a
nonnegative byte count; read returns the bytes, while write returns zero data.
Failures use the existing negative results: `INVALID=-1`, `DENIED=-2`,
`STALE=-3`, `TOO_LARGE=-6`, `NO_SPACE=-7`, and `TIMEOUT=-8`. Supervisor enqueue
backpressure is `AGAIN=-4`, and checked-copy failures remain `BAD_ADDRESS=-5`.
Malformed lengths, counts, identities, reserved fields, names, or padding are
discarded without a storage mutation; a waiting caller eventually times out.

The application and filesystem use separate monotonically increasing 64-bit
request identities. Exhaustion is terminal. Reply matching requires the
expected sender endpoint generation, reply operation, request identity, handle,
and offset; block success must match the exact requested count. Opening
returns a new handle rather than echoing one. Late replies cannot complete a
new request, even after a timeout or rebind.

Queue backpressure permits at most four send attempts, with finite one-tick
sleeps between retry attempts. Once enqueued, a request is never automatically
resent. Each transaction allows at most eight receive attempts with ten-tick
finite waits; timeout, dependency change, or receive-budget exhaustion ends the
request. Unrelated received application work is preserved in an eight-message
FIFO inbox at the filesystem. A full inbox ends the pending transfer rather
than overflowing it. Dependency absence and interrupted requests do not cause
an unbounded blocking receive or busy polling.

## Interrupted operations and restart behavior

A timeout or missing reply means the outcome may be unknown, not that a write
was rolled back. There is no duplicate suppression or exactly-once guarantee.
If the block applied a write but its reply is lost, overwritten bytes may have
changed; unacknowledged file growth remains hidden by the previous length. If
the filesystem accepted the block reply and its application reply is lost, the
write and length change are already committed. Retrying with a fresh identity
is a new operation. A lost successful open reply leaves an allocated handle
whose token the caller may not know; repeated retries can exhaust the eight
slots. Such a slot is recovered by service or dependency reset, not by an
unimplemented lease or reclamation mechanism.

A filesystem cold restart discards names, lengths, and handles, then recreates
only `/hello`. The healthy block cell's bytes can remain in its private RAM,
but old writable extents are not accessible through filesystem metadata. Each
new file is fully zeroed through the block service before publication, so
previous bytes cannot be exposed by reuse.

A block cold restart clears the backing and restores `/hello`. On observing
any block endpoint change or its temporary absence, the filesystem discards
all writable metadata and handles, preserving its serial counter. The client
rejects stale handles, looks up current endpoints and capabilities, and starts
new operations. A filesystem restart also changes the handle's filesystem
generation. This is volatile storage: file data does not survive the recovery
contract, machine shutdown, or a fresh boot.

Scenario 20 demonstrates three real isolated application cycles: create
`/note`, check empty EOF and a rejected gap, write the 26-byte payload
`Zeal writable RAM storage.` in four chunks, close, reopen, read, and verify
all bytes. It checks a write denied under delegated read authority, then repeats
valid work after separate block and filesystem restarts, explicitly rejecting
old handles at both boundaries. The external oracle joins application requests,
filesystem-to-block request identities, actual block outcomes, replies, and
application byte verification; completion markers alone are insufficient.

Storage tracing is bounded to 512 successful storage IPC records and 512 storage
reports per supervisor boot. Records carry cell identity and generation, with
request identities, operation results, transfer links, and verified application
bytes where applicable. `make test` preserves serial traces and machine-readable
results under `build/research/`; see [validation](testing.md).
