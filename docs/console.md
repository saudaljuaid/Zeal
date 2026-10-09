# Interactive serial console

`make interactive` builds `build/interactive/zeal.img` using scenario 26 and
opens QEMU COM1 through the host terminal. The initial output is `zeal> `.
Type commands normally; Ctrl-C terminates QEMU. The console stays usable until
host termination. It has no command script, colors or terminal escape codes.
The ordinary `make run` demonstration remains available.

The client image's console branch runs at ring 3 in its existing private
address space. Parsing, line editing, formatting, rendering and file operations
live in Zig userspace. The privileged supervisor checks explicit serial
authority, copies checked user bytes and performs finite UART operations.
Knowing a name, identity or endpoint grants no device permission.

## Commands

| Syntax | Behavior |
| --- | --- |
| `help` | Lists the four implemented commands and their syntax. |
| `version` | Displays the build's source fingerprint and the actual system ABI. |
| `info` | Displays this cell's identity, role, generation, current endpoint and boot relationships; current tick and dependency endpoints; configured image, stack, writable, IO and line limits. Global statistics are explicitly unavailable. |
| `cat <path>` | Opens an existing file, collects authenticated chunks through the filesystem and RAM block cells, closes its handle and safely displays the bytes. |

Commands are case sensitive. Spaces separate arguments; leading/trailing
spaces are accepted. Quoting, expansion, pipes and extra arguments are
unsupported. A path is 2–16 bytes: `/` followed by 1–15 ASCII letters, digits,
`_`, `-` or `.`. This is a flat namespace; embedded slashes are invalid.

`cat /hello` reads the boot file's actual 14 bytes, `Zeal survives.`. The console
receives only open, chunk-read and close rights on the filesystem, without write
or raw-block authority. Its `cat` uses open-existing and never creates a missing
file. The underlying open right still permits legacy create-on-open packets from
other code within this same entitled cell. Missing names, malformed paths,
denied access, stale handles/generations, exhausted handles, unavailable services
and timeouts produce bounded errors followed by another prompt.

## Editing and rendering

The line buffer holds at most 96 printable ASCII bytes. Enter accepts CR, LF
or CRLF; the LF immediately following CR is consumed without a second command
or prompt. Backspace (`0x08`) and delete (`0x7f`) erase one character using
backspace-space-backspace. Empty lines return to the prompt. Unsupported
controls and non-ASCII input reject the entire line. After an unsupported byte
or a 97th printable byte, all input is discarded through Enter, including
erasure: a rejected command cannot execute a truncated valid prefix. The next
line starts normally.

File data remains bytes. Printable ASCII appears literally except backslash
is doubled to distinguish literal escape notation. LF becomes terminal CRLF.
Every other control/non-ASCII byte, including TAB, CR, NUL and ESC, appears as
uppercase `\xHH`. File bytes cannot inject terminal controls. A display newline
is appended before the prompt if the file has no final LF, without changing it.

Each input turn reads at most 64 bytes and sleeps one tick even under continuous
input. An idle console sleeps; the existing scheduler still runs other cells.
Output expands newlines in a 64-byte local buffer. Partial UART writes are
accepted. Each flush permits at most 64 positive-progress calls and eight total
zero-progress attempts, with one-tick sleeps on zero progress. A failed serial
interface ends this cell incarnation finitely.

## Authority and additive ABI

Manifest v2 root flags retain active bit 0 and add console bit 2 (`0x4`). An
optional boolean `console = true` compiles this explicit entitlement. At most
one active root may hold it. Templates and descendants cannot acquire it;
it is not an IPC right or delegable capability. Every read/write requires the
current live root's own configured flags. Cold restart retains the declaration
while clearing private state through the ordinary lifecycle mechanisms.

Existing ABI v4 structures and call numbers remain unchanged. These calls append
to the `int 0x80` ABI; all reserved arguments must be zero:

| Call | Number | Arguments and result |
| --- | ---: | --- |
| `console_read` | 20 | RDI writable buffer, RSI count 0–64, RDX zero. Returns actual copied input count; zero means no available byte. |
| `console_write` | 21 | RDI readable buffer, RSI count 0–64, RDX zero. Returns actual transmitted count, possibly partial. |
| `system_info` | 22 | RDI writable `SystemInfo`, RSI exactly 80, RDX zero. Returns this caller's configured resources, current tick and build identity. This metadata grants no device authority. |

`SystemInfo` is an 80-byte, 8-byte-aligned record: six u32 fields (`abi`,
`console_limit`, `image_budget`, `stack_budget`, `writable_budget`,
`console_entitled`), u64 `ticks` at offset 24, and 48 zero-padded build bytes
at offset 32. Compiled C/Zig tests check every field and call.
`tools/build_id.py` fingerprints the actual build source inputs; the kernel's
generated header supplies the displayed `source-` identification, also for
exported checkouts.

Device calls deny unentitled callers before accessing their addresses, reject
excessive counts/invalid ranges, use the existing private-memory checked-copy
mechanism, and attempt at most one device operation per byte. Zero count does
no copy or device access. No user pointer reaches the UART.

## File protocol and resource bounds

Existing `file_open` operation 10 and its right gain an additive open-existing
request of exactly 32 payload bytes: nonzero request ID at 0–7, zero-padded
name at 8–23, name length at byte 24, mode 1 at byte 25, zero reserved bytes
at 26–31. Legacy 10–24 byte opens retain create-on-open behavior. Missing existing
names return additive `NOT_FOUND=-9` without changing bytes, metadata, handles
or counters. Other packet and caller layouts remain supported.

The console reuses production storage transaction state. Each operation allows
four enqueue attempts with one-tick backoff, never retransmits after successful
enqueue, and permits eight receive attempts with ten-tick waits. Replies must
match authenticated sender generation, operation, request ID, handle and offset.
Open success requires a nonzero handle. Each command collects at most 128 bytes,
permits sixteen data chunks plus one EOF request, and attempts one bounded close
after successful open even on read failure. A partial failed file is not
displayed as complete. Close failure is reported separately because a handle may
remain allocated. A lost open reply leaves an unknown handle that this client
cannot reclaim. These are finite guest tick deadlines, not wall-clock guarantees.
The supported PIT supplies 100 ticks/second.

Storage remains volatile: four files, eight handles, 128 bytes per file and
eight-byte transfers. Service restart can invalidate handles and discard
metadata. Persistence, directories, general file permissions and executable
loading remain future work. Resource ceilings stay at four roots, eight runtime
slots, 128 private pages, 32 capabilities and eight-message queues. The console
uses the existing client root allocation, a 96-byte line, 64-byte input/output
buffers and 128-byte file collection; it adds no pages or cells. Its syscall
copy uses a 64-byte privileged temporary buffer; acceptance traces are capped
at 1,024 console records in addition to the existing bounded storage/wait traces.

## Finite acceptance

`make test-console` runs two finite acceptance boots and one normal interactive
boot using actual host serial input.
`make test` runs it after all pre-existing host, sanitizer, model, repeated QEMU,
platform and negative-control checks. Scenario 27 executes the same console
code as scenario 26, plus boundary assertions. The host checks every command,
repeated `/hello` reads, EOF and closes, missing-file noncreation, malformed
recovery, overflow, erasure, CRLF, rejected bytes and other-cell progress while
the console is idle. Live checks also verify entitled invalid-address/oversized/
reserved calls and unentitled read/write denial. After collecting the command
exchanges, the host requests QMP quit and verifies its acknowledgment, actual
process exit and the complete causal evidence. Host timeouts are bounded.

Normal scenario 26 suppresses trusted research output to keep the UI plain.
Fatal supervisor diagnostics remain visible if this configuration cannot boot
or encounters a trusted fault.
Scenario 27 sends trusted supervisor records through separate debugcon port
`0xe9`; application output stays on COM1. The observer joins copied UART bytes
and real ring-3 traps to host input/output, manifest/metadata, authenticated IPC
enqueue/delivery, filesystem transfer IDs, actual block reads, returned bytes,
EOF and close. Prompt-only and counterfeit causal traces fail. Trace exhaustion
fails acceptance. Serial/input/QMP transcripts, JSON, images and failure
witnesses remain under `build/console-acceptance`.
