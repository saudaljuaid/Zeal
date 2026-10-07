# Zeal's native operating model

Zeal is an operating system under development. Its native units are cells,
explicit authority, finite resource domains, compositions and work contracts.
The implemented subset is deliberately bounded. The coherent relationship
between purpose, permission, backing, execution and outcome matters more than
giving an existing mechanism a new name.

## Primitives and enforcement boundaries

* **Cell:** an isolated executable system with checked immutable code, private
  writable backing, a logical instance, a current execution endpoint, explicit
  capabilities and a lifecycle. Diagnostic identity and image identity grant no
  creator, resource-owner or service authority. See `arch/x86_64/arch.c`,
  `kernel/hosting.c` and `policy/hosting.rs`.
* **Authority:** a checked permission with an exact holder generation, object or
  target, rights, scope and nonrepeating lifetime. Knowing an endpoint, role,
  template or contract token is insufficient. IPC capabilities, lifecycle
  controls and creation domains are distinct types. See `policy/capability.rs`
  and `docs/hosting-policy.md`.
* **Resource domain:** a finite commitment of allocatable descendant slots and
  private pages, conserved through creation, delegation, backoff, stop and reap.
  A cell's own pages are separate from its descendant allowance. Reserved credit
  is separate from free physical capacity, static kernel overhead and CPU time.
* **Composition:** checked relationships among cells, authority paths, resource
  commitments and lifetimes. Root, isolated supervisor and worker execute under
  one privileged supervisor, one global scheduler and one CPU. An isolated
  supervisor acquires no page-table manager or independent scheduler.
* **Work contract:** a bounded broker-owned record binding one authenticated
  requester generation, fixed profile/input, actual backing worker, current
  attempt, checked result, terminal outcome and settlement. Its service token
  grants no kernel management authority. See `docs/work-contracts.md`.
* **Offer:** an invitation backed by an already allocated worker and its actual
  slot/two private pages. The waiting worker has no authorization to compute the
  offered input until acceptance. A terminal record is no longer a live offer.
* **Acceptance:** the requester's explicit authorization of the exact offered
  profile/input. Incorrect owner, reference, generation, profile or input cannot
  start work. An exact duplicate is a narrow control-path idempotence rule.
* **Receipt:** a finite account of an authenticated current-attempt delivery and
  independently recomputed scalar result. It names the actual execution and
  attempt. It is neither a signature nor proof of arbitrary program correctness.
* **Settlement:** a terminal lifecycle/resource transition, with separate worker
  page release, kernel control/slot reap and service-record reap. Successful
  terminal publication follows actual worker cleanup. It is not payment.
* **Causal evidence:** bounded records joining authenticated requester input,
  actual worker backing/entry, acceptance, dispatch/delivery, verification,
  cleanup, terminal status and record reap. An application success marker alone
  does not establish this chain.

Assembly implements CPU entry, traps and privilege transitions. C implements
privileged allocation, address spaces, checked copies, bounded IPC, waits,
atomic lifecycle orchestration and trusted trace seams. Rust without `std`
implements lifecycle, hierarchy, generation, resource and authority policy.
Zig implements isolated applications, the broker's finite service state,
protocol and deterministic verification. Python/build tools validate artifacts,
reconstruct evidence and run independent finite models and tests.

The contract table is private Zig service state. It cannot edit kernel tables,
map another cell or manufacture credit. Kernel management calls enforce actual
creation, direct ownership, generation retirement, stop, reap and rebind. Broker
logic decides the fixed work profile, acceptance, result checking, cancellation
precedence and retained terminal metadata. These are different enforcement
points, not an additional privileged spawn engine or escrow object.

## Concrete evidence and finite limits

The existing foundations are exercised by `tests/hosting.c` under ASan/UBSan,
Rust policy tests, `cells/hosting_tests.zig`, and QEMU scenarios 21–23 with the
independent `tests/hosting_oracle.py`. The contract slice uses
`cells/contract_core.zig`, `cells/contract_wire.zig`, its production host tests,
the isolated runtime and the dedicated scenario 24 oracle. The complete
supported gate remains `make test`; host models and emulator evidence establish
different parts of the claim. Detailed protocol and test boundaries are in
`docs/work-contracts.md` and `docs/testing.md`.

| Capacity | Bound |
| --- | --- |
| Runtime slots | 8: 4 permanently reserved roots, 4 descendants |
| Hierarchy | 2 descendant levels: root → supervisor → worker |
| Private writable pages | 128 total; roots at most 80, descendants at most 48 |
| Per-cell private pages | At most 20; default supervisor 4 and worker 2 |
| IPC authority | 32 capability entries |
| Kernel queue and payload | 8 messages per cell; at most 32 payload bytes |
| Existing application RPC dispatcher | 4 pending records; 8 deferred messages |
| Contract broker | 2 records total, including unreaped terminal records |
| Broker descendant backing | 2 slots and 4 pages; broker's own 4 pages separate |
| Worker recovery | At most 1 retry per accepted contract |

Preallocated sealed-image backing, page tables, frames, physical-pool storage
and kernel tables are finite static overhead. Private page credit is not a bill
for every byte of that overhead. `tools/footprint.py` reports loaded BIOS bytes
and static supervisor footprint, enforces the loaded-byte window, and requires
the static supervisor end below 4 MiB. The test suite retains 32–128 MiB QEMU
coverage and the general-register-only CPU contract; floating point and SIMD
remain disabled.

## Direction: implemented slice, foundation and future

IMPLEMENTED means the specific finite behavior described by source and its
tests. FOUNDATION identifies an existing mechanism useful to a larger design.
FUTURE is a design direction, not a current API or guarantee. The following
table keeps all three boundaries explicit. Work-contract evidence refers to
the production core/runtime and scenario 24; authority/resource foundations
refer to the policy, C lifecycle engine and existing hosting tests above.

| Idea | IMPLEMENTED slice | FOUNDATION | FUTURE |
| --- | --- | --- | --- |
| A. Intent-based composition | Fixed profile and explicit acceptance | Typed connections and finite domains | Arbitrary intent solving and declarative application graphs |
| B. Resource passports | Actual slot/page backing and status | Manifest budgets, domains and capability rights | Portable inspectable declarations through arbitrary descendants; comprehensive metering |
| C. Revocable collaboration | Generation-safe channels and checked cleanup | Holder/target/issuer checks and revocation | General adoption and live migration |
| D. Verified work markets | One approved broker, fixed profile and capacity | Offers separated from acceptance | Provider matching, pricing, bidding, remote providers and distributed agreement |
| E. Causal work receipts | Exact attempt/execution and scalar recomputation | Immutable images and externally hashed test artifacts | Rich configuration provenance, consumed-resource records and checkable dependency graphs |
| F. Transactional composition | Individual atomic creation/rollback and finite contract transitions | Checked publication and cleanup | Atomic admission/publication of entire dependency graphs |
| G. Public failure domains | Worker recovery under a live broker; cold-cleared broker records | Owner-generation subtree retirement | General obligation survival and recovery policies |
| H. Replaceable providers | Approved immutable worker with automatic restart | Explicit fresh-generation rebind | Implementation hot swap and provider migration |
| I. Reproducible envelopes | Sealed templates, fixed scalar profile and finite authority/resources | Manifest/image checks | Arbitrary executables, timing reproduction and persistent checkpoints |
| J. Resource causality | Backing/status and structured evidence | Real domain queries and lifecycle traces | Desktop, terminal or graphical resource manager |
| K. Obligation graphs | Individual contract causality | Parentage and explicit authority edges | Distinct data, authority, reservation and failure edges; cycles and atomic acceptance |
| L. Authority following purpose | Service policy restricts one profile | Kernel capabilities enforce actual IPC/lifecycle rights | Purpose-bearing grants with defined enforcement and revocation |
| M. Alternatives before commitment | Offer and acceptance are observable separate acts | Allocated offer backing | Discovery, comparisons and cross-provider commitment |
| N. Result versus attempt | Stable contract across one worker restart; exact attempt identity | Stable logical worker/control, changing execution endpoint | Authorized provider replacement and richer logical obligations |
| O. Authority return at completion | Worker retirement/resource return before successful terminal publication | Generation revocation, wait cancellation, stop/reap | Revocation dependency tracking for rights shared among providers |
| P. Cost of waiting | Offered/running/recovering backing and finite waits | Slot/page commitments | Owner-approved restructuring; CPU, energy or monetary measurements |
| Q. Checking boundary | Deterministic recomputation | Exact authenticated delivery and input-sensitive work | Witness profiles, redundant providers, external verifiers and semantic proofs |
| R. Explainable rejection | Bounded protocol errors and terminal reasons | Existing precise management errors | Automatic planning and human-facing diagnostic interfaces |
| S. Bounded experiments | Provider faults coexist with independent storage verification | Isolation, attenuated authority and small domains | General trials, live promotion and implementation replacement |
| T. Owner commitments | One authenticated root requester | Explicit ownership and lifecycle control | Human identity/consent interfaces, federation and durable audit |

For a future document transformation, an application could propose a bounded
source reader, transform provider, checker and preview provider. Each connection
would declare permitted data/objects, backing and an acceptance rule. The owner
would inspect obligations before accepting them. Reader authority would not
silently flow to the transform provider; a preview would not establish correct
transformation. Failure would expose the permitted next attempt and unaffected
obligations. Completion would retire resources and temporary rights and retain a
bounded account of the accepted execution. This is a design example, not an
implemented document pipeline.

Such mechanisms might reduce software coordination costs and help compare
commitments and understand failures. Productivity, adoption and economic impact
are hypotheses requiring measurements and useful applications. This milestone
adds no money, financial tokens, blockchain, trading or distributed payments.

## Prior art and current boundary

Explicit authority and component trees have substantial prior art.
[seL4 capabilities](https://docs.sel4.systems/Tutorials/capabilities.html)
illustrate object-specific permissions and derivation/revocation.
[Genode's architecture](https://genode.org/documentation/architecture/core) and
[init configuration](https://www.genode.org/documentation/genode-foundations/26.05/system_configuration/The_init_component.html)
describe component resource/authority organization.
[Fuchsia realms](https://fuchsia.dev/fuchsia-src/concepts/components/v2/realms)
describe explicit component topology and capability routing.
These are useful comparisons, not compatibility claims or borrowed guarantees.
[seL4 MCS scheduling contexts](https://docs.sel4.systems/Tutorials/mcs.html)
enforce CPU budgets/periods; Zeal's memory and slot reservations enforce no CPU
budget. Channel/RPC lifetime rules also need care independently of application
completion; compare [Fuchsia channel call](https://fuchsia.dev/reference/syscalls/channel_call).
Zeal claims no world-first mechanism, formal verification, seL4 guarantees,
Zircon semantics or Genode compatibility.

Current limits include no general matching/market/pricing, CPU reservations or
metering, persistent receipts/storage, cryptographic signatures/attestation,
arbitrary code loading, transactional I/O effects, general exactly-once
execution, session leases, deeper hierarchy, provider migration, independent
schedulers, SMP, DMA protection or new devices. The existing storage workload
remains volatile with its own interrupted-write/unknown-outcome contract.
An accepted pure scalar result does not make arbitrary side effects retry-safe.
