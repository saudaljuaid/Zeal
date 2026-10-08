# Checked hosted snapshot admission

ABI 4 and manifest 2 retain their existing layouts, calls and operations 1–16.
`cells/analysis.toml` explicitly selects scenario 25, sealed broker template 5,
worker template 6 and bootstrap recipe 2. Old hosting templates 1/2, scalar
contract templates 3/4 and recipe 1 retain their existing RPC-only behavior.
The compiler and privileged manifest validator reject using recipe 2 with an
old template or selecting scenario 25 through an old recipe.

Recipe 2 extends the existing creation/rebind transaction. It requires the
current direct owner's configured recipe-2 creation domain, the approved sealed
template, resource allowance, and a configured filesystem self-grant containing
snapshot read, snapshot reply, snapshot release and delegation. The filesystem
is the current original filesystem root in slot 1; its role locates the sealed
dependency, while the checked domain and grant confer authority. User code
cannot supply another service endpoint. There is no new syscall, independent
spawn engine or mint-to-any-endpoint interface: existing create/rebind can
express this finite recipe without changing their checked request/result ABI.

| Holder | Exact target | Operations | Issuer / derivation |
| --- | --- | --- | --- |
| Direct owner | Created child | hosting request 15 | Owner / sealed RPC root |
| Created child | Direct owner | hosting reply 16 | Owner / sealed RPC root |
| Broker template 5 | Current filesystem | snapshot read 18, snapshot release 20 | Filesystem / current filesystem self-grant |
| Worker template 6 | Current filesystem | snapshot read 18 | Filesystem / current filesystem self-grant |
| Current filesystem | Created broker or worker | snapshot reply 19 | Filesystem / sealed recipe reply root |

The worker has no operation 17 control, operation 20 release, file-open,
file-write, raw-block or general delegation right. The separately admitted
broker release right is limited by filesystem object policy to an owner-bound
checker; it does not confer owner control. Scenario 25 also gives the original
probe/owner root narrow file-handle operations and snapshot control 17/read 18,
with filesystem result 14/snapshot reply 19 in the reverse direction. The
original client workload retains its original grants.

Every capability has the existing nonwrapping full epoch. The read leg is an
ordinary attenuation of the filesystem's exact current root entitlement. The
reply leg needs a sealed retargeting step because ordinary delegation cannot
change a parent's target. Both legs are checked against the exact child and
filesystem endpoint generations. `host-channel` and `host-rebind` each emit an
additional storage pair in scenario 25: `parent_cap` is the read/release leg and
`child_cap` is the reply leg. The trace derives holder, target, issuer, rights,
derivation and epoch from the actual capability table. Ordinary capability
query exposes holder, target, rights and parent; its handle carries the epoch.

Creation initializes private backing and the ring-3 frame before installing
both RPC and storage pairs. Two-entry capability preflight makes each pair
atomic. A failure in either pair, the checked result copy, or the final current
dependency check removes all unpublished pairs, allocation and reservations.
Consumed creation identities, request identities and capability epochs remain
retired. Capacity or epoch exhaustion fails closed. This is a single-CPU
interrupt-masked transaction; no child user turn can observe partial admission.

Rebind installs replacement pairs and copies the result before retiring the
predecessor pairs held in that exact runtime record. Failure removes the new
pairs and preserves any surviving predecessor connection; mandatory lifecycle
cleanup is never overwritten by a table rollback. Replacement does not revoke
another child's or root's routes. Queued messages using retired capabilities
are revalidated by the existing IPC delivery path and discarded. A worker fault
retires every route involving its old endpoint; cold restart has no storage
connection until its owner explicitly rebinds. Filesystem retirement invalidates
both route directions, and its fresh root grant cannot revive an old child
capability. Old immutable input objects also fail filesystem service policy;
rebind does not recreate their bytes.

The kernel authorizes operations against an exact service endpoint. It does not
encode a snapshot identity, acceptance decision or reader binding. Filesystem
policy checks the authenticated sender against an immutable object's exact
owner and current reader/checker binding. Broker/worker protocol policy controls
acceptance and dispatch. Snapshot revocation prevents newly authorized reads;
it cannot erase bytes already delivered into private cell memory. Delivery and
private-result fences belong to the finite service/work protocol.

Admission uses the existing 32 capability entries, with four entries per
admitted child and no enlarged queue, page, slot or payload ceiling. Each
runtime record retains three u64 fields for dependency endpoint/read/reply
handles: 24 bytes per record, 192 bytes over eight records. No new privileged
object table or buffer is added. The existing RPC and service capabilities are
separate from snapshot bytes, object metadata, reader bindings, worker attempts
and contract receipts. Stopping/reaping the child retires its IPC authority;
filesystem release clears byte backing and bindings; owner close/reap retires
the retained input record. These release points are separately observable.
