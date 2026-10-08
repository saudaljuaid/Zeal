# Sealed roots and creation templates

Zeal's manifest v2 separates boot roots, immutable approved images, creation
configurations, and creator entitlements. A template is never an active cell.
The runtime registry owns execution state and logical instance ownership after
creation; it does not change the manifest or image catalog.

`cells/manifest.toml` retains the four original roots and their initial grants.
`cells/hosting.toml` additionally approves the purpose-built supervisor and worker
and grants creation authority to root identity 400 in hosting scenarios 21–23. The separate `cells/contracts.toml` source grants
root 400 templates 3/4 for the native contract branch in scenario 24; old
scenario manifests and grants retain their behavior. Configuration 24 is a
compatible additional branch; configuration 25 remains invalid.
Root identities 100, 200, and 300 remain the block, filesystem, and existing
storage application. They receive no creation domains. Standalone root boots
use the ordinary manifest, with one root active and all four root slots reserved.

## Serialized v2 format

Every integer is explicitly little-endian. Records contain no pointers. The
compiler and privileged validator share the field declarations in
`include/zeal/manifest_schema.def`, but read and validate the resulting artifact
independently. Unknown TOML fields, unsupported versions, nonzero reserved
fields, inconsistent lengths, and excessive counts fail validation.

Records appear in this order: header, root cells, initial grants, creation
templates, root creation domains. Counts identify exact lengths; trailing bytes
are rejected. The theoretical schema bound is 1,320 bytes, including four roots,
16 grants, eight templates, and eight domain records. The configured creator
policy currently permits only one root domain; eight is the finite capacity of
the shared dynamic-domain policy, including descendant domains.

| Record | Bytes | Fields, in byte order |
| --- | ---: | --- |
| Header | 40 | u32 magic, version, total_size, cell_count, grant_count, template_count, domain_count, reserved0, reserved1, reserved2 |
| Root | 64 | u32 identity, image, abi, flags; u64 entry; u32 image_budget, stack_budget, writable_budget, boot_config, restart_limit, restart_delay; 16-byte name |
| Initial grant | 16 | u32 holder identity, target identity, operation rights, flags |
| Template | 64 | u32 identity, image, abi, flags; u64 entry; u32 image_budget, stack_budget, writable_budget, boot_config, restart_limit, restart_delay, max_descendant_depth, child_template_mask, bootstrap_recipe, reserved |
| Root domain | 32 | u32 owner_identity, template_mask, slot_limit, page_limit, max_depth, bootstrap_recipe, reserved0, reserved1 |

The magic is `0x4c41455a`, version is 2, and cell ABI is 4. Root flags permit only
bit 0, meaning active. Grant flags and template flags are zero. Names contain
1–15 ASCII letters, digits, underscores, or hyphens followed by zero padding.
Template identities are 1–8; mask bit `identity - 1` selects a template. A mask
cannot reference a template absent from the sealed artifact.

There are at most eight catalog images, independently of the four root records
and eight template records. Root images occupy identities 1–4. Templates must
select an approved catalog image above 4, so existing storage services cannot
silently become dynamic programs with root-specific routing assumptions. The
current supervisor and worker images are 5 and 6. Multiple runtime instances
may select the same template; no image identity grants lifecycle authority.

## Approved configurations and entitlement

| Template | Image | Stack | Heap | Charged pages | Descendants below this instance | Child template mask |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 1, supervisor | 5 | 8 KiB | 8 KiB | 4 | 1 | 2, selecting worker |
| 2, worker | 6 | 4 KiB | 4 KiB | 2 | 0 | 0 |

`writable_budget` includes stack plus heap. Stack and heap are rounded to 4 KiB
pages independently. Validation preserves 4–16 KiB stacks, 0–64 KiB heaps, and
at most 20 charged private pages per cell. Tests cover independently rounded
non-page-aligned budgets, minimum and maximum approved configurations, and
unsigned arithmetic boundaries. Callers cannot resize these approved private
configurations during spawn; they request only a delegated descendant allowance.

Root 400's explicit creation domain allows templates 1 and 2, four descendant
slots, 48 descendant private pages, and maximum absolute depth 2. Templates
express a relative descendant depth: one for the supervisor, zero for the
worker. The runtime policy intersects the ancestor mask with the supervisor's
child mask and limits delegated depth by both the ancestor and template.

Scenario 25 uses `cells/analysis.toml`, templates 5/6 and explicit recipe 2.
It admits snapshot-only worker reads and separate broker checking/release routes
through the current filesystem. [Storage admission](storage-admission.md) states
the endpoint, entitlement, rollback and retirement boundary. Old sources cannot
silently select this behavior. ABI 4 and manifest 2 layouts remain stable.

Bootstrap recipe 1 entitles narrowly checked parent/child RPC. Both the root
creation domain and selected template must explicitly carry that recipe;
selecting an image alone does not create channel authority. Dynamic programs
receive no filesystem or block capabilities. The initial root grant list stays
separate and retains its original narrow storage operation rights.

All root budgets remain within their existing 80-page reservation. Descendant
commitments remain within 48 pages, with a 128-page global physical private
pool. Root-domain reservations cannot manufacture physical pages or runtime
slots. Actual descendant allocation and delegated credit follow the hosting
policy's conservation rules, not the number of template records.

## Build and privileged validation

`tools/manifest.py` accepts four to eight checked binary image paths in catalog
identity order. Hosting scenarios require an explicit creation domain and all
four roots active; a default manifest cannot become a creator merely because a
caller chooses a scenario or image number. Solo boots cannot retain the hosting
fixture's creation domain.

Each image is produced through the normal Zig ELF link and image checker.
`tools/check_cell.py` validates the ELF64 little-endian executable header,
entry `0x40000000`, at most eight program headers, immutable bounded load
segments, nonoverlapping virtual/file ranges, alignment, and an executable entry.
Writable image segments and executable stack declarations are rejected. The
flat image must be nonempty and at most 64 KiB; every selected image must fit
its manifest image budget. The privileged validator checks catalog identities,
lengths, entries, every serialized field, references, memory configuration,
lifecycle parameters, masks, depth, and explicit recipes before returning a
parsed manifest. A rejection leaves its output object unchanged.

The linker checks the BIOS loaded payload ends at or below `0x90000`, and the
image builder separately caps loaded kernel bytes at `0x70000`. The supervisor's
static address footprint must end below 4 MiB. These checks include preallocated
kernel tables and backing; private page allowances do not claim to charge all
kernel memory. `make test` retains these checks while validating both ordinary
and hosting images.
