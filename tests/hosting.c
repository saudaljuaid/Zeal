/* Production orchestration under ASan/UBSan. The callbacks below supply real
 * checked physical memory and bounded broker/wait mechanisms; they do not
 * implement another spawn engine. Failure injection is host-fixture-only. */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <zeal/hosting.h>
#include <zeal/memory.h>

enum injection_point {
    INJECT_NONE, INJECT_INPUT_RANGE, INJECT_OUTPUT_RANGE, INJECT_COPY_IN,
    INJECT_SPACE_BEFORE, INJECT_SPACE_PARTIAL, INJECT_SPACE_AFTER,
    INJECT_MEMORY_CHECK, INJECT_FRAME, INJECT_COPY_OUT,
    INJECT_RESET_BEFORE, INJECT_RESET_AFTER,
};
struct injection {
    enum injection_point point;
    bool consumed, fail;
    int fault_cell;
};
struct fixture {
    struct z_runtime runtime;
    struct z_broker broker;
    struct z_wait_table waits;
    struct z_memory_pool memory;
    struct z_frame frames[Z_CELL_COUNT];
    struct z_memory_layout layouts[Z_CELL_COUNT];
    struct z_manifest manifest;
    struct z_image_catalog catalog[8];
    uint8_t images[8][64];
    uint8_t image_backing[Z_CELL_COUNT][Z_MANIFEST_PAGE_SIZE];
    struct injection injection;
    unsigned events[Z_RUNTIME_EVENT_COUNT];
    unsigned publication_count, private_initializations, result_copies;
    uint64_t now, sequence[Z_CELL_COUNT];
};
static struct fixture f;
static unsigned fixture_count, fault_injections, failure_injections;
static const uint64_t input_address = Z_STACK_BASE + 64;
static const uint64_t output_address = Z_STACK_BASE + 512;
static const uint64_t status_address = Z_STACK_BASE + 1024;

static uint64_t endpoint(unsigned cell)
{
    return z_policy_handle(&f.broker.policies[cell], cell);
}
static bool inject(struct fixture *fixture, enum injection_point point)
{
    struct injection *control = &fixture->injection;
    if (control->point != point || control->consumed) return false;
    control->consumed = true;
    if (control->fail) ++failure_injections;
    if (control->fault_cell >= 0) {
        ++fault_injections;
        int result = z_runtime_fault(&fixture->runtime, (unsigned)control->fault_cell,
                                     fixture->now, UINT64_C(0x0e));
        assert(result == Z_OK);
    }
    return control->fail;
}
static bool range(void *context, unsigned cell, uint64_t address, size_t length, bool write)
{
    struct fixture *fixture = context;
    if (inject(fixture, write ? INJECT_OUTPUT_RANGE : INJECT_INPUT_RANGE)) return false;
    return cell < Z_CELL_COUNT && z_memory_copy_valid(&fixture->memory, cell,
                    &fixture->layouts[cell], address, length, write);
}
static bool copy_in(void *context, unsigned cell, void *destination, uint64_t source, size_t length)
{
    struct fixture *fixture = context;
    if (inject(fixture, INJECT_COPY_IN)) return false;
    return cell < Z_CELL_COUNT && z_memory_copy_in(&fixture->memory, cell,
                    &fixture->layouts[cell], destination, source, length);
}
static bool copy_out(void *context, unsigned cell, uint64_t destination, const void *source, size_t length)
{
    struct fixture *fixture = context;
    if (inject(fixture, INJECT_COPY_OUT)) return false;
    if (length == sizeof(struct z_create_result)) {
        const struct z_create_result *result = source;
        // Spawn output must precede execution publication; rebind output names
        // an existing execution and is checked separately in focused cases.
        if (result->slot < Z_CELL_COUNT && !fixture->runtime.records[result->slot].published) {
            assert(z_policy_resolve(fixture->broker.policies, Z_CELL_COUNT, result->endpoint) < 0);
        }
        ++fixture->result_copies;
    }
    return cell < Z_CELL_COUNT && z_memory_copy_out(&fixture->memory, cell,
                    &fixture->layouts[cell], destination, source, length);
}
static bool space_init(void *context, unsigned cell, const void *image, size_t length,
                        const struct z_manifest_cell *config)
{
    struct fixture *fixture = context;
    if (cell >= Z_CELL_COUNT || image == NULL || length == 0 || inject(fixture, INJECT_SPACE_BEFORE)) return false;
    if (!z_memory_allocate(&fixture->memory, cell, config->stack_budget, config->writable_budget)) return false;
    const struct z_memory_allocation *allocation = &fixture->memory.cells[cell];
    unsigned image_pages = (config->image_budget + Z_MANIFEST_PAGE_SIZE - 1) / Z_MANIFEST_PAGE_SIZE;
    assert(image_pages == 1 && length <= sizeof(fixture->image_backing[cell]));
    memset(fixture->image_backing[cell], 0, sizeof(fixture->image_backing[cell]));
    memcpy(fixture->image_backing[cell], image, length);
    fixture->layouts[cell] = (struct z_memory_layout) {
        .image = fixture->image_backing[cell], .image_size = image_pages * Z_MANIFEST_PAGE_SIZE,
        .stack_size = (uint32_t)allocation->stack_pages * Z_MANIFEST_PAGE_SIZE,
        .heap_size = (uint32_t)allocation->heap_pages * Z_MANIFEST_PAGE_SIZE,
    };
    for (unsigned page = 0; page < allocation->count; ++page) {
        const uint8_t *bytes = z_memory_page(&fixture->memory, cell, page);
        assert(bytes != NULL);
        for (unsigned i = 0; i < Z_MANIFEST_PAGE_SIZE; ++i) assert(bytes[i] == 0);
    }
    ++fixture->private_initializations;
    if (inject(fixture, INJECT_SPACE_PARTIAL)) return false;
    return !inject(fixture, INJECT_SPACE_AFTER);
}
static bool space_reset(void *context, unsigned cell, const void *image, size_t length,
                         const struct z_manifest_cell *config)
{
    struct fixture *fixture = context;
    if (inject(fixture, INJECT_RESET_BEFORE)) return false;
    if (fixture->memory.cells[cell].count == 0)
        return space_init(context, cell, image, length, config);
    if (!z_memory_reset(&fixture->memory, cell)) return false;
    assert(length <= sizeof(fixture->image_backing[cell]));
    memset(fixture->image_backing[cell], 0, sizeof(fixture->image_backing[cell]));
    memcpy(fixture->image_backing[cell], image, length);
    for (unsigned page = 0; page < fixture->memory.cells[cell].count; ++page) {
        const uint8_t *bytes = z_memory_page(&fixture->memory, cell, page);
        assert(bytes != NULL);
        for (unsigned i = 0; i < Z_MANIFEST_PAGE_SIZE; ++i) assert(bytes[i] == 0);
    }
    return !inject(fixture, INJECT_RESET_AFTER);
}
static void space_release(void *context, unsigned cell)
{
    struct fixture *fixture = context;
    if (cell < Z_CELL_COUNT) {
        if (fixture->memory.cells[cell].count != 0) assert(z_memory_release(&fixture->memory, cell));
        fixture->layouts[cell] = (struct z_memory_layout){0};
    }
}
static bool frame_init(void *context, unsigned cell, struct z_frame *frame)
{
    struct fixture *fixture = context;
    if (inject(fixture, INJECT_FRAME) || cell >= Z_CELL_COUNT ||
        fixture->memory.cells[cell].count == 0) return false;
    *frame = (struct z_frame) { .rip = Z_IMAGE_BASE, .cs = 0x1b, .ss = 0x23,
        .flags = 0x202, .rsp = Z_STACK_BASE + fixture->layouts[cell].stack_size - sizeof(uint64_t) };
    return true;
}
static unsigned space_pages(void *context, unsigned cell)
{
    struct fixture *fixture = context;
    return cell < Z_CELL_COUNT ? fixture->memory.cells[cell].count : 0;
}
static bool memory_check(void *context)
{
    struct fixture *fixture = context;
    return !inject(fixture, INJECT_MEMORY_CHECK) && z_memory_check(&fixture->memory);
}
static void trace(void *context, const struct z_runtime_event *event)
{
    struct fixture *fixture = context;
    assert(event->kind < Z_RUNTIME_EVENT_COUNT);
    ++fixture->events[event->kind];
    if (event->kind == Z_RUNTIME_PUBLISH) {
        assert(event->record.published);
        assert(endpoint(event->cell) == event->transaction.endpoint);
        assert(fixture->result_copies > fixture->publication_count);
        ++fixture->publication_count;
    }
}
static const struct z_runtime_callbacks callbacks = {
    .range = range, .copy_in = copy_in, .copy_out = copy_out,
    .space_init = space_init, .space_reset = space_reset, .space_release = space_release,
    .frame_init = frame_init, .space_pages = space_pages, .memory_check = memory_check, .trace = trace,
};
static bool receive_copy(void *context, unsigned cell, uint64_t generation,
                          uint64_t destination, const struct z_message *message)
{
    struct fixture *fixture = context;
    if (cell >= Z_CELL_COUNT || fixture->broker.policies[cell].phase != Z_POLICY_READY ||
        fixture->broker.policies[cell].generation != generation ||
        !z_memory_copy_valid(&fixture->memory, cell, &fixture->layouts[cell],
                              destination, sizeof(*message), true)) return false;
    return message == NULL || z_memory_copy_out(&fixture->memory, cell,
                    &fixture->layouts[cell], destination, message, sizeof(*message));
}
static void store(unsigned cell, uint64_t address, const void *value, size_t length)
{
    assert(z_memory_copy_out(&f.memory, cell, &f.layouts[cell], address, value, length));
}
static void load(unsigned cell, uint64_t address, void *value, size_t length)
{
    assert(z_memory_copy_in(&f.memory, cell, &f.layouts[cell], value, address, length));
}
static unsigned allocated_pages(void)
{
    unsigned total = 0;
    for (unsigned cell = 0; cell < Z_CELL_COUNT; ++cell) total += f.memory.cells[cell].count;
    return total;
}
static unsigned live_caps(void)
{
    unsigned total = 0;
    for (unsigned i = 0; i < Z_CAPACITY; ++i) total += !!f.broker.capabilities.entries[i].live;
    return total;
}
static uint64_t domain(unsigned caller)
{
    struct z_boot_info info;
    assert(z_runtime_boot(&f.runtime, caller, &info) == Z_OK);
    return info.creation;
}
static struct z_domain_status ledger(unsigned caller, uint64_t authority)
{
    assert(z_runtime_domain_status(&f.runtime, caller, authority, status_address,
                                    sizeof(struct z_domain_status)) == Z_OK);
    struct z_domain_status result;
    load(caller, status_address, &result, sizeof(result));
    assert(result.owned_slots + result.reserved_slots + result.available_slots == result.slot_limit);
    assert(result.owned_pages + result.reserved_pages + result.available_pages == result.page_limit);
    return result;
}
static struct z_cell_status status(unsigned caller, uint64_t control)
{
    assert(z_runtime_status(&f.runtime, caller, control, status_address,
                            sizeof(struct z_cell_status)) == Z_OK);
    struct z_cell_status result;
    load(caller, status_address, &result, sizeof(result));
    return result;
}
static struct z_create_request creation(unsigned caller, uint64_t authority,
                                         unsigned template_id, unsigned slots, unsigned pages)
{
    assert(f.sequence[caller] != UINT64_MAX);
    return (struct z_create_request) { .authority = authority, .request = ++f.sequence[caller],
        .template_id = template_id, .descendant_slots = slots, .descendant_pages = pages };
}
static int create_request(unsigned caller, const struct z_create_request *request,
                           uint64_t input, size_t length, uint64_t output)
{
    store(caller, input_address, request, sizeof(*request));
    return z_runtime_create(&f.runtime, caller, input, length, output);
}
static struct z_create_result create(unsigned caller, uint64_t authority,
                                      unsigned template_id, unsigned slots, unsigned pages)
{
    struct z_create_request request = creation(caller, authority, template_id, slots, pages);
    int result = create_request(caller, &request, input_address, sizeof(request), output_address);
    if (result != Z_OK) fprintf(stderr, "create caller=%u template=%u result=%d\n", caller, template_id, result);
    assert(result == Z_OK);
    struct z_create_result created;
    load(caller, output_address, &created, sizeof(created));
    assert(created.slot >= Z_ROOT_COUNT && created.slot < Z_CELL_COUNT);
    assert(endpoint(created.slot) == created.endpoint);
    assert(z_runtime_check(&f.runtime));
    return created;
}
static int rebind(unsigned caller, uint64_t authority, uint64_t control,
                    struct z_create_result *result)
{
    struct z_rebind_request request = { .authority = authority, .control = control,
        .request = ++f.sequence[caller] };
    store(caller, input_address, &request, sizeof(request));
    int code = z_runtime_rebind(&f.runtime, caller, input_address, sizeof(request), output_address);
    if (code == Z_OK && result != NULL) load(caller, output_address, result, sizeof(*result));
    return code;
}
static int send(unsigned source, uint64_t target, uint64_t cap, uint32_t operation, uint64_t marker)
{
    struct z_message message = { .sender = UINT64_MAX, .operation = operation, .length = 8 };
    memcpy(message.payload, &marker, sizeof(marker));
    return z_broker_send(&f.broker, source, target, cap, &message);
}
static void fixture_catalog_config(uint32_t supervisor_stack, uint32_t supervisor_writable,
                            uint32_t worker_stack, uint32_t worker_writable,
                            unsigned depth, unsigned slot_limit, unsigned page_limit, bool second_worker_image)
{
    ++fixture_count;
    memset(&f, 0, sizeof(f));
    f.injection.fault_cell = -1;
    assert(z_memory_init(&f.memory, Z_MANIFEST_POOL_PAGES));
    memset(f.memory.data, 0xcd, sizeof(f.memory.data));
    z_broker_init(&f.broker); z_wait_init(&f.waits);
    unsigned catalog_count = second_worker_image ? 7 : 6;
    const uint32_t roles[] = { Z_BLOCK, Z_FS, Z_CLIENT, Z_PROBE, Z_SUPERVISOR, Z_WORKER, Z_WORKER };
    for (unsigned i = 0; i < catalog_count; ++i) {
        memset(f.images[i], (int)(0x40 + i), sizeof(f.images[i]));
        f.catalog[i] = (struct z_image_catalog) { .identity = i + 1, .role = roles[i],
            .data = f.images[i], .length = sizeof(f.images[i]), .entry = Z_IMAGE_BASE };
    }
    struct z_manifest_cell cells[4];
    for (unsigned i = 0; i < 4; ++i) {
        cells[i] = (struct z_manifest_cell) { .identity = (i + 1) * 100, .image = i + 1,
            .abi = Z_ABI_VERSION, .flags = Z_MANIFEST_ACTIVE, .entry = Z_IMAGE_BASE,
            .image_budget = sizeof(f.images[i]), .stack_budget = 16384, .writable_budget = 81920,
            .boot_config = i == Z_PROBE ? 21 : 0, .restart_limit = 3, .restart_delay = 4,
            .name = { 'r', 'o', 'o', 't', (uint8_t)('0' + i), 0 } };
    }
    const struct z_manifest_grant grants[] = {
        { 200, 200, Z_RIGHT(Z_FILE_READ) | Z_RIGHT_DELEGATE, 0 },
        { 300, 200, Z_RIGHT(Z_FILE_READ) | Z_RIGHT(Z_FILE_WRITE), 0 },
        { 200, 100, Z_RIGHT(Z_BLOCK_READ) | Z_RIGHT(Z_BLOCK_WRITE), 0 },
        { 100, 200, Z_RIGHT(Z_BLOCK_REPLY), 0 },
    };
    const struct z_manifest_template templates[] = {
        { .identity = 1, .image = 5, .abi = Z_ABI_VERSION, .entry = Z_IMAGE_BASE,
          .image_budget = sizeof(f.images[4]), .stack_budget = supervisor_stack, .writable_budget = supervisor_writable,
          .boot_config = 21, .restart_limit = 3, .restart_delay = 4,
          .max_descendant_depth = 1, .child_template_mask = 2, .bootstrap_recipe = 1 },
        { .identity = 2, .image = 6, .abi = Z_ABI_VERSION, .entry = Z_IMAGE_BASE,
          .image_budget = sizeof(f.images[5]), .stack_budget = worker_stack, .writable_budget = worker_writable,
          .boot_config = 21, .restart_limit = 3, .restart_delay = 4, .bootstrap_recipe = 1 },
        { .identity = 3, .image = 7, .abi = Z_ABI_VERSION, .entry = Z_IMAGE_BASE,
          .image_budget = sizeof(f.images[6]), .stack_budget = worker_stack, .writable_budget = worker_writable,
          .boot_config = 21, .restart_limit = 3, .restart_delay = 4, .bootstrap_recipe = 1 },
    };
    const struct z_manifest_domain domains[] = {
        { .owner_identity = 400, .template_mask = second_worker_image ? 7 : 3, .slot_limit = slot_limit,
          .page_limit = page_limit, .max_depth = depth, .bootstrap_recipe = 1 },
    };
    uint8_t bytes[Z_MANIFEST_ARTIFACT_MAX] = {0};
    unsigned template_count = second_worker_image ? 3 : 2;
    size_t template_bytes = template_count * sizeof(*templates);
    size_t length = sizeof(struct z_manifest_header) + sizeof(cells) + sizeof(grants) + template_bytes + sizeof(domains);
    const struct z_manifest_header header = { .magic = Z_MANIFEST_MAGIC,
        .version = Z_MANIFEST_VERSION, .total_size = (uint32_t)length,
        .cell_count = 4, .grant_count = sizeof(grants) / sizeof(*grants),
        .template_count = template_count, .domain_count = 1 };
    size_t at = 0;
    memcpy(bytes + at, &header, sizeof(header)); at += sizeof(header);
    memcpy(bytes + at, cells, sizeof(cells)); at += sizeof(cells);
    memcpy(bytes + at, grants, sizeof(grants)); at += sizeof(grants);
    memcpy(bytes + at, templates, template_bytes); at += template_bytes;
    memcpy(bytes + at, domains, sizeof(domains)); at += sizeof(domains);
    assert(at == length);
    enum z_manifest_error error;
    assert(z_manifest_validate(bytes, length, f.catalog, catalog_count, &f.manifest, &error));
    struct z_boot_grant policy_grants[sizeof(grants) / sizeof(*grants)];
    for (unsigned i = 0; i < sizeof(grants) / sizeof(*grants); ++i)
        policy_grants[i] = (struct z_boot_grant) {
            .holder = (uint32_t)z_manifest_slot(&f.manifest, grants[i].holder),
            .target = (uint32_t)z_manifest_slot(&f.manifest, grants[i].target), .rights = grants[i].rights };
    assert(z_broker_configure(&f.broker, policy_grants, sizeof(policy_grants) / sizeof(*policy_grants)) == Z_OK);
    assert(z_broker_refresh(&f.broker) == Z_OK);
    for (unsigned i = 0; i < 4; ++i) {
        assert(space_init(&f, i, f.images[i], sizeof(f.images[i]), &f.manifest.cells[i]));
        assert(frame_init(&f, i, &f.frames[i]));
    }
    assert(z_runtime_init(&f.runtime, &f.broker, &f.waits, f.frames, &f.manifest,
                           f.catalog, catalog_count, &callbacks, &f) == Z_OK);
    assert(z_runtime_check(&f.runtime));
    assert(allocated_pages() == 80);
    assert(live_caps() == 4);
    assert(domain(Z_PROBE) != 0);
    for (unsigned i = 0; i < Z_PROBE; ++i) assert(domain(i) == 0);
}
static void fixture_config(uint32_t supervisor_stack, uint32_t supervisor_writable,
                            uint32_t worker_stack, uint32_t worker_writable,
                            unsigned depth, unsigned slot_limit, unsigned page_limit)
{
    fixture_catalog_config(supervisor_stack, supervisor_writable, worker_stack,
                            worker_writable, depth, slot_limit, page_limit, false);
}
static void fixture_init(void)
{
    fixture_config(8192, 16384, 4096, 8192, 2, 4, 48);
}
static void set_injection(enum injection_point point, bool fail, int fault_cell)
{
    f.injection = (struct injection) { .point = point, .fail = fail, .fault_cell = fault_cell };
}
static void assert_no_dynamic_charge(void)
{
    assert(z_runtime_check(&f.runtime));
    assert(allocated_pages() == 80);
    for (unsigned cell = Z_ROOT_COUNT; cell < Z_CELL_COUNT; ++cell) {
        assert(f.runtime.records[cell].origin == Z_RUNTIME_FREE);
        assert(f.broker.policies[cell].phase == Z_POLICY_DORMANT);
        assert(f.memory.cells[cell].count == 0);
        assert(f.waits.entries[cell].kind == Z_WAIT_NONE);
        assert(f.broker.queues[cell].count == 0);
    }
    const struct z_host_domain *root = &f.runtime.hierarchy.domains[Z_PROBE];
    assert(root->owned_slots == 0 && root->owned_pages == 0 && root->reserved_slots == 0 && root->reserved_pages == 0);
    assert(live_caps() == 4);
}

static void real_creation_identity_backing_channels_and_denied_storage(void)
{
    fixture_init();
    uint64_t authority = domain(Z_PROBE);
    struct z_create_result parent = create(Z_PROBE, authority, 1, 1, 8);
    struct z_create_result child = create(parent.slot, parent.creation, 2, 0, 0);
    struct z_create_result sibling = create(Z_PROBE, authority, 2, 0, 0);
    assert(parent.slot == 4 && child.slot == 5 && sibling.slot == 6);
    assert(child.identity != sibling.identity && child.instance != sibling.instance);
    assert(child.control != sibling.control && child.endpoint != sibling.endpoint);
    assert(f.runtime.records[child.slot].config.image == f.runtime.records[sibling.slot].config.image);
    assert(f.runtime.records[child.slot].depth == 2 && f.runtime.records[sibling.slot].depth == 1);
    assert(allocated_pages() == 88 && live_caps() == 10);
    struct z_domain_status root = ledger(Z_PROBE, authority);
    assert(root.owned_slots == 2 && root.owned_pages == 6 && root.reserved_slots == 1 && root.reserved_pages == 8);
    struct z_domain_status nested = ledger(parent.slot, parent.creation);
    assert(nested.owned_slots == 1 && nested.owned_pages == 2 && nested.available_slots == 0 && nested.available_pages == 6);
    uint64_t sentinels[] = { UINT64_C(0x5531aef9807dcb42), UINT64_C(0xafe376019d882c54), UINT64_C(0x719cee55200ab863) };
    const unsigned cells[] = { parent.slot, child.slot, sibling.slot };
    for (unsigned i = 0; i < 3; ++i) store(cells[i], Z_HEAP_BASE, &sentinels[i], sizeof(sentinels[i]));
    for (unsigned i = 0; i < 3; ++i) {
        uint64_t observed = 0; load(cells[i], Z_HEAP_BASE, &observed, sizeof(observed)); assert(observed == sentinels[i]);
        assert(z_broker_find(&f.broker, cells[i], endpoint(Z_FS), Z_RIGHT(Z_FILE_READ)) == Z_DENIED);
        assert(z_broker_find(&f.broker, cells[i], endpoint(Z_BLOCK), Z_RIGHT(Z_BLOCK_READ)) == Z_DENIED);
    }
    for (unsigned i = 0; i < 3; ++i)
        for (unsigned j = i + 1; j < 3; ++j)
            for (unsigned a = 0; a < f.memory.cells[cells[i]].count; ++a)
                for (unsigned b = 0; b < f.memory.cells[cells[j]].count; ++b)
                    assert(f.memory.cells[cells[i]].pages[a] != f.memory.cells[cells[j]].pages[b]);
    assert(send(Z_PROBE, parent.endpoint, parent.channel, Z_HOST_REQUEST, 17) == Z_OK);
    struct z_message delivered;
    assert(z_broker_receive(&f.broker, parent.slot, &delivered) == Z_OK);
    assert(delivered.sender == endpoint(Z_PROBE));
    assert(send(parent.slot, endpoint(Z_PROBE), f.runtime.records[parent.slot].parent_channel, Z_HOST_REPLY, 18) == Z_OK);
    assert(z_broker_receive(&f.broker, Z_PROBE, &delivered) == Z_OK && delivered.sender == parent.endpoint);
    assert(send(parent.slot, child.endpoint, child.channel, Z_HOST_REQUEST, 23) == Z_OK);
    assert(z_broker_receive(&f.broker, child.slot, &delivered) == Z_OK && delivered.sender == parent.endpoint);
    assert(send(child.slot, parent.endpoint, f.runtime.records[child.slot].parent_channel, Z_HOST_REPLY, 24) == Z_OK);
    assert(z_broker_receive(&f.broker, parent.slot, &delivered) == Z_OK && delivered.sender == child.endpoint);
    assert(send(child.slot, parent.endpoint, parent.channel, Z_HOST_REQUEST, 25) == Z_DENIED);
    assert(send(child.slot, sibling.endpoint, sibling.channel, Z_HOST_REQUEST, 26) == Z_DENIED);
    assert(z_runtime_stop(&f.runtime, child.slot, parent.control) == Z_DENIED);
    assert(z_runtime_stop(&f.runtime, parent.slot, sibling.control) == Z_DENIED);
    assert(z_runtime_status(&f.runtime, Z_PROBE, parent.endpoint, status_address, sizeof(struct z_cell_status)) == Z_INVALID);
    assert(z_broker_query(&f.broker, Z_PROBE, parent.control, &(struct z_cap_info){0}) == Z_INVALID);
    assert(z_policy_resolve(f.broker.policies, Z_CELL_COUNT, parent.control) == Z_POLICY_INVALID);
    assert(z_runtime_check(&f.runtime));
}
static void ordinary_failures_roll_back_every_reserved_resource(void)
{
    const enum injection_point points[] = { INJECT_INPUT_RANGE, INJECT_OUTPUT_RANGE, INJECT_COPY_IN,
        INJECT_SPACE_BEFORE, INJECT_SPACE_PARTIAL, INJECT_SPACE_AFTER,
        INJECT_MEMORY_CHECK, INJECT_FRAME, INJECT_COPY_OUT };
    for (unsigned i = 0; i < sizeof(points) / sizeof(*points); ++i) {
        fixture_init();
        struct z_create_request request = creation(Z_PROBE, domain(Z_PROBE), 1, 2, 8);
        set_injection(points[i], true, -1);
        int result = create_request(Z_PROBE, &request, input_address, sizeof(request), output_address);
        assert(result != Z_OK && f.injection.consumed);
        assert(f.publication_count == 0);
        assert_no_dynamic_charge();
        assert(f.runtime.hierarchy.history[4] == 0);
        assert(f.broker.policies[4].generation == 0);
        set_injection(INJECT_NONE, false, -1);
        struct z_create_result replacement = create(Z_PROBE, domain(Z_PROBE), 2, 0, 0);
        assert(replacement.endpoint == (UINT64_C(1) << 8 | 5));
    }
}
static void parent_retirement_at_all_creation_boundaries(void)
{
    const enum injection_point points[] = { INJECT_INPUT_RANGE, INJECT_OUTPUT_RANGE, INJECT_COPY_IN,
        INJECT_SPACE_BEFORE, INJECT_SPACE_PARTIAL, INJECT_SPACE_AFTER,
        INJECT_MEMORY_CHECK, INJECT_FRAME, INJECT_COPY_OUT };
    for (unsigned i = 0; i < sizeof(points) / sizeof(*points); ++i)
        for (unsigned fail = 0; fail < 2; ++fail) {
            fixture_init();
            struct z_create_request request = creation(Z_PROBE, domain(Z_PROBE), 1, 1, 8);
            set_injection(points[i], fail, Z_PROBE);
            int result = create_request(Z_PROBE, &request, input_address, sizeof(request), output_address);
            assert(result != Z_OK && f.injection.consumed);
            assert(f.publication_count == 0);
            assert(z_runtime_check(&f.runtime));
            assert(allocated_pages() == 80);
            assert(f.broker.policies[Z_PROBE].phase == Z_POLICY_BACKOFF);
            for (unsigned child = Z_ROOT_COUNT; child < Z_CELL_COUNT; ++child) {
                assert(f.runtime.records[child].origin == Z_RUNTIME_FREE);
                assert(f.broker.policies[child].phase == Z_POLICY_DORMANT);
            }
            assert(f.runtime.hierarchy.domains[Z_PROBE].owned_slots == 0);
            set_injection(INJECT_NONE, false, -1);
            assert(z_runtime_poll(&f.runtime, Z_PROBE, 4) == 1);
            assert(z_runtime_check(&f.runtime));
        }
}
static void checked_ranges_exact_lengths_reserved_fields_and_overflow(void)
{
    fixture_init();
    struct z_create_request request = creation(Z_PROBE, domain(Z_PROBE), 2, 0, 0);
    const uint64_t bad_outputs[] = { Z_IMAGE_BASE, Z_IMAGE_BASE + 128, Z_STACK_BASE + 16384 - 47,
        Z_STACK_BASE - 1, Z_HEAP_BASE + 65536 - 47, UINT64_MAX - 31,
        UINT64_C(0x800000000000), 0 };
    for (unsigned i = 0; i < sizeof(bad_outputs) / sizeof(*bad_outputs); ++i) {
        assert(create_request(Z_PROBE, &request, input_address, sizeof(request), bad_outputs[i]) == Z_BAD_ADDRESS);
        assert_no_dynamic_charge();
    }
    uint8_t padding[32];
    assert(z_memory_copy_in(&f.memory, Z_PROBE, &f.layouts[Z_PROBE], padding, Z_IMAGE_BASE + 128, sizeof(padding)));
    for (unsigned i = 0; i < sizeof(padding); ++i) assert(padding[i] == 0);
    assert(!z_memory_copy_in(&f.memory, Z_PROBE, &f.layouts[Z_PROBE], padding,
                              Z_IMAGE_BASE + Z_MANIFEST_PAGE_SIZE - 31, sizeof(padding)));
    const uint64_t bad_inputs[] = { Z_STACK_BASE - 1, Z_STACK_BASE + 16384 - 31,
        Z_HEAP_BASE + 65536 - 31, UINT64_MAX - 15, 0 };
    for (unsigned i = 0; i < sizeof(bad_inputs) / sizeof(*bad_inputs); ++i) {
        assert(create_request(Z_PROBE, &request, bad_inputs[i], sizeof(request), output_address) == Z_BAD_ADDRESS);
        assert_no_dynamic_charge();
    }
    const size_t lengths[] = { 0, 1, 31, 33, SIZE_MAX };
    for (unsigned i = 0; i < sizeof(lengths) / sizeof(*lengths); ++i) {
        assert(create_request(Z_PROBE, &request, input_address, lengths[i], output_address) == Z_INVALID);
        assert_no_dynamic_charge();
    }
    struct z_create_request bad[] = {
        { .authority = request.authority, .request = 1, .template_id = 0 },
        { .authority = request.authority, .request = 1, .template_id = 9 },
        { .authority = request.authority, .request = 1, .template_id = 2, .reserved = 1 },
        { .authority = request.authority, .request = 1, .template_id = 2, .descendant_slots = UINT32_MAX },
        { .authority = request.authority, .request = 1, .template_id = 1, .descendant_pages = UINT32_MAX },
        { .authority = request.authority, .request = 0, .template_id = 2 },
    };
    for (unsigned i = 0; i < sizeof(bad) / sizeof(*bad); ++i) {
        assert(create_request(Z_PROBE, &bad[i], input_address, sizeof(bad[i]), output_address) != Z_OK);
        assert_no_dynamic_charge();
    }
    assert(z_runtime_status(&f.runtime, Z_PROBE, 0, status_address, sizeof(struct z_cell_status) - 1) == Z_INVALID);
    assert(z_runtime_domain_status(&f.runtime, Z_PROBE, request.authority, Z_IMAGE_BASE, sizeof(struct z_domain_status)) == Z_BAD_ADDRESS);
    assert_no_dynamic_charge();
}

static void subtree_recovery_wait_queue_memory_and_sibling_preservation(void)
{
    fixture_init();
    uint64_t authority = domain(Z_PROBE);
    struct z_create_result parent = create(Z_PROBE, authority, 1, 2, 8);
    struct z_create_result child = create(parent.slot, parent.creation, 2, 0, 0);
    struct z_create_result sibling = create(Z_PROBE, authority, 2, 0, 0);
    uint64_t sibling_sentinel = UINT64_C(0x69a2d184ec0fb375);
    uint64_t manager_sentinel = UINT64_C(0xf9ce72006584da13);
    uint64_t storage_sentinel = UINT64_C(0xa22c3117e53d9010);
    store(sibling.slot, Z_HEAP_BASE, &sibling_sentinel, sizeof(sibling_sentinel));
    store(parent.slot, Z_HEAP_BASE, &manager_sentinel, sizeof(manager_sentinel));
    store(Z_CLIENT, Z_HEAP_BASE, &storage_sentinel, sizeof(storage_sentinel));
    uint16_t retired_pages[Z_MANIFEST_PAGES_PER_CELL];
    unsigned retired_count = f.memory.cells[child.slot].count;
    memcpy(retired_pages, f.memory.cells[child.slot].pages, sizeof(retired_pages));
    assert(z_wait_sleep(&f.waits, &f.broker, sibling.slot, 0, 30) == Z_OK);
    assert(z_wait_sleep(&f.waits, &f.broker, child.slot, 0, 20) == Z_OK);
    assert(send(parent.slot, child.endpoint, child.channel, Z_HOST_REQUEST, 11) == Z_OK);
    assert(send(Z_PROBE, sibling.endpoint, sibling.channel, Z_HOST_REQUEST, 17) == Z_OK);
    assert(send(Z_PROBE, sibling.endpoint, sibling.channel, Z_HOST_REQUEST, 23) == Z_OK);
    assert(send(sibling.slot, endpoint(Z_PROBE), f.runtime.records[sibling.slot].parent_channel, Z_HOST_REPLY, 71) == Z_OK);
    assert(send(parent.slot, endpoint(Z_PROBE), f.runtime.records[parent.slot].parent_channel, Z_HOST_REPLY, 91) == Z_OK);
    int64_t storage_cap = z_broker_find(&f.broker, Z_CLIENT, endpoint(Z_FS), Z_RIGHT(Z_FILE_WRITE));
    assert(storage_cap > 0);
    assert(send(Z_CLIENT, endpoint(Z_FS), (uint64_t)storage_cap, Z_FILE_WRITE, UINT64_C(0xfeed0123)) == Z_OK);
    const struct z_wait_entry sibling_wait = f.waits.entries[sibling.slot];
    const struct z_queue sibling_queue = f.broker.queues[sibling.slot];
    const struct z_queue storage_queue = f.broker.queues[Z_FS];
    assert(z_runtime_fault(&f.runtime, parent.slot, 10, 14) == Z_OK);
    assert(f.runtime.records[child.slot].origin == Z_RUNTIME_FREE);
    assert(f.waits.entries[child.slot].kind == Z_WAIT_NONE);
    assert(f.broker.queues[child.slot].count == 0);
    assert(f.memory.cells[child.slot].count == 0);
    for (unsigned p = 0; p < retired_count; ++p) {
        assert(f.memory.owners[retired_pages[p]] == 0);
        for (unsigned i = 0; i < Z_MANIFEST_PAGE_SIZE; ++i) assert(f.memory.data[retired_pages[p]][i] == 0);
    }
    assert(memcmp(&f.waits.entries[sibling.slot], &sibling_wait, sizeof(sibling_wait)) == 0);
    assert(memcmp(&f.broker.queues[sibling.slot], &sibling_queue, sizeof(sibling_queue)) == 0);
    assert(memcmp(&f.broker.queues[Z_FS], &storage_queue, sizeof(storage_queue)) == 0);
    assert(endpoint(sibling.slot) == sibling.endpoint);
    assert(z_caps_check(&f.broker.capabilities, f.broker.policies, endpoint(Z_PROBE), sibling.channel,
                          sibling.endpoint, Z_RIGHT(Z_HOST_REQUEST)) == Z_OK);
    uint64_t observed = 0;
    load(sibling.slot, Z_HEAP_BASE, &observed, sizeof(observed)); assert(observed == sibling_sentinel);
    load(Z_CLIENT, Z_HEAP_BASE, &observed, sizeof(observed)); assert(observed == storage_sentinel);
    struct z_cell_status before_restart = status(Z_PROBE, parent.control);
    assert(before_restart.phase == Z_POLICY_BACKOFF && before_restart.generation == 1);
    assert(before_restart.own_pages == 4 && before_restart.reserved_pages == 8 && before_restart.domain == 0);
    struct z_domain_status root = ledger(Z_PROBE, authority);
    assert(root.owned_slots == 2 && root.owned_pages == 6 && root.reserved_slots == 2 && root.reserved_pages == 8);
    assert(z_wait_next(&f.waits, &f.broker, Z_PROBE) == Z_BLOCK);
    assert(z_runtime_check(&f.runtime));
    assert(z_runtime_poll(&f.runtime, parent.slot, 13) == 0);
    assert(z_runtime_poll(&f.runtime, parent.slot, 14) == 1);
    load(parent.slot, Z_HEAP_BASE, &observed, sizeof(observed)); assert(observed == 0);
    struct z_cell_status after_restart = status(Z_PROBE, parent.control);
    assert(after_restart.instance == parent.instance && after_restart.generation == 2);
    assert(after_restart.phase == Z_POLICY_READY && after_restart.domain == 0);
    assert(send(Z_PROBE, parent.endpoint, parent.channel, Z_HOST_REQUEST, 33) == Z_STALE);
    assert(z_broker_query(&f.broker, Z_PROBE, parent.channel, &(struct z_cap_info){0}) == Z_STALE);
    struct z_create_result rebound;
    assert(rebind(Z_PROBE, authority, parent.control, &rebound) == Z_OK);
    assert(rebound.instance == parent.instance && rebound.control == parent.control);
    assert(rebound.endpoint != parent.endpoint && rebound.creation != parent.creation);
    assert(rebound.channel != parent.channel);
    struct z_boot_info boot;
    assert(z_runtime_boot(&f.runtime, parent.slot, &boot) == Z_OK);
    assert(boot.creation == rebound.creation && boot.parent_channel != 0 && boot.parent_endpoint == endpoint(Z_PROBE));
    f.sequence[parent.slot] = 0; // A cold restarted execution starts its own request namespace.
    struct z_create_result replacement = create(parent.slot, rebound.creation, 2, 0, 0);
    assert(replacement.slot == child.slot && replacement.endpoint >> 8 == 2);
    assert(z_runtime_status(&f.runtime, parent.slot, child.control, status_address, sizeof(struct z_cell_status)) == Z_STALE);
    int wake_result = 0; enum z_wake_reason wake_reason = Z_WAKE_NONE;
    assert(z_wait_poll(&f.waits, &f.broker, sibling.slot, 29, receive_copy, &f, &wake_result, &wake_reason) == Z_WAIT_PENDING);
    assert(z_wait_poll(&f.waits, &f.broker, sibling.slot, 30, receive_copy, &f, &wake_result, &wake_reason) == Z_WAIT_DONE);
    assert(wake_result == Z_OK && wake_reason == Z_WAKE_SLEEP);
    struct z_message message;
    assert(z_broker_receive(&f.broker, sibling.slot, &message) == Z_OK);
    memcpy(&observed, message.payload, sizeof(observed)); assert(observed == 17 && message.sender == endpoint(Z_PROBE));
    assert(z_broker_receive(&f.broker, sibling.slot, &message) == Z_OK);
    memcpy(&observed, message.payload, sizeof(observed)); assert(observed == 23 && message.sender == endpoint(Z_PROBE));
    assert(z_broker_receive(&f.broker, sibling.slot, &message) == Z_AGAIN);
    assert(z_broker_receive(&f.broker, Z_PROBE, &message) == Z_OK && message.sender == sibling.endpoint);
    memcpy(&observed, message.payload, sizeof(observed)); assert(observed == 71);
    assert(z_broker_receive(&f.broker, Z_PROBE, &message) == Z_AGAIN);
    assert(z_broker_receive(&f.broker, Z_FS, &message) == Z_OK && message.sender == endpoint(Z_CLIENT));
    memcpy(&observed, message.payload, sizeof(observed)); assert(observed == UINT64_C(0xfeed0123));
    assert(z_runtime_fault(&f.runtime, replacement.slot, 40, 14) == Z_OK);
    assert(f.broker.policies[replacement.slot].deadline == 44);
    assert(z_wait_sleep(&f.waits, &f.broker, sibling.slot, 40, 15) == Z_OK);
    const struct z_wait_entry preserved = f.waits.entries[sibling.slot];
    assert(z_runtime_stop(&f.runtime, Z_PROBE, parent.control) == Z_OK);
    assert(z_runtime_stop(&f.runtime, Z_PROBE, parent.control) == Z_OK);
    assert(memcmp(&f.waits.entries[sibling.slot], &preserved, sizeof(preserved)) == 0);
    assert(z_runtime_poll(&f.runtime, replacement.slot, 1000) == 0);
    assert(z_runtime_poll(&f.runtime, parent.slot, 1000) == 0);
    assert(status(Z_PROBE, parent.control).own_pages == 0);
    assert(z_runtime_reap(&f.runtime, Z_PROBE, parent.control) == Z_OK);
    assert(z_runtime_reap(&f.runtime, Z_PROBE, parent.control) == Z_STALE);
    struct z_create_result reused = create(Z_PROBE, authority, 2, 0, 0);
    assert(reused.slot == parent.slot && reused.endpoint >> 8 == 3);
    assert(reused.instance != parent.instance && reused.control != parent.control);
    load(reused.slot, Z_HEAP_BASE, &observed, sizeof(observed)); assert(observed == 0);
    assert(send(Z_PROBE, rebound.endpoint, rebound.channel, Z_HOST_REQUEST, 34) == Z_STALE);
    assert(z_runtime_status(&f.runtime, Z_PROBE, parent.control, status_address, sizeof(struct z_cell_status)) == Z_STALE);
    assert(z_runtime_stop(&f.runtime, Z_PROBE, reused.control) == Z_OK);
    assert(z_runtime_reap(&f.runtime, Z_PROBE, reused.control) == Z_OK);
    assert(z_runtime_stop(&f.runtime, Z_PROBE, sibling.control) == Z_OK);
    assert(z_runtime_reap(&f.runtime, Z_PROBE, sibling.control) == Z_OK);
    assert_no_dynamic_charge();
}

static void rebind_failure_atomicity_request_retirement_and_unrelated_faults(void)
{
    fixture_init();
    uint64_t authority = domain(Z_PROBE);
    struct z_create_result parent = create(Z_PROBE, authority, 1, 2, 8);
    uint64_t old_creation = parent.creation, old_channel = parent.channel;
    uint64_t epoch_before = f.runtime.hierarchy.next_epoch;
    set_injection(INJECT_COPY_OUT, true, -1);
    assert(rebind(Z_PROBE, authority, parent.control, NULL) == Z_BAD_ADDRESS);
    assert(f.injection.consumed);
    assert(f.runtime.hierarchy.next_epoch > epoch_before);
    assert(f.runtime.records[parent.slot].creation == old_creation);
    assert(status(Z_PROBE, parent.control).domain == old_creation);
    assert(live_caps() == 6 && allocated_pages() == 84);
    assert(send(Z_PROBE, parent.endpoint, old_channel, Z_HOST_REQUEST, 17) == Z_OK);
    struct z_message ignored; assert(z_broker_receive(&f.broker, parent.slot, &ignored) == Z_OK);
    assert(z_runtime_check(&f.runtime));
    struct z_rebind_request replay = { .authority = authority, .control = parent.control, .request = f.sequence[Z_PROBE] };
    store(Z_PROBE, input_address, &replay, sizeof(replay));
    assert(z_runtime_rebind(&f.runtime, Z_PROBE, input_address, sizeof(replay), output_address) == Z_STALE);
    set_injection(INJECT_NONE, false, -1);
    struct z_create_result rebound;
    assert(rebind(Z_PROBE, authority, parent.control, &rebound) == Z_OK);
    assert(rebound.creation != old_creation && rebound.channel != old_channel);
    assert(z_broker_query(&f.broker, Z_PROBE, old_channel, &(struct z_cap_info){0}) == Z_STALE);
    assert(live_caps() == 6);
    assert(z_runtime_check(&f.runtime));
    for (unsigned fail = 0; fail < 2; ++fail)
        for (unsigned victim = 0; victim < 3; ++victim) {
            fixture_init(); authority = domain(Z_PROBE);
            parent = create(Z_PROBE, authority, 1, 1, 8);
            int fault_cell = victim == 0 ? Z_PROBE : victim == 1 ? (int)parent.slot : Z_FS;
            set_injection(INJECT_COPY_OUT, fail, fault_cell);
            int result = rebind(Z_PROBE, authority, parent.control, NULL);
            assert(f.injection.consumed);
            if (victim == 2 && !fail) assert(result == Z_OK);
            else assert(result != Z_OK);
            assert(z_runtime_check(&f.runtime));
            assert(f.broker.policies[fault_cell].phase == Z_POLICY_BACKOFF);
            if (victim == 0) {
                assert(f.runtime.records[parent.slot].origin == Z_RUNTIME_FREE);
                assert(f.runtime.hierarchy.domains[Z_PROBE].owned_slots == 0);
                assert(allocated_pages() == 80);
            } else {
                assert(f.runtime.records[parent.slot].origin == Z_RUNTIME_CHILD);
                assert(allocated_pages() == 84);
                if (victim == 1) {
                    assert(f.runtime.records[parent.slot].creation == 0);
                    assert(f.runtime.records[parent.slot].parent_channel == 0);
                } else {
                    assert(f.runtime.hierarchy.history[Z_FS] == 1);
                    assert(f.broker.policies[Z_FS].faults == 1);
                }
            }
        }
}

static void private_budget_rounding_exact_last_global_page_and_maximum(void)
{
    const uint32_t budgets[][3] = {
        { 4096, 4096, 1 }, { 4097, 8194, 4 }, { 8192, 16384, 4 }, { 16384, 81920, 20 },
    };
    for (unsigned i = 0; i < sizeof(budgets) / sizeof(*budgets); ++i) {
        fixture_config(8192, 16384, budgets[i][0], budgets[i][1], 2, 4, 48);
        struct z_create_result worker = create(Z_PROBE, domain(Z_PROBE), 2, 0, 0);
        assert(f.memory.cells[worker.slot].count == budgets[i][2]);
        assert(status(Z_PROBE, worker.control).own_pages == budgets[i][2]);
        assert(ledger(Z_PROBE, domain(Z_PROBE)).owned_pages == budgets[i][2]);
        assert(z_runtime_stop(&f.runtime, Z_PROBE, worker.control) == Z_OK);
        assert(z_runtime_reap(&f.runtime, Z_PROBE, worker.control) == Z_OK);
        assert_no_dynamic_charge();
    }
    fixture_config(8192, 16384, 4096, 4096, 2, 4, 1);
    f.memory.page_count = 81;
    struct z_create_result last = create(Z_PROBE, domain(Z_PROBE), 2, 0, 0);
    assert(allocated_pages() == 81);
    assert(ledger(Z_PROBE, domain(Z_PROBE)).available_pages == 0);
    struct z_create_request request = creation(Z_PROBE, domain(Z_PROBE), 2, 0, 0);
    assert(create_request(Z_PROBE, &request, input_address, sizeof(request), output_address) == Z_NO_SPACE);
    assert(allocated_pages() == 81 && f.publication_count == 1);
    assert(z_runtime_stop(&f.runtime, Z_PROBE, last.control) == Z_OK);
    assert(z_runtime_reap(&f.runtime, Z_PROBE, last.control) == Z_OK);
    assert_no_dynamic_charge();
    fixture_init(); f.memory.page_count = 80;
    request = creation(Z_PROBE, domain(Z_PROBE), 2, 0, 0);
    assert(create_request(Z_PROBE, &request, input_address, sizeof(request), output_address) == Z_NO_SPACE);
    assert_no_dynamic_charge();
    fixture_config(8192, 16384, 4096, 49152, 2, 4, 48);
    struct z_create_result workers[4];
    for (unsigned i = 0; i < 4; ++i) workers[i] = create(Z_PROBE, domain(Z_PROBE), 2, 0, 0);
    assert(allocated_pages() == 128);
    assert(ledger(Z_PROBE, domain(Z_PROBE)).available_pages == 0);
    assert(z_runtime_check(&f.runtime));
    for (unsigned i = 0; i < 4; ++i) {
        assert(z_runtime_stop(&f.runtime, Z_PROBE, workers[i].control) == Z_OK);
        assert(z_runtime_reap(&f.runtime, Z_PROBE, workers[i].control) == Z_OK);
    }
    assert_no_dynamic_charge();
}

static void pressure_retained_controls_capabilities_and_counters(void)
{
    fixture_init();
    struct z_create_result workers[4];
    for (unsigned i = 0; i < 4; ++i) {
        workers[i] = create(Z_PROBE, domain(Z_PROBE), 2, 0, 0);
        assert(z_runtime_stop(&f.runtime, Z_PROBE, workers[i].control) == Z_OK);
    }
    assert(allocated_pages() == 80);
    struct z_domain_status root = ledger(Z_PROBE, domain(Z_PROBE));
    assert(root.owned_slots == 4 && root.available_slots == 0 && root.owned_pages == 0 && root.available_pages == 48);
    struct z_create_request request = creation(Z_PROBE, domain(Z_PROBE), 2, 0, 0);
    unsigned published = f.publication_count;
    assert(create_request(Z_PROBE, &request, input_address, sizeof(request), output_address) == Z_NO_SPACE);
    assert(f.publication_count == published);
    for (unsigned i = 0; i < 4; ++i) assert(z_runtime_reap(&f.runtime, Z_PROBE, workers[i].control) == Z_OK);
    assert_no_dynamic_charge();
    fixture_init();
    uint64_t delegates[Z_CAPACITY]; unsigned count = 0;
    int64_t parent = z_broker_find(&f.broker, Z_FS, endpoint(Z_FS), Z_RIGHT(Z_FILE_READ) | Z_RIGHT_DELEGATE);
    assert(parent > 0);
    while (live_caps() < Z_CAPACITY - 1) {
        int64_t delegated = z_broker_delegate(&f.broker, Z_FS, (uint64_t)parent, endpoint(Z_FS), Z_RIGHT(Z_FILE_READ));
        assert(delegated > 0); delegates[count++] = (uint64_t)delegated;
    }
    unsigned caps_before = live_caps();
    request = creation(Z_PROBE, domain(Z_PROBE), 1, 1, 8);
    assert(create_request(Z_PROBE, &request, input_address, sizeof(request), output_address) == Z_NO_SPACE);
    assert(f.publication_count == 0 && allocated_pages() == 80 && live_caps() == caps_before);
    assert(z_runtime_check(&f.runtime));
    assert(z_broker_revoke_cap(&f.broker, Z_FS, delegates[--count]) == Z_OK);
    struct z_create_result manager = create(Z_PROBE, domain(Z_PROBE), 1, 1, 8);
    assert(live_caps() == Z_CAPACITY);
    assert(z_runtime_stop(&f.runtime, Z_PROBE, manager.control) == Z_OK);
    assert(z_runtime_reap(&f.runtime, Z_PROBE, manager.control) == Z_OK);
    for (unsigned i = 0; i < count; ++i)
        assert(z_caps_check(&f.broker.capabilities, f.broker.policies, endpoint(Z_FS), delegates[i], endpoint(Z_FS), Z_RIGHT(Z_FILE_READ)) == Z_OK);
    assert(allocated_pages() == 80 && z_runtime_check(&f.runtime));
    fixture_init(); f.broker.capabilities.next_epoch = (uint64_t)Z_POLICY_GENERATION_MAX;
    request = creation(Z_PROBE, domain(Z_PROBE), 2, 0, 0);
    assert(create_request(Z_PROBE, &request, input_address, sizeof(request), output_address) == Z_NO_SPACE);
    assert_no_dynamic_charge();
    fixture_init(); f.runtime.hierarchy.next_epoch = (uint64_t)Z_POLICY_GENERATION_MAX - 1;
    request = creation(Z_PROBE, domain(Z_PROBE), 2, 0, 0);
    assert(create_request(Z_PROBE, &request, input_address, sizeof(request), output_address) == Z_NO_SPACE);
    assert_no_dynamic_charge();
    fixture_init();
    assert(z_runtime_fault(&f.runtime, Z_PROBE, 0, 14) == Z_OK);
    f.runtime.hierarchy.next_epoch = (uint64_t)Z_POLICY_GENERATION_MAX + 1;
    assert(z_runtime_poll(&f.runtime, Z_PROBE, 4) == 1);
    assert(endpoint(Z_PROBE) >> 8 == 2 && domain(Z_PROBE) == 0);
    assert(f.runtime.records[Z_PROBE].published && f.frames[Z_PROBE].cs == 0x1b);
    assert_no_dynamic_charge();
    fixture_init(); f.runtime.next_identity = UINT32_MAX;
    request = creation(Z_PROBE, domain(Z_PROBE), 2, 0, 0);
    assert(create_request(Z_PROBE, &request, input_address, sizeof(request), output_address) == Z_NO_SPACE);
    assert_no_dynamic_charge();
    fixture_init();
    for (unsigned cell = Z_ROOT_COUNT; cell < Z_CELL_COUNT; ++cell) {
        f.runtime.hierarchy.history[cell] = (uint64_t)Z_POLICY_GENERATION_MAX;
        f.broker.policies[cell].generation = (uint64_t)Z_POLICY_GENERATION_MAX;
    }
    request = creation(Z_PROBE, domain(Z_PROBE), 2, 0, 0);
    assert(create_request(Z_PROBE, &request, input_address, sizeof(request), output_address) == Z_NO_SPACE);
    assert_no_dynamic_charge();
    fixture_init();
    request = (struct z_create_request) { .authority = domain(Z_PROBE), .request = UINT64_MAX, .template_id = 2 };
    assert(create_request(Z_PROBE, &request, input_address, sizeof(request), output_address) == Z_OK);
    struct z_create_result created; load(Z_PROBE, output_address, &created, sizeof(created));
    request.request = 1;
    assert(create_request(Z_PROBE, &request, input_address, sizeof(request), output_address) == Z_STALE);
    assert(z_runtime_stop(&f.runtime, Z_PROBE, created.control) == Z_OK);
    assert(z_runtime_reap(&f.runtime, Z_PROBE, created.control) == Z_OK);
    assert_no_dynamic_charge();
    // Valid supervisor domain, permitted worker image, exhausted absolute
    // depth. This denial is independent of leaf capability absence or quota.
    fixture_config(8192, 16384, 4096, 8192, 1, 4, 48);
    manager = create(Z_PROBE, domain(Z_PROBE), 1, 0, 0);
    assert(manager.creation != 0);
    request = creation(manager.slot, manager.creation, 2, 0, 0);
    assert(create_request(manager.slot, &request, input_address, sizeof(request), output_address) == Z_DENIED);
    assert(z_runtime_stop(&f.runtime, Z_PROBE, manager.control) == Z_OK);
    assert(z_runtime_reap(&f.runtime, Z_PROBE, manager.control) == Z_OK);
    assert_no_dynamic_charge();
}

static void restart_failures_and_owner_retirement_never_republish(void)
{
    const enum injection_point points[] = { INJECT_RESET_BEFORE, INJECT_RESET_AFTER, INJECT_FRAME };
    for (unsigned i = 0; i < sizeof(points) / sizeof(*points); ++i) {
        fixture_init();
        struct z_create_result parent = create(Z_PROBE, domain(Z_PROBE), 1, 1, 8);
        struct z_create_result sibling = create(Z_PROBE, domain(Z_PROBE), 2, 0, 0);
        uint64_t sentinel = UINT64_C(0xa8e03417cc905f26);
        store(sibling.slot, Z_HEAP_BASE, &sentinel, sizeof(sentinel));
        assert(z_wait_sleep(&f.waits, &f.broker, sibling.slot, 0, 30) == Z_OK);
        assert(send(Z_PROBE, sibling.endpoint, sibling.channel, Z_HOST_REQUEST, 17) == Z_OK);
        assert(send(Z_PROBE, sibling.endpoint, sibling.channel, Z_HOST_REQUEST, 23) == Z_OK);
        int64_t storage_cap = z_broker_find(&f.broker, Z_CLIENT, endpoint(Z_FS), Z_RIGHT(Z_FILE_WRITE));
        assert(storage_cap > 0 && send(Z_CLIENT, endpoint(Z_FS), (uint64_t)storage_cap, Z_FILE_WRITE, 71) == Z_OK);
        struct z_wait_entry sibling_wait = f.waits.entries[sibling.slot];
        struct z_queue sibling_queue = f.broker.queues[sibling.slot], storage_queue = f.broker.queues[Z_FS];
        assert(z_runtime_fault(&f.runtime, parent.slot, 0, 14) == Z_OK);
        set_injection(points[i], true, -1);
        assert(z_runtime_poll(&f.runtime, parent.slot, 4) == Z_NO_SPACE);
        assert(f.injection.consumed && z_runtime_check(&f.runtime));
        struct z_cell_status stopped = status(Z_PROBE, parent.control);
        assert(stopped.phase == Z_POLICY_STOPPED && stopped.own_pages == 0 && stopped.reserved_pages == 0);
        assert(stopped.reason == Z_TERMINATION_INITIALIZATION && stopped.generation == 2 && stopped.endpoint == 0);
        assert(memcmp(&f.waits.entries[sibling.slot], &sibling_wait, sizeof(sibling_wait)) == 0);
        assert(memcmp(&f.broker.queues[sibling.slot], &sibling_queue, sizeof(sibling_queue)) == 0);
        assert(memcmp(&f.broker.queues[Z_FS], &storage_queue, sizeof(storage_queue)) == 0);
        uint64_t observed; load(sibling.slot, Z_HEAP_BASE, &observed, sizeof(observed)); assert(observed == sentinel);
        assert(endpoint(sibling.slot) == sibling.endpoint);
        assert(z_caps_check(&f.broker.capabilities, f.broker.policies, endpoint(Z_PROBE), sibling.channel,
                            sibling.endpoint, Z_RIGHT(Z_HOST_REQUEST)) == Z_OK);
        assert(z_caps_check(&f.broker.capabilities, f.broker.policies, endpoint(Z_CLIENT), (uint64_t)storage_cap,
                            endpoint(Z_FS), Z_RIGHT(Z_FILE_WRITE)) == Z_OK);
        assert(z_runtime_poll(&f.runtime, parent.slot, 1000) == 0);
        assert(z_runtime_reap(&f.runtime, Z_PROBE, parent.control) == Z_OK);
        assert(z_runtime_stop(&f.runtime, Z_PROBE, sibling.control) == Z_OK);
        assert(z_runtime_reap(&f.runtime, Z_PROBE, sibling.control) == Z_OK);
        assert_no_dynamic_charge();
    }
    for (unsigned i = 0; i < sizeof(points) / sizeof(*points); ++i)
        for (unsigned fail = 0; fail < 2; ++fail) {
            fixture_init();
            struct z_create_result parent = create(Z_PROBE, domain(Z_PROBE), 1, 1, 8);
            assert(z_runtime_fault(&f.runtime, parent.slot, 0, 14) == Z_OK);
            set_injection(points[i], fail, Z_PROBE);
            assert(z_runtime_poll(&f.runtime, parent.slot, 4) < 0);
            assert(f.injection.consumed);
            if (!z_runtime_check(&f.runtime))
                fprintf(stderr, "restart retirement point=%u fail=%u child_origin=%u child_phase=%u child_pages=%u\n",
                    points[i], fail, f.runtime.records[parent.slot].origin,
                    f.broker.policies[parent.slot].phase, f.memory.cells[parent.slot].count);
            assert(z_runtime_check(&f.runtime));
            assert(allocated_pages() == 80);
            assert(f.runtime.records[parent.slot].origin == Z_RUNTIME_FREE);
            assert(f.broker.policies[parent.slot].phase == Z_POLICY_DORMANT);
            assert(f.broker.policies[Z_PROBE].phase == Z_POLICY_BACKOFF);
        }
}

static void root_retirement_reaps_ready_backoff_terminal_and_quarantined_descendants(void)
{
    fixture_init();
    uint64_t old_authority = domain(Z_PROBE);
    struct z_create_result manager = create(Z_PROBE, old_authority, 1, 2, 8);
    struct z_create_result stopped = create(manager.slot, manager.creation, 2, 0, 0);
    struct z_create_result delayed = create(manager.slot, manager.creation, 2, 0, 0);
    struct z_create_result sibling = create(Z_PROBE, old_authority, 2, 0, 0);
    assert(z_runtime_stop(&f.runtime, manager.slot, stopped.control) == Z_OK);
    assert(z_runtime_fault(&f.runtime, delayed.slot, 0, 14) == Z_OK);
    f.broker.policies[sibling.slot].restarts = 3;
    f.broker.policies[sibling.slot].faults = 3;
    assert(z_runtime_fault(&f.runtime, sibling.slot, 0, 14) == Z_OK);
    assert(status(Z_PROBE, sibling.control).phase == Z_POLICY_QUARANTINED);
    uint32_t fault_reason = status(Z_PROBE, sibling.control).reason;
    assert(fault_reason == (UINT32_C(0x10000) | 14));
    assert(z_runtime_stop(&f.runtime, Z_PROBE, sibling.control) == Z_OK);
    assert(status(Z_PROBE, sibling.control).reason == fault_reason);
    uint64_t sentinel = UINT64_C(0x483764910fea52cc);
    store(Z_PROBE, Z_HEAP_BASE, &sentinel, sizeof(sentinel));
    assert(z_runtime_fault(&f.runtime, Z_PROBE, 0, 14) == Z_OK);
    assert(z_runtime_check(&f.runtime));
    assert(allocated_pages() == 80);
    for (unsigned cell = Z_ROOT_COUNT; cell < Z_CELL_COUNT; ++cell) {
        assert(f.runtime.records[cell].origin == Z_RUNTIME_FREE);
        assert(f.broker.policies[cell].phase == Z_POLICY_DORMANT);
        assert(f.waits.entries[cell].kind == Z_WAIT_NONE && f.broker.queues[cell].count == 0);
        assert(z_runtime_poll(&f.runtime, cell, 1000) == 0);
    }
    assert(f.runtime.hierarchy.domains[Z_PROBE].token == 0);
    assert(f.runtime.hierarchy.domains[Z_PROBE].owned_slots == 0);
    assert(f.runtime.hierarchy.domains[Z_PROBE].reserved_pages == 0);
    assert(z_runtime_poll(&f.runtime, Z_PROBE, 3) == 0);
    assert(z_runtime_poll(&f.runtime, Z_PROBE, 4) == 1);
    uint64_t observed; load(Z_PROBE, Z_HEAP_BASE, &observed, sizeof(observed)); assert(observed == 0);
    uint64_t fresh_authority = domain(Z_PROBE);
    assert(fresh_authority != old_authority && endpoint(Z_PROBE) >> 8 == 2);
    assert(z_runtime_status(&f.runtime, Z_PROBE, manager.control, status_address, sizeof(struct z_cell_status)) == Z_STALE);
    struct z_create_request stale = creation(Z_PROBE, old_authority, 2, 0, 0);
    assert(create_request(Z_PROBE, &stale, input_address, sizeof(stale), output_address) == Z_STALE);
    struct z_create_result replacement = create(Z_PROBE, fresh_authority, 2, 0, 0);
    assert(replacement.endpoint >> 8 == 2);
    for (unsigned root = 0; root < Z_PROBE; ++root) assert(endpoint(root) >> 8 == 1);
    assert(z_runtime_stop(&f.runtime, Z_PROBE, replacement.control) == Z_OK);
    assert(z_runtime_reap(&f.runtime, Z_PROBE, replacement.control) == Z_OK);
    assert_no_dynamic_charge();
}

static void creation_revocation_preserves_query_cleanup_and_existing_narrow_channels(void)
{
    fixture_init();
    uint64_t authority = domain(Z_PROBE);
    struct z_create_result manager = create(Z_PROBE, authority, 1, 1, 8);
    struct z_create_result child = create(manager.slot, manager.creation, 2, 0, 0);
    assert(z_runtime_revoke(&f.runtime, Z_PROBE, authority) == Z_OK);
    assert(ledger(Z_PROBE, authority).revoked == 1);
    assert(status(Z_PROBE, manager.control).instance == manager.instance);
    assert(status(manager.slot, child.control).instance == child.instance);
    assert(send(Z_PROBE, manager.endpoint, manager.channel, Z_HOST_REQUEST, 17) == Z_OK);
    struct z_message message; assert(z_broker_receive(&f.broker, manager.slot, &message) == Z_OK);
    struct z_create_request request = creation(Z_PROBE, authority, 2, 0, 0);
    assert(create_request(Z_PROBE, &request, input_address, sizeof(request), output_address) == Z_DENIED);
    request = creation(manager.slot, manager.creation, 2, 0, 0);
    assert(create_request(manager.slot, &request, input_address, sizeof(request), output_address) == Z_DENIED);
    assert(rebind(Z_PROBE, authority, manager.control, NULL) == Z_DENIED);
    assert(z_runtime_stop(&f.runtime, Z_PROBE, manager.control) == Z_OK);
    assert(z_runtime_reap(&f.runtime, Z_PROBE, manager.control) == Z_OK);
    assert_no_dynamic_charge();
}

static void repeated_cycles_conserve_backing_reservations_and_generation_history(void)
{
    fixture_init();
    uint64_t authority = domain(Z_PROBE);
    uint64_t history[Z_CELL_COUNT] = {1, 1, 1, 1, 0, 0, 0, 0};
    uint64_t last_control_epoch = 0;
    for (unsigned cycle = 0; cycle < 256; ++cycle) {
        struct z_create_result manager = create(Z_PROBE, authority, 1, 1, 8);
        assert(manager.endpoint >> 8 == ++history[manager.slot]);
        assert(manager.control >> 8 > last_control_epoch); last_control_epoch = manager.control >> 8;
        struct z_create_result worker = create(manager.slot, manager.creation, 2, 0, 0);
        assert(worker.endpoint >> 8 == ++history[worker.slot]);
        assert(worker.control >> 8 > last_control_epoch); last_control_epoch = worker.control >> 8;
        if (cycle & 1) {
            bool blocked;
            assert(z_wait_receive(&f.waits, &f.broker, worker.slot, cycle * 100, 17,
                status_address, receive_copy, &f, &blocked) == Z_OK && blocked);
        } else assert(z_wait_sleep(&f.waits, &f.broker, worker.slot, cycle * 100, 17) == Z_OK);
        assert(z_runtime_fault(&f.runtime, manager.slot, cycle * 100, 14) == Z_OK);
        assert(f.waits.entries[worker.slot].kind == Z_WAIT_NONE);
        assert(f.runtime.records[worker.slot].origin == Z_RUNTIME_FREE);
        assert(z_runtime_poll(&f.runtime, manager.slot, cycle * 100 + 4) == 1);
        ++history[manager.slot];
        assert(status(Z_PROBE, manager.control).generation == history[manager.slot]);
        struct z_create_result rebound;
        assert(rebind(Z_PROBE, authority, manager.control, &rebound) == Z_OK);
        f.sequence[manager.slot] = 0;
        struct z_create_result replacement = create(manager.slot, rebound.creation, 2, 0, 0);
        assert(replacement.endpoint >> 8 == ++history[replacement.slot]);
        assert(replacement.control >> 8 > last_control_epoch); last_control_epoch = replacement.control >> 8;
        assert(z_runtime_stop(&f.runtime, Z_PROBE, manager.control) == Z_OK);
        assert(z_runtime_reap(&f.runtime, Z_PROBE, manager.control) == Z_OK);
        assert(z_runtime_status(&f.runtime, Z_PROBE, manager.control, status_address, sizeof(struct z_cell_status)) == Z_STALE);
        assert_no_dynamic_charge();
        for (unsigned cell = 0; cell < Z_CELL_COUNT; ++cell) assert(f.runtime.hierarchy.history[cell] == history[cell]);
    }
}

/* Independent host model: logical nodes in a compact unordered list. Credit
 * is derived by traversing direct owners, never stored as production ledgers. */
enum model_life { MODEL_READY, MODEL_BACKOFF, MODEL_STOPPED, MODEL_QUARANTINED };
struct model_node {
    struct z_create_result info;
    uint64_t parent, deadline, marker;
    unsigned template_id, depth, pages, allowance_slots, allowance_pages, restarts, faults;
    enum model_life life;
    unsigned wait_kind;
    uint64_t wait_deadline;
    uint64_t queued[Z_QUEUE_DEPTH];
    unsigned queue_count;
};
struct model_tree {
    struct model_node nodes[4];
    unsigned count;
    uint64_t history[Z_CELL_COUNT], now, root_domain;
    uint64_t seed, rng, step;
    uint64_t stale_controls[32], stale_endpoints[32];
    unsigned stale_count, stale_cursor;
    bool root_revoked;
};
static struct model_tree model;
#define MODEL_CHECK(value) do { if (!(value)) { \
    fprintf(stderr, "C hosting model seed=0x%llx step=%llu check=%s line=%u\n", \
      (unsigned long long)model.seed, (unsigned long long)model.step, #value, __LINE__); \
    assert(value); } } while (0)
static uint64_t model_random(void)
{
    model.rng ^= model.rng << 13; model.rng ^= model.rng >> 7; model.rng ^= model.rng << 17;
    return model.rng;
}
static struct model_node *model_logical(uint64_t instance)
{
    for (unsigned i = 0; i < model.count; ++i)
        if (model.nodes[i].info.instance == instance) return &model.nodes[i];
    return NULL;
}
static unsigned model_owner(const struct model_node *node)
{
    return node->parent == 0 ? Z_PROBE : model_logical(node->parent)->info.slot;
}
static bool model_holds(const struct model_node *node)
{
    return node->life == MODEL_READY || node->life == MODEL_BACKOFF;
}
static void model_credit(uint64_t parent, unsigned *slots, unsigned *pages,
                           unsigned *reserved_slots, unsigned *reserved_pages)
{
    *slots = *pages = *reserved_slots = *reserved_pages = 0;
    for (unsigned i = 0; i < model.count; ++i) {
        const struct model_node *child = &model.nodes[i];
        if (child->parent != parent) continue;
        ++*slots;
        if (model_holds(child)) {
            *pages += child->pages;
            *reserved_slots += child->allowance_slots;
            *reserved_pages += child->allowance_pages;
        }
    }
}
static void model_retire(const struct model_node *node)
{
    model.stale_controls[model.stale_cursor] = node->info.control;
    model.stale_endpoints[model.stale_cursor] = node->info.endpoint;
    model.stale_cursor = (model.stale_cursor + 1) % 32;
    if (model.stale_count < 32) ++model.stale_count;
}
static void model_remove(unsigned at)
{
    model_retire(&model.nodes[at]);
    model.nodes[at] = model.nodes[--model.count];
}
static void model_remove_descendants(uint64_t parent)
{
    for (unsigned i = 0; i < model.count;) {
        if (model.nodes[i].parent == parent) model_remove(i);
        else ++i;
    }
}
static void model_compare(void)
{
    MODEL_CHECK(z_runtime_check(&f.runtime));
    unsigned physical = 80;
    unsigned roots, pages, reservation_slots, reservation_pages;
    model_credit(0, &roots, &pages, &reservation_slots, &reservation_pages);
    struct z_domain_status root = ledger(Z_PROBE, model.root_domain);
    MODEL_CHECK(root.owned_slots == roots && root.owned_pages == pages);
    MODEL_CHECK(root.reserved_slots == reservation_slots && root.reserved_pages == reservation_pages);
    MODEL_CHECK(root.available_slots == 4 - roots - reservation_slots);
    MODEL_CHECK(root.available_pages == 48 - pages - reservation_pages);
    bool slots[Z_CELL_COUNT] = {0};
    for (unsigned i = 0; i < model.count; ++i) {
        const struct model_node *n = &model.nodes[i];
        MODEL_CHECK(n->info.slot >= Z_ROOT_COUNT && n->info.slot < Z_CELL_COUNT && !slots[n->info.slot]);
        slots[n->info.slot] = true;
        MODEL_CHECK(n->depth == (n->parent == 0 ? 1 : 2));
        if (n->parent != 0) MODEL_CHECK(model_logical(n->parent) != NULL);
        unsigned expected_pages = model_holds(n) ? n->pages : 0;
        physical += expected_pages;
        MODEL_CHECK(f.memory.cells[n->info.slot].count == expected_pages);
        MODEL_CHECK(f.runtime.records[n->info.slot].parent_instance == n->parent);
        MODEL_CHECK(f.runtime.records[n->info.slot].instance == n->info.instance);
        MODEL_CHECK(f.runtime.records[n->info.slot].control == n->info.control);
        const struct z_policy_state *policy = &f.broker.policies[n->info.slot];
        unsigned phase = n->life == MODEL_READY ? Z_POLICY_READY : n->life == MODEL_BACKOFF ?
            Z_POLICY_BACKOFF : n->life == MODEL_STOPPED ? Z_POLICY_STOPPED : Z_POLICY_QUARANTINED;
        MODEL_CHECK(policy->phase == phase && policy->generation == model.history[n->info.slot]);
        MODEL_CHECK(policy->restarts == n->restarts && policy->faults == n->faults);
        if (n->life == MODEL_BACKOFF) MODEL_CHECK(policy->deadline == n->deadline);
        MODEL_CHECK(f.waits.entries[n->info.slot].kind == n->wait_kind);
        if (n->wait_kind) MODEL_CHECK(f.waits.entries[n->info.slot].deadline == n->wait_deadline);
        MODEL_CHECK(f.broker.queues[n->info.slot].count == n->queue_count);
        if (expected_pages != 0) {
            uint64_t marker; load(n->info.slot, Z_HEAP_BASE, &marker, sizeof(marker));
            MODEL_CHECK(marker == n->marker);
        }
        struct z_cell_status reported = status(model_owner(n), n->info.control);
        MODEL_CHECK(reported.instance == n->info.instance && reported.generation == model.history[n->info.slot]);
        MODEL_CHECK(reported.phase == phase && reported.own_pages == expected_pages);
        if (n->template_id == 1 && model_holds(n) && n->info.creation != 0) {
            unsigned owned_slots, owned_pages, rs, rp;
            model_credit(n->info.instance, &owned_slots, &owned_pages, &rs, &rp);
            struct z_domain_status domain_status = ledger(n->info.slot, n->info.creation);
            MODEL_CHECK(domain_status.slot_limit == n->allowance_slots && domain_status.page_limit == n->allowance_pages);
            MODEL_CHECK(domain_status.owned_slots == owned_slots && domain_status.owned_pages == owned_pages);
            MODEL_CHECK(domain_status.reserved_slots == rs && domain_status.reserved_pages == rp);
        }
    }
    MODEL_CHECK(allocated_pages() == physical);
    for (unsigned slot = Z_ROOT_COUNT; slot < Z_CELL_COUNT; ++slot) {
        MODEL_CHECK(f.runtime.hierarchy.history[slot] == model.history[slot]);
        if (!slots[slot]) MODEL_CHECK(f.runtime.records[slot].origin == Z_RUNTIME_FREE && f.memory.cells[slot].count == 0);
    }
    for (unsigned i = 0; i < model.stale_count; ++i) {
        MODEL_CHECK(z_runtime_status(&f.runtime, Z_PROBE, model.stale_controls[i], status_address, sizeof(struct z_cell_status)) != Z_OK);
        MODEL_CHECK(z_policy_resolve(f.broker.policies, Z_CELL_COUNT, model.stale_endpoints[i]) < 0);
    }
}
static void generated_production_tree_resource_queue_and_wait_model(void)
{
    const uint64_t seeds[] = { UINT64_C(0x5ea105), UINT64_C(0x726f6c6c6261636b), UINT64_C(0x9e3779b97f4a7c15) };
    for (unsigned seed = 0; seed < sizeof(seeds) / sizeof(*seeds); ++seed) {
        fixture_init();
        model = (struct model_tree) { .history = {1, 1, 1, 1, 0, 0, 0, 0},
            .root_domain = domain(Z_PROBE), .seed = seeds[seed], .rng = seeds[seed] };
        for (model.step = 0; model.step < 2500; ++model.step) {
            unsigned operation = (unsigned)(model_random() % 11);
            unsigned at = model.count == 0 ? 0 : (unsigned)(model_random() % model.count);
            struct model_node selected = model.count == 0 ? (struct model_node){0} : model.nodes[at];
            if (operation <= 2) {
                uint64_t parent = 0, authority = model.root_domain;
                unsigned owner = Z_PROBE, limit_slots = 4, limit_pages = 48, template_id = 2;
                unsigned delegate_slots = 0, delegate_pages = 0, depth = 1;
                if (model.count != 0 && selected.template_id == 1 && selected.life == MODEL_READY &&
                    selected.info.creation != 0 && selected.wait_kind == Z_WAIT_NONE && (model_random() & 1)) {
                    parent = selected.info.instance; owner = selected.info.slot; authority = selected.info.creation;
                    limit_slots = selected.allowance_slots; limit_pages = selected.allowance_pages; depth = 2;
                } else if ((model_random() % 4) == 0) {
                    template_id = 1; delegate_slots = (unsigned)(model_random() % 3);
                    delegate_pages = (unsigned)(model_random() % 9);
                }
                unsigned own_slots, own_pages, rs, rp;
                model_credit(parent, &own_slots, &own_pages, &rs, &rp);
                unsigned private_pages = template_id == 1 ? 4 : 2;
                bool fits = model.count < 4 && own_slots + rs + 1 + delegate_slots <= limit_slots &&
                    own_pages + rp + private_pages + delegate_pages <= limit_pages;
                struct z_create_request request = creation(owner, authority, template_id, delegate_slots, delegate_pages);
                bool failure = (model_random() % 7) == 0;
                if (failure) set_injection(model_random() & 1 ? INJECT_SPACE_PARTIAL : INJECT_COPY_OUT, true, -1);
                int result = create_request(owner, &request, input_address, sizeof(request), output_address);
                MODEL_CHECK((result == Z_OK) == (fits && !failure && !model.root_revoked));
                set_injection(INJECT_NONE, false, -1);
                if (result == Z_OK) {
                    struct z_create_result created; load(owner, output_address, &created, sizeof(created));
                    MODEL_CHECK(created.endpoint >> 8 == ++model.history[created.slot]);
                    struct model_node *n = &model.nodes[model.count++];
                    *n = (struct model_node) { .info = created, .parent = parent, .template_id = template_id,
                        .depth = depth, .pages = private_pages, .allowance_slots = delegate_slots,
                        .allowance_pages = delegate_pages, .life = MODEL_READY,
                        .marker = created.instance ^ UINT64_C(0x54ef723991a0dc85) };
                    store(created.slot, Z_HEAP_BASE, &n->marker, sizeof(n->marker));
                    f.sequence[created.slot] = 0;
                }
            } else if (operation == 3 && model.count != 0 && selected.life == MODEL_READY) {
                MODEL_CHECK(z_runtime_fault(&f.runtime, selected.info.slot, model.now, 14) == Z_OK);
                model_remove_descendants(selected.info.instance);
                struct model_node *n = model_logical(selected.info.instance);
                MODEL_CHECK(n != NULL);
                n->info.channel = 0; n->info.creation = 0; n->queue_count = 0; n->wait_kind = Z_WAIT_NONE;
                ++n->faults;
                if (n->restarts == 3) n->life = MODEL_QUARANTINED;
                else { n->life = MODEL_BACKOFF; n->deadline = model.now + (UINT64_C(4) << n->restarts); }
            } else if (operation == 4) {
                model.now += model_random() % 9 + 1;
                for (unsigned i = 0; i < model.count; ++i) {
                    struct model_node *n = &model.nodes[i];
                    if (n->life == MODEL_BACKOFF) {
                        bool due = model.now >= n->deadline;
                        MODEL_CHECK(z_runtime_poll(&f.runtime, n->info.slot, model.now) == (int)due);
                        if (due) {
                            n->life = MODEL_READY; ++n->restarts; ++model.history[n->info.slot];
                            n->info.endpoint = endpoint(n->info.slot); n->marker = 0;
                            f.sequence[n->info.slot] = 0;
                        }
                    }
                    if (n->wait_kind != Z_WAIT_NONE) {
                        int result = 0; enum z_wake_reason reason;
                        bool due = model.now >= n->wait_deadline;
                        bool delivery = !due && n->wait_kind == Z_WAIT_RECEIVE && n->queue_count != 0;
                        enum z_wait_status observed = z_wait_poll(&f.waits, &f.broker, n->info.slot, model.now,
                            receive_copy, &f, &result, &reason);
                        MODEL_CHECK(observed == ((due || delivery) ? Z_WAIT_DONE : Z_WAIT_PENDING));
                        if (due || delivery) {
                            if (delivery) {
                                MODEL_CHECK(result == Z_OK && reason == Z_WAKE_MESSAGE);
                                struct z_message message; load(n->info.slot, status_address, &message, sizeof(message));
                                uint64_t marker; memcpy(&marker, message.payload, sizeof(marker));
                                MODEL_CHECK(marker == n->queued[0]);
                                memmove(n->queued, n->queued + 1, (--n->queue_count) * sizeof(n->queued[0]));
                            } else MODEL_CHECK(result == (n->wait_kind == Z_WAIT_SLEEP ? Z_OK : Z_TIMEOUT));
                            n->wait_kind = Z_WAIT_NONE;
                        }
                    }
                }
            } else if (operation == 5 && model.count != 0) {
                bool terminal = !model_holds(&selected);
                MODEL_CHECK(z_runtime_stop(&f.runtime, model_owner(&selected), selected.info.control) == Z_OK);
                if (!terminal) {
                    model_remove_descendants(selected.info.instance);
                    struct model_node *n = model_logical(selected.info.instance);
                    n->life = MODEL_STOPPED; n->info.creation = 0; n->info.channel = 0;
                    n->queue_count = 0; n->wait_kind = Z_WAIT_NONE;
                }
            } else if (operation == 6 && model.count != 0) {
                int result = z_runtime_reap(&f.runtime, model_owner(&selected), selected.info.control);
                MODEL_CHECK(result == (model_holds(&selected) ? Z_DENIED : Z_OK));
                if (result == Z_OK) model_remove(at);
            } else if (operation == 7 && model.count != 0 && selected.life == MODEL_READY && selected.info.channel == 0) {
                unsigned owner = model_owner(&selected);
                uint64_t creation_domain = selected.parent == 0 ? model.root_domain : model_logical(selected.parent)->info.creation;
                struct z_create_result rebound;
                bool failure = model_random() % 5 == 0;
                if (failure) set_injection(INJECT_COPY_OUT, true, -1);
                int result = rebind(owner, creation_domain, selected.info.control, &rebound);
                MODEL_CHECK((result == Z_OK) == (!model.root_revoked && !failure));
                set_injection(INJECT_NONE, false, -1);
                if (result == Z_OK) {
                    struct model_node *n = model_logical(selected.info.instance);
                    MODEL_CHECK(rebound.endpoint == n->info.endpoint && rebound.control == n->info.control);
                    n->info = rebound;
                }
            } else if (operation == 8 && model.count != 0 && selected.life == MODEL_READY && selected.wait_kind == Z_WAIT_NONE) {
                uint64_t duration = model_random() % 17 + 1;
                struct model_node *n = model_logical(selected.info.instance);
                n->wait_deadline = model.now + duration;
                if (model_random() & 1) {
                    MODEL_CHECK(z_wait_sleep(&f.waits, &f.broker, n->info.slot, model.now, duration) == Z_OK);
                    n->wait_kind = Z_WAIT_SLEEP;
                } else {
                    bool blocked;
                    int result = z_wait_receive(&f.waits, &f.broker, n->info.slot, model.now, duration,
                        status_address, receive_copy, &f, &blocked);
                    MODEL_CHECK(result == Z_OK && blocked == (n->queue_count == 0));
                    if (blocked) n->wait_kind = Z_WAIT_RECEIVE;
                    else memmove(n->queued, n->queued + 1, (--n->queue_count) * sizeof(n->queued[0]));
                }
            } else if (operation == 9 && model.count != 0 && selected.life == MODEL_READY && selected.info.channel != 0) {
                struct model_node *n = model_logical(selected.info.instance);
                uint64_t marker = model_random();
                int result = send(model_owner(n), n->info.endpoint, n->info.channel, Z_HOST_REQUEST, marker);
                MODEL_CHECK(result == (n->queue_count < Z_QUEUE_DEPTH ? Z_OK : Z_AGAIN));
                if (result == Z_OK) n->queued[n->queue_count++] = marker;
                if (n->wait_kind == Z_WAIT_NONE && n->queue_count != 0 && (model_random() & 1)) {
                    struct z_message message; MODEL_CHECK(z_broker_receive(&f.broker, n->info.slot, &message) == Z_OK);
                    memcpy(&marker, message.payload, sizeof(marker)); MODEL_CHECK(marker == n->queued[0]);
                    memmove(n->queued, n->queued + 1, (--n->queue_count) * sizeof(n->queued[0]));
                }
            } else if (operation == 10 && model_random() % 11 == 0) {
                MODEL_CHECK(z_runtime_revoke(&f.runtime, Z_PROBE, model.root_domain) == Z_OK);
                model.root_revoked = true;
            }
            model_compare();
            if (model.root_revoked && model.count == 0) {
                uint64_t step = model.step, rng = model.rng, seed_value = model.seed;
                fixture_init();
                model = (struct model_tree) { .history = {1, 1, 1, 1, 0, 0, 0, 0},
                    .root_domain = domain(Z_PROBE), .seed = seed_value, .rng = rng, .step = step };
            }
        }
    }
}
#undef MODEL_CHECK

static void dormant_root_polling_and_orphaned_backoff_cleanup(void)
{
    for (unsigned solo = 0; solo < Z_ROOT_COUNT; ++solo) {
        fixture_init();
        for (unsigned root = 0; root < Z_ROOT_COUNT; ++root) {
            f.manifest.cells[root].flags = root == solo ? Z_MANIFEST_ACTIVE : 0;
            f.manifest.cells[root].boot_config = 0;
            if (root != solo) { space_release(&f, root); f.frames[root] = (struct z_frame){0}; }
        }
        f.manifest.template_count = f.manifest.domain_count = 0;
        uint8_t bytes[Z_MANIFEST_ARTIFACT_MAX] = {0};
        size_t length = sizeof(struct z_manifest_header) + sizeof(f.manifest.cells) +
            f.manifest.grant_count * sizeof(f.manifest.grants[0]);
        struct z_manifest_header header = { .magic = Z_MANIFEST_MAGIC, .version = Z_MANIFEST_VERSION,
            .total_size = (uint32_t)length, .cell_count = 4, .grant_count = f.manifest.grant_count };
        memcpy(bytes, &header, sizeof(header));
        memcpy(bytes + sizeof(header), f.manifest.cells, sizeof(f.manifest.cells));
        memcpy(bytes + sizeof(header) + sizeof(f.manifest.cells), f.manifest.grants,
            f.manifest.grant_count * sizeof(f.manifest.grants[0]));
        enum z_manifest_error error;
        struct z_manifest sealed;
        assert(z_manifest_validate(bytes, length, f.catalog, 6, &sealed, &error));
        f.manifest = sealed;
        z_broker_init(&f.broker);
        for (unsigned root = 0; root < Z_ROOT_COUNT; ++root)
            if (root != solo) f.broker.policies[root] = (struct z_policy_state){0};
        assert(z_runtime_init(&f.runtime, &f.broker, &f.waits, f.frames, &f.manifest,
            f.catalog, 6, &callbacks, &f) == Z_OK);
        for (unsigned cell = 0; cell < Z_CELL_COUNT; ++cell)
            assert(z_runtime_poll(&f.runtime, cell, UINT64_MAX) == 0);
        assert(z_runtime_check(&f.runtime) && allocated_pages() == 20);
        assert(z_wait_next(&f.waits, &f.broker, (solo + 1) % Z_CELL_COUNT) == (int)solo);
        assert(z_runtime_exit(&f.runtime, solo) == Z_OK);
        assert(z_runtime_check(&f.runtime) && allocated_pages() == 0);
        assert(z_wait_next(&f.waits, &f.broker, solo) == -1);
    }
    fixture_init();
    struct z_create_result manager = create(Z_PROBE, domain(Z_PROBE), 1, 1, 8);
    assert(z_runtime_fault(&f.runtime, manager.slot, 0, 14) == Z_OK);
    // Host-only trusted seam: the owner's endpoint has already retired, before
    // mechanism cleanup is asked to poll its promised child. No syscall can
    // select this seam or mutate these policy states.
    z_policy_stop(&f.broker.policies[Z_PROBE]);
    f.runtime.records[Z_PROBE].published = 0;
    f.runtime.hierarchy.domains[Z_PROBE].token = 0;
    assert(z_runtime_poll(&f.runtime, manager.slot, 4) == 0);
    assert(f.runtime.records[manager.slot].origin == Z_RUNTIME_FREE);
    assert(f.memory.cells[manager.slot].count == 0);
    assert(f.runtime.hierarchy.domains[Z_PROBE].owned_slots == 0);
    assert(f.runtime.hierarchy.domains[Z_PROBE].reserved_pages == 0);
    assert(z_runtime_check(&f.runtime));
}

static void image_role_diagnostic_instance_and_slot_are_distinct(void)
{
    fixture_catalog_config(8192, 16384, 4096, 8192, 2, 4, 48, true);
    struct z_create_result first = create(Z_PROBE, domain(Z_PROBE), 2, 0, 0);
    struct z_create_result second = create(Z_PROBE, domain(Z_PROBE), 3, 0, 0);
    struct z_boot_info a, b;
    assert(z_runtime_boot(&f.runtime, first.slot, &a) == Z_OK);
    assert(z_runtime_boot(&f.runtime, second.slot, &b) == Z_OK);
    assert(a.role == Z_WORKER && b.role == Z_WORKER);
    assert(f.runtime.records[first.slot].config.image == 6);
    assert(f.runtime.records[second.slot].config.image == 7);
    assert(first.identity != second.identity && first.instance != second.instance && first.control != second.control);
    assert(first.slot != second.slot && first.endpoint != second.endpoint);
    assert(a.creation == 0 && b.creation == 0 && a.parent_endpoint == endpoint(Z_PROBE) && b.parent_endpoint == endpoint(Z_PROBE));
    assert(a.template_id == 2 && b.template_id == 3 && a.identity == first.identity && b.identity == second.identity);
    assert(z_runtime_stop(&f.runtime, Z_PROBE, first.control) == Z_OK);
    assert(z_runtime_reap(&f.runtime, Z_PROBE, first.control) == Z_OK);
    assert(z_runtime_stop(&f.runtime, Z_PROBE, second.control) == Z_OK);
    assert(z_runtime_reap(&f.runtime, Z_PROBE, second.control) == Z_OK);
    assert_no_dynamic_charge();
}

static void nested_owner_and_ancestor_retirement_at_every_creation_boundary(void)
{
    const enum injection_point points[] = { INJECT_INPUT_RANGE, INJECT_OUTPUT_RANGE, INJECT_COPY_IN,
        INJECT_SPACE_BEFORE, INJECT_SPACE_PARTIAL, INJECT_SPACE_AFTER,
        INJECT_MEMORY_CHECK, INJECT_FRAME, INJECT_COPY_OUT };
    unsigned probes = 0;
    for (unsigned i = 0; i < sizeof(points) / sizeof(*points); ++i)
        for (unsigned fail = 0; fail < 2; ++fail)
            for (unsigned victim = 0; victim < 2; ++victim) {
                fixture_init();
                uint64_t root_authority = domain(Z_PROBE);
                struct z_create_result manager = create(Z_PROBE, root_authority, 1, 2, 8);
                struct z_create_request request = creation(manager.slot, manager.creation, 2, 0, 0);
                set_injection(points[i], fail, victim ? Z_PROBE : (int)manager.slot);
                int result = create_request(manager.slot, &request, input_address, sizeof(request), output_address);
                assert(result != Z_OK && f.injection.consumed);
                assert(f.publication_count == 1 && z_runtime_check(&f.runtime));
                assert(allocated_pages() == (victim ? 80 : 84));
                for (unsigned child = Z_ROOT_COUNT; child < Z_CELL_COUNT; ++child)
                    if (child != manager.slot || victim) assert(f.runtime.records[child].origin == Z_RUNTIME_FREE);
                set_injection(INJECT_NONE, false, -1);
                if (!victim) {
                    assert(z_runtime_poll(&f.runtime, manager.slot, 4) == 1);
                    struct z_create_result rebound;
                    assert(rebind(Z_PROBE, root_authority, manager.control, &rebound) == Z_OK);
                    f.sequence[manager.slot] = 0;
                    create(manager.slot, rebound.creation, 2, 0, 0);
                    assert(z_runtime_stop(&f.runtime, Z_PROBE, manager.control) == Z_OK);
                    assert(z_runtime_reap(&f.runtime, Z_PROBE, manager.control) == Z_OK);
                } else assert(z_runtime_poll(&f.runtime, Z_PROBE, 4) == 1);
                assert_no_dynamic_charge();
                ++probes;
            }
    assert(probes == 36);
}

int main(void)
{
    real_creation_identity_backing_channels_and_denied_storage();
    ordinary_failures_roll_back_every_reserved_resource();
    parent_retirement_at_all_creation_boundaries();
    checked_ranges_exact_lengths_reserved_fields_and_overflow();
    subtree_recovery_wait_queue_memory_and_sibling_preservation();
    rebind_failure_atomicity_request_retirement_and_unrelated_faults();
    private_budget_rounding_exact_last_global_page_and_maximum();
    pressure_retained_controls_capabilities_and_counters();
    restart_failures_and_owner_retirement_never_republish();
    root_retirement_reaps_ready_backoff_terminal_and_quarantined_descendants();
    creation_revocation_preserves_query_cleanup_and_existing_narrow_channels();
    repeated_cycles_conserve_backing_reservations_and_generation_history();
    generated_production_tree_resource_queue_and_wait_model();
    dormant_root_polling_and_orphaned_backoff_cleanup();
    image_role_diagnostic_instance_and_slot_are_distinct();
    nested_owner_and_ancestor_retirement_at_every_creation_boundary();
    printf("C hosting: 16 groups, fixtures=%u, injected failures=%u/faults=%u, 256 recovery/cleanup/reuse cycles, 7500 independent model steps seeds=0x5ea105/0x726f6c6c6261636b/0x9e3779b97f4a7c15; production checked copies, private page ownership, reservation conservation, rollback, stale typed authority, capability pressure/exhaustion, subtree waits/queues/sibling preservation PASS\n",
        fixture_count, failure_injections, fault_injections);
    return 0;
}
