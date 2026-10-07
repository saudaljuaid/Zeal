#include <zeal/abi.h>
#include <zeal/arch.h>
#include <zeal/ipc.h>
#include <zeal/hosting.h>
#include <zeal/memory.h>
#include <zeal/wait.h>

#ifndef Z_SCENARIO
#define Z_SCENARIO 0
#endif
#ifndef Z_TEST
#define Z_TEST 0
#endif
#ifndef Z_SOLO
#define Z_SOLO -1
#endif

extern const unsigned char _binary_block_bin_start[], _binary_block_bin_end[];
extern const unsigned char _binary_filesystem_bin_start[], _binary_filesystem_bin_end[];
extern const unsigned char _binary_client_bin_start[], _binary_client_bin_end[];
extern const unsigned char _binary_probe_bin_start[], _binary_probe_bin_end[];
extern const unsigned char _binary_manifest_bin_start[], _binary_manifest_bin_end[];
extern const unsigned char _binary_supervisor_bin_start[], _binary_supervisor_bin_end[];
extern const unsigned char _binary_worker_bin_start[], _binary_worker_bin_end[];

static struct z_broker broker;
static struct z_wait_table waits;
static struct z_refresh_state root_refresh;
static struct z_manifest manifest;
static struct z_runtime runtime;
static struct z_image_catalog catalog[6];
static struct z_frame frames[Z_CELL_COUNT];
static const unsigned char *images[Z_MANIFEST_IMAGE_COUNT_MAX];
static size_t image_lengths[Z_MANIFEST_IMAGE_COUNT_MAX];
static unsigned current;
static uint64_t ticks, reads;
static uint64_t sends[Z_CELL_COUNT], fault_sends[2], fault_reads[2];
static unsigned run_ticks[Z_CELL_COUNT], boots[Z_CELL_COUNT], reset_reports, recovered;
static bool contract_ok, finished;
static unsigned wait_events[Z_CELL_COUNT], idle_events;
static bool wait_traced[Z_CELL_COUNT];
static unsigned storage_events, storage_reports;
static unsigned refresh_events;
static unsigned refresh_cell;
static unsigned storage_stage;
static uint64_t storage_checkpoint;
static bool storage_done;
static unsigned hosting_events, hosting_reports;
static uint64_t contract_entry_generation[Z_CELL_COUNT];
static uint64_t hosting_storage_cycles;
static bool hosting_complete, hosting_storage_ready;
static uint64_t hosting_last_cleanup_tick, hosting_cycle_boundary_tick;
static bool hosting_post_cleanup_verified;

static unsigned storage_trace_limit(void)
{
    /* Hosting preservation observes two files through longer subtree recovery
     * and teardown intervals. Legacy scenarios retain their original limit. */
    if (Z_SCENARIO == 24) return 2048u;
    return Z_SCENARIO >= 21 && Z_SCENARIO <= 23 ? 1024u : 512u;
}

static bool storage_trace_credit(unsigned *used)
{
    unsigned limit = storage_trace_limit();
    if (*used < limit) { ++*used; return true; }
    if (*used == limit) { ++*used; serial_puts("STORAGE_TRACE_EXHAUSTED\n"); }
    return false;
}

static void field(const char *name, uint64_t value)
{
    serial_puts(" "); serial_puts(name); serial_puts("="); serial_hex(value);
}

static void event(const char *name, unsigned cell)
{
    serial_puts("EVENT "); serial_puts(name);
    field("cell", cell); field("identity", runtime.initialized ? runtime.records[cell].config.identity : manifest.cells[cell].identity);
    field("generation", broker.policies[cell].generation); field("tick", ticks);
}

static uint64_t storage_word(const uint8_t *bytes, unsigned count)
{
    uint64_t value = 0;
    for (unsigned i = 0; i < count; ++i) value |= (uint64_t)bytes[i] << (i * 8);
    return value;
}

static void page_fields(unsigned cell)
{
    unsigned count = arch_space_pages(cell);
    field("physical_pages", count);
    for (unsigned i = 0; i < count; ++i) {
        char name[4] = { 'p', 0, 0, 0 };
        if (i < 10) name[1] = (char)('0' + i);
        else { name[1] = '1'; name[2] = (char)('0' + i - 10); }
        field(name, arch_space_page_id(cell, i));
    }
}

static bool hosting_trace_credit(void)
{
    if (hosting_events < 2048) { ++hosting_events; return true; }
    if (hosting_events == 2048) {
        ++hosting_events; serial_puts("HOSTING_TRACE_EXHAUSTED\n");
    }
    return false;
}

static void trace_host_ipc(const struct z_message *message, unsigned cell,
                            uint64_t target, uint64_t capability, int result, bool delivered)
{
    if (Z_SCENARIO < 21 || Z_SCENARIO > 24 ||
        (message->operation != Z_HOST_REQUEST && message->operation != Z_HOST_REPLY) ||
        !hosting_trace_credit()) return;
    event(delivered ? "host-ipc-deliver" : result == Z_OK ? "host-ipc-enqueue" : "host-ipc-reject", cell);
    field("sender", message->sender); field("target", target); field("cap", capability);
    field("operation", message->operation); field("length", message->length);
    field("request", storage_word(message->payload, 8));
    field("command", storage_word(message->payload + 8, 4));
    if (Z_SCENARIO == 24) {
        field("version", message->payload[8]); field("service_command", message->payload[9]);
        field("kind", message->payload[10]); field("detail", message->payload[11]);
        field("token", storage_word(message->payload + 16, 8));
        field("data", storage_word(message->payload + 24, 8));
    }
    field("reserved", storage_word(message->payload + 12, 4));
    field("argument", storage_word(message->payload + 16, 8));
    field("value", storage_word(message->payload + 24, 8));
    field("result", (uint64_t)(int64_t)result); serial_puts("\n");
}

static void runtime_trace(void *context, const struct z_runtime_event *record)
{
    (void)context;
    if (Z_SCENARIO < 21 || Z_SCENARIO > 24 || !hosting_trace_credit()) return;
    static const char *const names[] = {
        "host-request", "host-reserve", "host-space", "host-channel", "host-publish",
        "host-abort", "host-result", "host-status", "host-stop", "host-reap",
        "host-fault", "host-backoff", "host-restart", "host-rebind", "host-revoke",
        "host-cancel", "host-invalidate", "host-cleanup", "host-return", "host-domain",
    };
    if (record->kind >= sizeof(names) / sizeof(names[0])) return;
    unsigned cell = record->cell;
    const struct z_runtime_record *owned = &record->record;
    const struct z_host_transaction *transaction = &record->transaction;
    serial_puts("EVENT "); serial_puts(names[record->kind]);
    field("cell", cell); field("identity", owned->config.identity);
    field("generation", transaction->endpoint ? transaction->endpoint >> 8 : broker.policies[cell].generation);
    field("tick", ticks); field("caller", record->caller);
    field("caller_identity", runtime.records[record->caller].config.identity);
    field("caller_endpoint", record->caller_endpoint); field("request", record->request);
    field("instance", transaction->instance ? transaction->instance : owned->instance);
    field("control", transaction->control ? transaction->control : owned->control);
    field("endpoint", transaction->endpoint ? transaction->endpoint :
          (broker.policies[cell].generation << 8) | (cell + 1));
    field("parent_instance", transaction->parent_instance ? transaction->parent_instance : owned->parent_instance);
    field("parent_endpoint", transaction->parent_endpoint ? transaction->parent_endpoint : owned->parent_endpoint);
    field("template", transaction->template_id ? transaction->template_id : owned->template_id);
    field("image", owned->config.image); field("role", owned->role);
    field("depth", transaction->depth ? transaction->depth : owned->depth);
    field("pages", transaction->pages ? transaction->pages : owned->allocated_pages);
    field("reserved_slots", transaction->transaction ? transaction->descendant_slots : owned->reserved_slots);
    field("reserved_pages", transaction->transaction ? transaction->descendant_pages : owned->reserved_pages);
    field("creation", transaction->domain ? transaction->domain : owned->creation);
    field("transaction", transaction->transaction);
    field("parent_cap", record->parent_cap); field("child_cap", record->child_cap);
    field("result", (uint64_t)(int64_t)record->result);
    field("phase", broker.policies[cell].phase); field("deadline", broker.policies[cell].deadline);
    field("reason", owned->last_reason);
    field("queued", record->queued); field("retired_pages", record->retired_pages);
    field("retained", runtime.records[cell].origin != Z_RUNTIME_FREE);
    if (record->kind == Z_RUNTIME_REQUEST ||
        (record->kind == Z_RUNTIME_RESULT && record->result != Z_OK)) {
        field("requested_slots", transaction->descendant_slots);
        field("requested_pages", transaction->descendant_pages);
    }
    if (record->kind == Z_RUNTIME_SPACE || record->kind == Z_RUNTIME_RESTART) {
        field("cs", frames[cell].cs); field("rip", frames[cell].rip); field("rsp", frames[cell].rsp);
        field("ss", frames[cell].ss); field("rflags", frames[cell].flags);
        field("zero", arch_space_zero(cell)); page_fields(cell);
    }
    if (record->kind == Z_RUNTIME_CHANNEL || record->kind == Z_RUNTIME_REBIND) {
        uint64_t handles[] = { record->parent_cap, record->child_cap };
        const char *prefix[] = { "parent", "child" };
        for (unsigned direction = 0; direction < 2; ++direction) {
            unsigned encoded = (unsigned)(handles[direction] & 255);
            if (encoded == 0 || encoded > Z_CAPACITY) continue;
            const struct z_cap_entry *grant = &broker.capabilities.entries[encoded - 1];
            serial_puts(" "); serial_puts(prefix[direction]); serial_puts("_holder="); serial_hex(grant->holder);
            serial_puts(" "); serial_puts(prefix[direction]); serial_puts("_target="); serial_hex(grant->target);
            serial_puts(" "); serial_puts(prefix[direction]); serial_puts("_issuer="); serial_hex(grant->issuer);
            serial_puts(" "); serial_puts(prefix[direction]); serial_puts("_rights="); serial_hex(grant->rights);
            serial_puts(" "); serial_puts(prefix[direction]); serial_puts("_derivation="); serial_hex(grant->parent);
            serial_puts(" "); serial_puts(prefix[direction]); serial_puts("_epoch="); serial_hex(grant->epoch);
        }
        field("recipe", transaction->bootstrap_recipe);
    }
    if (record->kind == Z_RUNTIME_CANCEL) {
        field("wait_generation", record->wait.generation); field("wait_kind", record->wait.kind);
        field("wait_deadline", record->wait.deadline);
        wait_traced[cell] = false;
    }
    if (record->kind == Z_RUNTIME_DOMAIN) {
        const struct z_domain_status *domain = &record->domain;
        field("domain", domain->domain); field("holder", domain->holder);
        field("domain_instance", domain->instance);
        field("slot_limit", domain->slot_limit); field("page_limit", domain->page_limit);
        field("owned_slots", domain->owned_slots); field("owned_pages", domain->owned_pages);
        field("domain_reserved_slots", domain->reserved_slots); field("domain_reserved_pages", domain->reserved_pages);
        field("available_slots", domain->available_slots); field("available_pages", domain->available_pages);
        field("max_depth", domain->max_depth); field("template_mask", domain->template_mask);
        field("recipe", domain->recipe); field("revoked", domain->revoked);
    }
    serial_puts("\n");
    if (record->kind == Z_RUNTIME_PUBLISH) {
        run_ticks[cell] = 0;
        if (boots[cell] != UINT32_MAX) ++boots[cell];
    }
    if (record->kind == Z_RUNTIME_STOP || record->kind == Z_RUNTIME_REAP) {
        hosting_last_cleanup_tick = ticks; hosting_post_cleanup_verified = false;
    }
}

static bool runtime_range(void *context, unsigned cell, uint64_t address, size_t length, bool write)
{ (void)context; return arch_cell_range(cell, address, length, write); }
static bool runtime_copy_in(void *context, unsigned cell, void *destination, uint64_t source, size_t length)
{ (void)context; return arch_cell_copy_in(cell, destination, source, length); }
static bool runtime_copy_out(void *context, unsigned cell, uint64_t destination, const void *source, size_t length)
{ (void)context; return arch_cell_copy_out(cell, destination, source, length); }
static bool runtime_space_init(void *context, unsigned cell, const void *image, size_t length,
                                const struct z_manifest_cell *config)
{ (void)context; return arch_space_init(cell, image, length, config); }
static bool runtime_space_reset(void *context, unsigned cell, const void *image, size_t length,
                                 const struct z_manifest_cell *config)
{ (void)context; return arch_space_reset(cell, image, length, config); }
static void runtime_space_release(void *context, unsigned cell)
{ (void)context; arch_space_release(cell); }
static bool runtime_frame_init(void *context, unsigned cell, struct z_frame *frame)
{ (void)context; arch_frame_init(frame, cell); return true; }
static unsigned runtime_space_pages(void *context, unsigned cell)
{ (void)context; return arch_space_pages(cell); }
static bool runtime_memory_check(void *context)
{ (void)context; return arch_memory_check(); }

static const struct z_runtime_callbacks runtime_callbacks = {
    runtime_range, runtime_copy_in, runtime_copy_out, runtime_space_init,
    runtime_space_reset, runtime_space_release, runtime_frame_init,
    runtime_space_pages, runtime_memory_check, runtime_trace,
};

static void trace_storage(const struct z_message *message, uint64_t target, uint64_t cap, int result)
{
    if (message->operation < Z_BLOCK_READ || message->operation > Z_FILE_RESULT ||
        !storage_trace_credit(&storage_events)) return;
    event(result == Z_OK ? "storage-ipc" : "storage-reject", current);
    field("target", target); field("cap", cap); field("outcome", (uint64_t)(int64_t)result);
    field("operation", message->operation); field("length", message->length);
    field("request", storage_word(message->payload, 8));
    field("handle", storage_word(message->payload + 8, 8));
    field("offset", storage_word(message->payload + 16, 4));
    field("result", storage_word(message->payload + 20, 4));
    field("data", storage_word(message->payload + 24, 8)); serial_puts("\n");
}

static void wait_event(const char *name, unsigned cell,
                        const struct z_wait_entry *entry)
{
    serial_puts("EVENT "); serial_puts(name);
    field("cell", cell); field("identity", runtime.initialized ? runtime.records[cell].config.identity : manifest.cells[cell].identity);
    field("generation", entry->generation); field("tick", ticks);
    field("kind", entry->kind); field("deadline", entry->deadline);
}

static void trace_wait(unsigned cell)
{
    /* Trace whole pairs and cap volume independently of hostile syscall rates. */
    wait_traced[cell] = wait_events[cell] < 256;
    if (wait_traced[cell]) {
        ++wait_events[cell]; wait_event("wait-arm", cell, &waits.entries[cell]);
        serial_puts("\n");
    }
}

static void cancel_wait(unsigned cell, uint64_t reason)
{
    if (waits.entries[cell].kind != Z_WAIT_NONE && wait_traced[cell]) {
        wait_event("wait-cancel", cell, &waits.entries[cell]);
        field("reason", reason); serial_puts("\n");
    }
    z_wait_cancel(&waits, cell); wait_traced[cell] = false;
}

static bool receive_copy(void *context, unsigned cell, uint64_t generation,
                          uint64_t destination, const struct z_message *message)
{
    (void)context;
    if (cell >= Z_CELL_COUNT || runtime.records[cell].origin == Z_RUNTIME_FREE || broker.policies[cell].phase != Z_POLICY_READY ||
        broker.policies[cell].generation != generation)
        return false;
    if (message == NULL) return arch_cell_copy_valid(cell, destination, sizeof(*message));
    if (!arch_cell_copy_out(cell, destination, message, sizeof(*message))) return false;
    trace_host_ipc(message, cell, z_policy_handle(&broker.policies[cell], cell), 0, Z_OK, true);
    return true;
}

static void complete_waits(void)
{
    for (unsigned cell = 0; cell < Z_CELL_COUNT; ++cell) {
        struct z_wait_entry owned = waits.entries[cell];
        int result;
        enum z_wake_reason reason;
        enum z_wait_status status = z_wait_poll(&waits, &broker, cell, ticks,
                                                receive_copy, NULL, &result, &reason);
        if (status == Z_WAIT_PENDING) continue;
        if (status == Z_WAIT_DONE) {
            frames[cell].rax = (uint64_t)(int64_t)result;
            run_ticks[cell] = 0;
        }
        if (wait_traced[cell]) {
            wait_event(status == Z_WAIT_DONE ? "wake" : "wait-cancel", cell, &owned);
            field("reason", reason); field("result", (uint64_t)(int64_t)result);
            serial_puts("\n");
        }
        wait_traced[cell] = false;
    }
}

static void panic(const char *reason) __attribute__((noreturn));
static void panic(const char *reason)
{
    serial_puts("PANIC "); serial_puts(reason); serial_puts("\n"); arch_finish(2);
}

static void advance_tick(void)
{
    if (ticks == UINT64_MAX) panic("scheduler tick overflow");
    ++ticks;
}

static void load_manifest(void)
{
    images[0] = _binary_block_bin_start;
    images[1] = _binary_filesystem_bin_start;
    images[2] = _binary_client_bin_start;
    images[3] = _binary_probe_bin_start;
    image_lengths[0] = (size_t)(_binary_block_bin_end - _binary_block_bin_start);
    image_lengths[1] = (size_t)(_binary_filesystem_bin_end - _binary_filesystem_bin_start);
    image_lengths[2] = (size_t)(_binary_client_bin_end - _binary_client_bin_start);
    image_lengths[3] = (size_t)(_binary_probe_bin_end - _binary_probe_bin_start);
    images[4] = _binary_supervisor_bin_start;
    images[5] = _binary_worker_bin_start;
    image_lengths[4] = (size_t)(_binary_supervisor_bin_end - _binary_supervisor_bin_start);
    image_lengths[5] = (size_t)(_binary_worker_bin_end - _binary_worker_bin_start);
    static const uint32_t roles[] = { Z_BLOCK, Z_FS, Z_CLIENT, Z_PROBE, Z_SUPERVISOR, Z_WORKER };
    for (unsigned i = 0; i < 6; ++i)
        catalog[i] = (struct z_image_catalog) { i + 1, roles[i], images[i], image_lengths[i], Z_IMAGE_BASE };
    size_t length = (size_t)(_binary_manifest_bin_end - _binary_manifest_bin_start);
    enum z_manifest_error error;
    if (!z_manifest_validate(_binary_manifest_bin_start, length, catalog,
                             sizeof(catalog) / sizeof(catalog[0]), &manifest, &error)) {
        serial_puts("MANIFEST_REJECT reason="); serial_puts(z_manifest_diagnostic(error));
        serial_puts("\n"); arch_finish(3);
    }
    serial_puts("MANIFEST_ACCEPT version=2 cells="); serial_hex(manifest.cell_count);
    serial_puts(" grants="); serial_hex(manifest.grant_count); serial_puts("\n");
}

/* The oracle compares the trusted admitted catalog with the emitted manifest.
 * Catalog identity describes immutable configuration, never caller authority. */
static void trace_contract_catalog(void)
{
    if (Z_SCENARIO != 24) return;
    for (unsigned i = 0; i < manifest.template_count; ++i) {
        const struct z_manifest_template *t = &manifest.templates[i];
        uint16_t stack, heap;
        if (!z_manifest_memory_pages(t->stack_budget, t->writable_budget, &stack, &heap))
            panic("admitted template memory changed");
        serial_puts("EVENT host-template");
        field("template", t->identity); field("image", t->image); field("abi", t->abi);
        field("entry", t->entry); field("image_bytes", image_lengths[t->image - 1]);
        field("image_budget", t->image_budget); field("stack_budget", t->stack_budget);
        field("writable_budget", t->writable_budget); field("pages", stack + heap);
        field("config", t->boot_config); field("restart_limit", t->restart_limit);
        field("restart_delay", t->restart_delay); field("max_depth", t->max_descendant_depth);
        field("template_mask", t->child_template_mask); field("recipe", t->bootstrap_recipe);
        field("reserved", t->reserved); serial_puts("\n");
    }
    for (unsigned i = 0; i < manifest.domain_count; ++i) {
        const struct z_manifest_domain *d = &manifest.domains[i];
        int owner = z_manifest_slot(&manifest, d->owner_identity);
        serial_puts("EVENT host-root-domain");
        field("identity", d->owner_identity); field("cell", (unsigned)owner);
        field("endpoint", z_policy_handle(&broker.policies[owner], (unsigned)owner));
        field("template_mask", d->template_mask); field("slot_limit", d->slot_limit);
        field("page_limit", d->page_limit); field("max_depth", d->max_depth);
        field("recipe", d->bootstrap_recipe); field("reserved0", d->reserved0);
        field("reserved1", d->reserved1); serial_puts("\n");
    }
}

static unsigned role_slot(unsigned role)
{
    static const uint32_t identities[] = { 100, 200, 300, 400 };
    if (role >= sizeof(identities) / sizeof(identities[0])) return Z_CELL_COUNT;
    int slot = z_manifest_slot(&manifest, identities[role]);
    return slot >= 0 ? (unsigned)slot : Z_CELL_COUNT;
}

static void note_boot(unsigned cell)
{
    const struct z_manifest_cell *config = runtime.initialized ? &runtime.records[cell].config : &manifest.cells[cell];
    run_ticks[cell] = 0;
    if (boots[cell] != UINT32_MAX) ++boots[cell];
    event("boot", cell);
    field("image", config->image); field("abi", config->abi);
    field("entry", config->entry); field("image_budget", config->image_budget);
    field("writable_budget", config->writable_budget); field("config", config->boot_config);
    page_fields(cell); serial_puts("\n");
}

static void cold_boot(unsigned cell)
{
    cancel_wait(cell, 68);
    const struct z_manifest_cell *config = &manifest.cells[cell];
    unsigned image = config->image - 1;
    if (!arch_space_reset(cell, images[image], image_lengths[image], config))
        panic("manifest cell memory reset failed");
    arch_frame_init(&frames[cell], cell);
    note_boot(cell);
}

static void fail_cell(unsigned cell, uint64_t reason, uint64_t error, uint64_t address)
{
    cancel_wait(cell, reason);
    event("fault", cell); field("reason", reason); field("error", error);
    field("address", address); serial_puts("\n");
    if (cell < 2) { fault_sends[cell] = sends[cell]; fault_reads[cell] = reads; }
    if (z_runtime_fault(&runtime, cell, ticks, reason) != Z_OK) panic("runtime fault policy rejected live cell");
    run_ticks[cell] = 0;
    if (broker.policies[cell].phase == Z_POLICY_QUARANTINED) {
        arch_space_release(cell);
        event("quarantine", cell); serial_puts("\n");
    }
}

static void supervisor_tick(void)
{
    bool root_changed = false;
    if (Z_SCENARIO == 12 && ticks == 10) __asm__ volatile("ud2");
    if (Z_SOLO < 0 && Z_SCENARIO < 20 && ticks == 20) {
        unsigned block = role_slot(Z_BLOCK);
        if (block < manifest.cell_count) fail_cell(block, 64, 0, 0);
    }
    if (Z_SOLO < 0 && Z_SCENARIO < 20 && ticks == 40) {
        unsigned fs = role_slot(Z_FS);
        if (fs < manifest.cell_count) fail_cell(fs, 64, 0, 0);
    }
    if (Z_SOLO < 0 && Z_SCENARIO == 20 &&
        (storage_stage == 1 || storage_stage == 3) && ticks - storage_checkpoint >= 2) {
        unsigned service = role_slot(storage_stage == 1 ? Z_BLOCK : Z_FS);
        ++storage_stage;
        if (service < manifest.cell_count) fail_cell(service, 64, 0, 0);
    }
    for (unsigned i = 0; i < Z_CELL_COUNT; ++i) {
        if (!z_policy_check(&broker.policies[i])) panic("policy invariant");
        int restarted = z_runtime_poll(&runtime, i, ticks);
        if (restarted < 0) {
            if (restarted != Z_NO_SPACE || broker.policies[i].phase != Z_POLICY_STOPPED ||
                arch_space_pages(i) != 0 || !z_runtime_check(&runtime))
                panic("reserved restart invariant failed");
            event("restart-unavailable", i); field("result", (uint64_t)(int64_t)restarted);
            serial_puts("\n");
            continue;
        }
        if (restarted) {
            note_boot(i);
            if (i < Z_ROOT_COUNT) { root_changed = true; refresh_cell = i; }
        }
    }
    if (root_changed || root_refresh.pending) {
        int result = z_broker_refresh_bounded(&broker, &root_refresh, ticks, root_changed);
        if (result == Z_NO_SPACE && refresh_events < 16) {
            ++refresh_events; event("cap-refresh-unavailable", refresh_cell);
            field("result", (uint64_t)(int64_t)result); field("closed", root_refresh.closed);
            field("deadline", root_refresh.deadline); serial_puts("\n");
        } else if (result != Z_OK && result != Z_AGAIN && result != Z_NO_SPACE)
            panic("static grant refresh invariant failed");
    }
}

static void observe_read(void)
{
    ++reads;
    unsigned client = role_slot(Z_CLIENT);
    if (client < manifest.cell_count && reads <= 128) {
        event("read-verified", client); field("reads", reads); serial_puts("\n");
    }
    if (reads == 1 && client < manifest.cell_count) {
        event("read", client); field("reads", reads); serial_puts("\n");
    }
    for (unsigned i = 0; i < 2; ++i) {
        unsigned service = role_slot(i);
        if (service < manifest.cell_count && !(recovered & (1u << i)) &&
            broker.policies[service].generation == 2 && sends[service] > fault_sends[i] &&
            reads > fault_reads[i]) {
            recovered |= 1u << i;
            event("recovered", service); field("reads", reads); serial_puts("\n");
        }
    }
}

static int64_t hosting_management(struct z_frame *frame)
{
    int result;
    /* Capture the checked caller's actual request before create/rebind can
     * overwrite an overlapping result buffer. No user turn can interleave
     * inside this interrupt-masked, single-CPU management operation. */
    struct z_management_capture capture = {0};
    if (Z_SCENARIO == 24)
        z_runtime_capture_begin(&runtime, current, frame->rax, frame->rdi, frame->rsi, frame->rdx, &capture);
    switch (frame->rax) {
    case Z_CREATE: result = z_runtime_create(&runtime, current, frame->rdi, frame->rsi, frame->rdx); break;
    case Z_CELL_STATUS: result = z_runtime_status(&runtime, current, frame->rdi, frame->rsi, frame->rdx); break;
    case Z_CELL_STOP:
        result = frame->rsi || frame->rdx ? Z_INVALID : z_runtime_stop(&runtime, current, frame->rdi); break;
    case Z_CELL_REAP:
        result = frame->rsi || frame->rdx ? Z_INVALID : z_runtime_reap(&runtime, current, frame->rdi); break;
    case Z_CELL_REBIND: result = z_runtime_rebind(&runtime, current, frame->rdi, frame->rsi, frame->rdx); break;
    case Z_CREATION_REVOKE:
        result = frame->rsi || frame->rdx ? Z_INVALID : z_runtime_revoke(&runtime, current, frame->rdi); break;
    case Z_DOMAIN_STATUS: result = z_runtime_domain_status(&runtime, current, frame->rdi, frame->rsi, frame->rdx); break;
    default: return Z_INVALID;
    }
    if (Z_SCENARIO == 24)
        z_runtime_capture_end(&runtime, current, frame->rax, frame->rdi, frame->rsi, frame->rdx, result, &capture);
    if (Z_SCENARIO >= 21 && Z_SCENARIO <= 24 && hosting_trace_credit()) {
        event("host-call", current); field("caller_endpoint", z_policy_handle(&broker.policies[current], current));
        field("call", frame->rax); field("arg0", frame->rdi); field("arg1", frame->rsi); field("arg2", frame->rdx);
        field("result", (uint64_t)(int64_t)result);
        if (Z_SCENARIO == 24) {
            if (frame->rax == Z_CREATE || frame->rax == Z_CELL_REBIND) {
                field("input_copied", capture.input_copied);
                if (frame->rax == Z_CREATE) {
                    field("input_authority", capture.input.create.authority); field("input_request", capture.input.create.request);
                    field("input_template", capture.input.create.template_id); field("input_slots", capture.input.create.descendant_slots);
                    field("input_pages", capture.input.create.descendant_pages); field("input_reserved", capture.input.create.reserved);
                } else {
                    field("input_authority", capture.input.rebind.authority); field("input_control", capture.input.rebind.control);
                    field("input_request", capture.input.rebind.request); field("input_reserved", capture.input.rebind.reserved);
                }
                const struct z_create_result copied = capture.output.create;
                field("output_copied", capture.output_copied);
                field("output_instance", copied.instance); field("output_control", copied.control);
                field("output_endpoint", copied.endpoint); field("output_channel", copied.channel);
                field("output_creation", copied.creation); field("output_slot", copied.slot);
                field("output_identity", copied.identity);
            } else if (frame->rax == Z_CELL_STATUS) {
                const struct z_cell_status copied = capture.output.status;
                field("output_copied", capture.output_copied);
                field("output_instance", copied.instance); field("output_control", copied.control);
                field("output_endpoint", copied.endpoint); field("output_domain", copied.domain);
                field("output_parent_instance", copied.parent_instance); field("output_parent_endpoint", copied.parent_endpoint);
                field("output_generation", copied.generation); field("output_slot", copied.slot);
                field("output_template", copied.template_id); field("output_depth", copied.depth);
                field("output_phase", copied.phase); field("output_faults", copied.faults);
                field("output_restarts", copied.restarts); field("output_reason", copied.reason);
                field("output_own_pages", copied.own_pages); field("output_reserved_slots", copied.reserved_slots);
                field("output_reserved_pages", copied.reserved_pages); field("output_available_slots", copied.available_slots);
                field("output_available_pages", copied.available_pages);
            } else if (frame->rax == Z_DOMAIN_STATUS) {
                const struct z_domain_status copied = capture.output.domain;
                field("output_copied", capture.output_copied);
                field("output_domain", copied.domain); field("output_holder", copied.holder);
                field("output_instance", copied.instance); field("output_slot_limit", copied.slot_limit);
                field("output_page_limit", copied.page_limit); field("output_owned_slots", copied.owned_slots);
                field("output_owned_pages", copied.owned_pages); field("output_reserved_slots", copied.reserved_slots);
                field("output_reserved_pages", copied.reserved_pages); field("output_available_slots", copied.available_slots);
                field("output_available_pages", copied.available_pages); field("output_max_depth", copied.max_depth);
                field("output_template_mask", copied.template_mask); field("output_recipe", copied.recipe);
                field("output_revoked", copied.revoked);
            }
        }
        serial_puts("\n");
    }
    return result;
}

static int hosting_report(struct z_frame *frame)
{
    if (hosting_reports >= 256 || !hosting_trace_credit()) return Z_TOO_LARGE;
    unsigned code = (unsigned)frame->rdi;
    unsigned role = runtime.records[current].role;
    bool dynamic = runtime.records[current].origin == Z_RUNTIME_CHILD;
    bool contract_broker = Z_SCENARIO == 24 && dynamic && role == Z_SUPERVISOR &&
        runtime.records[current].template_id == 3;
    bool controller = runtime.records[current].origin == Z_RUNTIME_ROOT &&
        runtime.records[current].config.identity == 400;
    bool client = runtime.records[current].origin == Z_RUNTIME_ROOT &&
        runtime.records[current].config.identity == 300;
    const char *name = NULL;
    switch (code) {
    case 40:
        if (!dynamic || frame->rsi != z_policy_handle(&broker.policies[current], current) ||
            frame->rdx != runtime.records[current].instance) return Z_DENIED;
        name = "host-entry"; break;
    case 41: {
        uint64_t stack, heap;
        if (!dynamic || !arch_cell_copy_in(current, &stack, Z_STACK_BASE + 64, sizeof(stack)) ||
            !arch_cell_copy_in(current, &heap, Z_WRITABLE_BASE, sizeof(heap)) ||
            stack != 0 || heap != 0 || frame->rsi != stack || frame->rdx != heap) return Z_DENIED;
        name = "host-cold"; break;
    }
    case 42: {
        uint64_t heap[2];
        if (!dynamic || !arch_cell_copy_in(current, heap, Z_WRITABLE_BASE, sizeof(heap)) ||
            frame->rsi != heap[0] || frame->rdx != heap[1]) return Z_DENIED;
        name = "host-memory"; break;
    }
    case 43: if (!dynamic) return Z_DENIED; name = "host-computed"; break;
    case 44: if (!controller) return Z_DENIED; name = "host-verified"; break;
    case 45: if (role != Z_SUPERVISOR || !dynamic) return Z_DENIED; name = "host-nested-verified"; break;
    case 46: if (role != Z_WORKER || !dynamic) return Z_DENIED; name = "host-sleep-start"; break;
    case 47: if (role != Z_WORKER || !dynamic) return Z_DENIED; name = "host-sleep-return"; break;
    case 48: if (role != Z_WORKER || !dynamic) return Z_DENIED; name = "host-timeout"; break;
    case 49: if (!dynamic) return Z_DENIED; name = "host-storage-denied"; break;
    case 50: if (!controller) return Z_DENIED; name = "host-rebound"; break;
    case 51: if (!controller && !contract_broker) return Z_DENIED; name = "host-stale"; break;
    case 52: if (!controller) return Z_DENIED; name = "host-denied"; break;
    case 53: if (!controller && role != Z_SUPERVISOR) return Z_DENIED; name = "host-ledger"; break;
    case 54: if (!controller) return Z_DENIED; name = "host-fifo"; break;
    case 55: if (!controller && !contract_broker) return Z_DENIED; name = "host-reaped"; break;
    case 56:
        if (!controller || frame->rsi != Z_SCENARIO || frame->rdx != 0) return Z_DENIED;
        hosting_complete = true; name = "host-complete"; break;
    case 57: if (!dynamic) return Z_DENIED; name = "host-copied"; break;
    case 58: if (role != Z_SUPERVISOR || !dynamic) return Z_DENIED; name = "host-backoff-observed"; break;
    case 59: if (!controller) return Z_DENIED; name = "host-probe-verified"; break;
    case 70: case 71: case 72: case 73: case 74: case 75: case 76:
    case 77: case 78: case 79: case 80: case 81: case 82: case 83: case 86: {
        static const char *const contract_names[] = {
            "contract-offer", "contract-input", "contract-worker", "contract-control",
            "contract-endpoint", "contract-accepted", "contract-dispatch", "contract-attempt",
            "contract-validated", "contract-terminal", "contract-reaped", "contract-late-rejected",
            "contract-recovering", "contract-rebound",
        };
        if (!contract_broker) return Z_DENIED;
        name = code == 86 ? "contract-deferred" : contract_names[code - 70]; break;
    }
    case 84:
        if (Z_SCENARIO != 24 || !controller) return Z_DENIED;
        name = "contract-requester-verified"; break;
    case 87:
        if (Z_SCENARIO != 24 || !controller || frame->rsi == 0 ||
            (frame->rdx != 1 && frame->rdx != 5)) return Z_DENIED;
        name = "contract-reply-lost"; break;
    case 85:
        if (Z_SCENARIO != 24 || !controller || frame->rsi != 24 || frame->rdx != 0)
            return Z_DENIED;
        hosting_complete = true; name = "contract-complete"; break;
    case 64:
        if (!client || frame->rsi == 0 || frame->rdx == 0 || frame->rsi == frame->rdx) return Z_DENIED;
        hosting_storage_ready = true; name = "hosting-storage-ready"; break;
    case 65:
        if (!client || !hosting_storage_ready || frame->rdx != 7 || frame->rsi != hosting_storage_cycles)
            return Z_DENIED;
        if (hosting_storage_cycles == UINT64_MAX) return Z_NO_SPACE;
        if (hosting_last_cleanup_tick && hosting_cycle_boundary_tick >= hosting_last_cleanup_tick)
            hosting_post_cleanup_verified = true;
        hosting_cycle_boundary_tick = ticks;
        ++hosting_storage_cycles; name = "hosting-storage-cycle"; break;
    default: return Z_INVALID;
    }
    ++hosting_reports;
    event(name, current); field("value", frame->rsi); field("extra", frame->rdx);
    field("endpoint", z_policy_handle(&broker.policies[current], current));
    field("instance", runtime.records[current].instance);
    field("template", runtime.records[current].template_id); field("depth", runtime.records[current].depth);
    field("parent_endpoint", runtime.records[current].parent_endpoint);
    serial_puts("\n"); return Z_OK;
}

static int64_t syscall(struct z_frame *frame)
{
    struct z_message message;
    uint64_t argument = frame->rdi;
    switch (frame->rax) {
    case Z_CREATE: case Z_CELL_STATUS: case Z_CELL_STOP: case Z_CELL_REAP:
    case Z_CELL_REBIND: case Z_CREATION_REVOKE: case Z_DOMAIN_STATUS:
        return hosting_management(frame);
    case Z_YIELD: return Z_OK;
    case Z_SLEEP: {
        int result = z_wait_sleep(&waits, &broker, current, ticks, argument);
        if (result == Z_OK && argument) trace_wait(current);
        return result;
    }
    case Z_RECV_WAIT: {
        bool blocked;
        int result = z_wait_receive(&waits, &broker, current, ticks, frame->rsi,
                                     argument, receive_copy, NULL, &blocked);
        if (blocked) trace_wait(current);
        return result;
    }
    case Z_SEND:
        if (!arch_user_range(frame->rsi, sizeof(message), false)) return Z_BAD_ADDRESS;
        arch_user_copy_in(&message, frame->rsi, sizeof(message));
        {
            int result = z_broker_send(&broker, current, argument, frame->rdx, &message);
            if (result == Z_OK && sends[current] != UINT64_MAX) ++sends[current];
            message.sender = z_policy_handle(&broker.policies[current], current);
            trace_host_ipc(&message, current, argument, frame->rdx, result, false);
            trace_storage(&message, argument, frame->rdx, result);
            return result;
        }
    case Z_RECV:
        return z_broker_receive_checked(&broker, current, argument, receive_copy, NULL);
    case Z_LOOKUP: {
        int target = z_manifest_slot(&manifest, (uint32_t)argument);
        if (target < 0 || manifest.cells[target].identity != argument) return Z_INVALID;
        return z_broker_lookup(&broker, current, (unsigned)target);
    }
    case Z_BOOT:
        if (!arch_user_range(argument, sizeof(struct z_boot_info), true)) return Z_BAD_ADDRESS;
        { struct z_boot_info info;
          int result = z_runtime_boot(&runtime, current, &info);
          if (result == Z_OK) arch_user_copy_out(argument, &info, sizeof(info));
          return result; }

    case Z_CAP_FIND:
        if (frame->rsi > UINT32_MAX) return Z_INVALID;
        return z_broker_find(&broker, current, argument, (uint32_t)frame->rsi);
    case Z_CAP_DELEGATE:
        if (!arch_user_range(argument, sizeof(struct z_cap_request), false)) return Z_BAD_ADDRESS;
        { struct z_cap_request request;
          arch_user_copy_in(&request, argument, sizeof(request));
          if (request.reserved) return Z_INVALID;
          struct z_cap_info parent_info;
          if (z_broker_query(&broker, current, request.parent, &parent_info) != Z_OK)
              return Z_DENIED;
          int64_t grant = z_broker_delegate(&broker, current, request.parent,
                                             request.holder, request.rights);
          if (grant > 0) {
              event("cap-delegate", current); field("holder", request.holder);
              field("target", parent_info.target); field("rights", request.rights);
              field("cap", (uint64_t)grant); field("parent", request.parent); serial_puts("\n");
          }
          return grant; }
    case Z_CAP_QUERY:
        if (!arch_user_range(frame->rsi, sizeof(struct z_cap_info), true)) return Z_BAD_ADDRESS;
        { struct z_cap_info info;
          int result = z_broker_query(&broker, current, argument, &info);
          if (result == Z_OK) arch_user_copy_out(frame->rsi, &info, sizeof(info));
          return result; }
    case Z_CAP_REVOKE: {
        int result = z_broker_revoke_cap(&broker, current, argument);
        if (result == Z_OK) {
            event("cap-revoke", current); field("cap", argument); serial_puts("\n");
        }
        return result;
    }
    case Z_REPORT:
        if (Z_SCENARIO >= 21 && Z_SCENARIO <= 24 &&
            ((argument >= 40 && argument <= 59) || argument == 64 || argument == 65 ||
             (Z_SCENARIO == 24 && argument >= 70 && argument <= 87)))
            return hosting_report(frame);
        if (argument == 7 && runtime.records[current].role == Z_PROBE) {
            ++reset_reports; event("reset-memory", current); serial_puts("\n"); return Z_OK;
        }
        if (argument == 1 && runtime.records[current].role == Z_CLIENT) {
            observe_read(); return Z_OK;
        }
        if (argument == 2 && runtime.records[current].role == Z_PROBE &&
            (Z_SCENARIO == 7 || Z_SCENARIO == 8 || Z_SCENARIO == 15 || Z_SCENARIO == 20)) {
            contract_ok = true; event("contract", current); serial_puts("\n"); return Z_OK;
        }
        if (argument == 8 && runtime.records[current].role == Z_CLIENT) {
            event("healthy-memory", current); field("stack", frame->rsi);
            field("writable", frame->rdx); serial_puts("\n"); return Z_OK;
        }
        if (argument == 9 && runtime.records[current].role == Z_CLIENT) {
            event("demo-allowed", current); field("cap", frame->rsi);
            field("parent", frame->rdx); serial_puts("\n"); return Z_OK;
        }
        if (argument == 10 && runtime.records[current].role == Z_CLIENT) {
            event("demo-revoked", current); field("cap", frame->rsi);
            field("endpoint", frame->rdx); serial_puts("\n"); return Z_OK;
        }
        if (argument == 11 && runtime.records[current].role == Z_CLIENT) {
            event("demo-rebind", current); field("old", frame->rsi);
            field("endpoint", frame->rdx); serial_puts("\n"); return Z_OK;
        }
        if (argument == 12 && runtime.records[current].role == Z_CLIENT) {
            event("demo-forbidden", current); field("rights", frame->rsi);
            field("result", frame->rdx); serial_puts("\n"); return Z_OK;
        }
        if (argument == 13 && runtime.records[current].role == Z_CLIENT) {
            event("demo-resumed", current); field("reads", reads); serial_puts("\n"); return Z_OK;
        }
        if (Z_SCENARIO == 19 && argument == 14 && runtime.records[current].role == Z_CLIENT) {
            event("wait-progress", current); field("reads", reads); serial_puts("\n"); return Z_OK;
        }
        if (Z_SCENARIO == 19 && argument == 15 && runtime.records[current].role == Z_PROBE) {
            event("wait-delivered", current); field("sender", frame->rsi);
            field("value", frame->rdx); serial_puts("\n"); return Z_OK;
        }
        if (Z_SCENARIO == 19 && argument == 16 && runtime.records[current].role == Z_PROBE) {
            contract_ok = frame->rsi == 7 && frame->rdx == 3;
            event("wait-contract", current); field("checks", frame->rsi);
            field("duration", frame->rdx); serial_puts("\n"); return Z_OK;
        }
        if ((argument == 30 && runtime.records[current].role == Z_BLOCK) ||
            (argument == 31 && runtime.records[current].role == Z_FS)) {
            if (!storage_trace_credit(&storage_reports)) return Z_TOO_LARGE;
            event(argument == 30 ? "storage-block" : "storage-fs", current);
            field("request", frame->rsi); field("operation", frame->rdx >> 32);
            field("result", frame->rdx & UINT32_MAX); serial_puts("\n"); return Z_OK;
        }
        if (argument >= 32 && argument <= 36 && runtime.records[current].role == Z_CLIENT) {
            if (!storage_trace_credit(&storage_reports)) return Z_TOO_LARGE;
            if (argument == 32) {
                event("storage-verified", current); field("request", frame->rsi);
                field("data", frame->rdx);
            } else if (argument == 33) {
                event("storage-stale", current); field("request", frame->rsi);
                field("handle", frame->rdx);
            } else if (argument == 34) {
                event("storage-denied", current); field("request", frame->rsi);
                field("result", frame->rdx);
            } else if (argument == 35) {
                if (Z_SCENARIO != 20 || !((frame->rsi == 1 && storage_stage == 0) ||
                    (frame->rsi == 2 && storage_stage == 2))) return Z_INVALID;
                ++storage_stage; storage_checkpoint = ticks;
                event("storage-checkpoint", current); field("phase", frame->rsi);
            } else {
                if (Z_SCENARIO != 20 || storage_stage != 4) return Z_INVALID;
                storage_done = true; event("storage-complete", current);
            }
            serial_puts("\n"); return Z_OK;
        }
        if (argument == 37 && runtime.records[current].role == Z_FS) {
            if (!storage_trace_credit(&storage_reports)) return Z_TOO_LARGE;
            event("storage-link", current); field("request", frame->rsi);
            field("block_request", frame->rdx); serial_puts("\n"); return Z_OK;
        }
        if (argument == 38 && runtime.records[current].role == Z_CLIENT) {
            if (!storage_trace_credit(&storage_reports)) return Z_TOO_LARGE;
            event("storage-rebind", current); field("old", frame->rsi);
            field("endpoint", frame->rdx); serial_puts("\n"); return Z_OK;
        }
        if (argument == (uint64_t)runtime.records[current].role + 3) {
            event("entry", current); serial_puts("\n"); return Z_OK;
        }
        event("bad-report", current); field("code", argument); serial_puts("\n");
        fail_cell(current, 66, 0, 0); return Z_INVALID;
    case Z_EXIT:
        cancel_wait(current, 67);
        if (z_runtime_exit(&runtime, current) != Z_OK) panic("runtime exit policy rejected live cell");
        event("exit", current); serial_puts("\n");
        if (Z_SCENARIO == 19 && Z_SOLO == 3 && Z_TEST) {
            serial_puts(contract_ok ? "RESEARCH_PASS" : "RESEARCH_FAIL");
            field("scenario", Z_SCENARIO); field("reads", reads); field("tick", ticks);
            serial_puts("\n"); arch_finish(contract_ok ? 0 : 1);
        }
        return Z_OK;
    default: return Z_INVALID;
    }
}

static void research_check(void)
{
    if (Z_SCENARIO >= 21 && Z_SCENARIO <= 24) {
        if (finished || !hosting_complete || hosting_storage_cycles < 2 || !hosting_post_cleanup_verified) return;
        bool pass = hosting_storage_ready && hosting_events <= 2048 && hosting_reports < 256 &&
            storage_events <= storage_trace_limit() && storage_reports <= storage_trace_limit() &&
            z_runtime_check(&runtime);
        for (unsigned i = 0; i < Z_ROOT_COUNT; ++i)
            pass = pass && runtime.records[i].origin == Z_RUNTIME_ROOT &&
                broker.policies[i].phase == Z_POLICY_READY && broker.policies[i].generation == 1 &&
                broker.policies[i].faults == 0 && boots[i] == 1;
        for (unsigned i = Z_ROOT_COUNT; i < Z_CELL_COUNT; ++i)
            pass = pass && runtime.records[i].origin == Z_RUNTIME_FREE && arch_space_pages(i) == 0;
        serial_puts(pass ? "RESEARCH_PASS" : "RESEARCH_FAIL");
        field("scenario", Z_SCENARIO); field("cycles", hosting_storage_cycles); field("tick", ticks);
        serial_puts("\n"); finished = true;
        if (!pass || Z_TEST) arch_finish(pass ? 0 : 1);
        return;
    }
    if (finished || ticks < (Z_SCENARIO == 20 ? 400u : 120u) || Z_SOLO >= 0) return;
    unsigned block = role_slot(Z_BLOCK), fs = role_slot(Z_FS), client = role_slot(Z_CLIENT);
    unsigned probe = role_slot(Z_PROBE);
    bool probe_ok = probe < manifest.cell_count &&
        broker.policies[probe].phase == Z_POLICY_QUARANTINED;
    if (probe < manifest.cell_count && (Z_SCENARIO == 7 || Z_SCENARIO == 8 || Z_SCENARIO == 15 || Z_SCENARIO == 19 || Z_SCENARIO == 20))
        probe_ok = broker.policies[probe].phase == Z_POLICY_STOPPED && contract_ok;
    else if (probe < manifest.cell_count)
        probe_ok = probe_ok && broker.policies[probe].faults == 4 && boots[probe] == 4;
    bool pass = block < manifest.cell_count && fs < manifest.cell_count && client < manifest.cell_count &&
        probe < manifest.cell_count && recovered == 3 && reads > 2 && probe_ok &&
        reset_reports == boots[probe] && broker.policies[block].phase == Z_POLICY_READY &&
        broker.policies[fs].phase == Z_POLICY_READY && broker.policies[client].faults == 0 &&
        boots[client] == 1 && (Z_SCENARIO != 20 || storage_done);
    serial_puts(pass ? "RESEARCH_PASS" : "RESEARCH_FAIL");
    field("scenario", Z_SCENARIO); field("reads", reads); field("tick", ticks); serial_puts("\n");
    finished = true;
    if (!pass || Z_TEST) arch_finish(pass ? 0 : 1);
}

static struct z_frame *schedule(void)
{
    for (;;) {
        complete_waits();
        int next = z_wait_next(&waits, &broker, current);
        if (next >= 0) {
            current = (unsigned)next; arch_activate(current); return &frames[current];
        }
        uint64_t entered = ticks;
        bool traced = idle_events < 16;
        if (traced) { ++idle_events; event("idle-enter", current); serial_puts("\n"); }
        /* No runnable test and HLT are serialized with interrupts masked.
         * STI's interrupt shadow closes the enable-to-halt lost interrupt gap. */
        __asm__ volatile("sti; hlt; cli" ::: "memory");
        if (traced) {
            event("idle-wake", current); field("entered", entered); field("reason", 6);
            serial_puts("\n");
        }
        supervisor_tick(); research_check();
    }
}

struct z_frame *kernel_trap(struct z_frame *frame)
{
    if ((frame->cs & 3) != 3) {
        if (frame->vector == 32) { advance_tick(); arch_eoi(); return frame; }
        serial_puts("KERNEL_FAULT"); field("vector", frame->vector);
        field("rip", frame->rip); serial_puts("\n"); panic("trusted kernel fault");
    }
    frames[current] = *frame;
    if (frame->cs != 0x1b || frame->ss != 0x23 ||
        !z_canonical_address(frame->rip) || !z_canonical_address(frame->rsp)) {
        if (frame->vector == 32) { advance_tick(); arch_eoi(); supervisor_tick(); }
        fail_cell(current, 69, 0, frame->rsp); return schedule();
    }
    /* Observe a hardware trap from the first actual ring-3 turn of each
     * contract execution. This is separate from application progress reports
     * and from a prepared frame that has not yet entered user mode. */
    if (Z_SCENARIO == 24 && runtime.records[current].origin == Z_RUNTIME_CHILD &&
        contract_entry_generation[current] != broker.policies[current].generation) {
        contract_entry_generation[current] = broker.policies[current].generation;
        if (hosting_trace_credit()) {
            event("host-kernel-entry", current);
            field("endpoint", z_policy_handle(&broker.policies[current], current));
            field("instance", runtime.records[current].instance);
            field("control", runtime.records[current].control);
            field("template", runtime.records[current].template_id);
            field("depth", runtime.records[current].depth);
            field("parent_endpoint", runtime.records[current].parent_endpoint);
            field("cs", frame->cs); field("ss", frame->ss); field("rip", frame->rip);
            field("rsp", frame->rsp); field("rflags", frame->flags); field("vector", frame->vector);
            serial_puts("\n");
        }
    }
    frames[current].flags = (frame->flags | UINT64_C(0x202)) & ~UINT64_C(0x27000);
    if (frame->vector == 32) {
        advance_tick(); arch_eoi(); if (++run_ticks[current] >= 5) fail_cell(current, 65, 0, 0);
        supervisor_tick(); research_check();
    } else if (frame->vector == 128) {
        run_ticks[current] = 0; frames[current].rax = (uint64_t)syscall(frame);
    } else if (frame->vector < 32) {
        fail_cell(current, frame->vector, frame->error,
                  frame->vector == 14 ? arch_fault_address() : 0);
    } else panic("unexpected interrupt");
    return schedule();
}

void kernel_main(void)
{
    serial_init(); serial_puts("ZEAL boot abi=4 x86_64\n");
    arch_init(); load_manifest(); z_broker_init(&broker);
    z_wait_init(&waits);
    z_broker_refresh_state_init(&root_refresh);
    for (unsigned i = manifest.cell_count; i < Z_CELL_COUNT; ++i)
        broker.policies[i] = (struct z_policy_state){ .phase = Z_POLICY_DORMANT };
    struct z_boot_grant grants[Z_MANIFEST_GRANT_MAX];
    for (unsigned i = 0; i < manifest.grant_count; ++i) {
        int holder = z_manifest_slot(&manifest, manifest.grants[i].holder);
        int target = z_manifest_slot(&manifest, manifest.grants[i].target);
        if (holder < 0 || target < 0) panic("manifest grant slot resolution failed");
        grants[i] = (struct z_boot_grant) { (uint32_t)holder, (uint32_t)target,
                                             manifest.grants[i].rights, 0 };
    }
    if (z_broker_configure(&broker, grants, manifest.grant_count) != Z_OK)
        panic("manifest initial grants rejected");
    unsigned active_count = 0;
    for (unsigned i = 0; i < manifest.cell_count; ++i) {
        if (!(manifest.cells[i].flags & Z_MANIFEST_ACTIVE)) {
            broker.policies[i] = (struct z_policy_state){ .phase = Z_POLICY_DORMANT };
            continue;
        }
        if (Z_SOLO >= 0 && i != (unsigned)Z_SOLO) {
            broker.policies[i] = (struct z_policy_state){ .phase = Z_POLICY_DORMANT };
            continue;
        }
        if (!arch_space_init(i, images[manifest.cells[i].image - 1],
                             image_lengths[manifest.cells[i].image - 1], &manifest.cells[i])) {
            serial_puts("MANIFEST_REJECT reason=cell memory allocation cell="); serial_hex(i);
            serial_puts("\n"); arch_finish(3);
        }
        cold_boot(i); ++active_count;
    }
    if (!active_count || z_broker_refresh(&broker) != Z_OK) panic("empty boot or initial authority failure");
    if (z_runtime_init(&runtime, &broker, &waits, frames, &manifest, catalog,
                         sizeof(catalog) / sizeof(catalog[0]), &runtime_callbacks, NULL) != Z_OK ||
        !z_runtime_check(&runtime)) panic("runtime registry initialization failed");
    trace_contract_catalog();
    current = role_slot(Z_SOLO >= 0 ? (unsigned)Z_SOLO : Z_BLOCK);
    if (current >= manifest.cell_count || broker.policies[current].phase != Z_POLICY_READY)
        panic("standalone selection is not active");
    arch_activate(current); arch_enter(&frames[current]);
}
