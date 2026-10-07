#include <stddef.h>
#include <zeal/hosting.h>

_Static_assert(sizeof(struct z_host_request) == sizeof(struct z_create_request),
               "checked creation request layout");
_Static_assert(sizeof(struct z_host_status) == sizeof(struct z_cell_status),
               "checked status layout");

static uint64_t principal(const struct z_runtime *runtime, unsigned cell)
{
    return runtime != NULL && runtime->initialized && cell < Z_CELL_COUNT &&
        runtime->records[cell].origin != Z_RUNTIME_FREE ?
        z_policy_handle(&runtime->broker->policies[cell], cell) : 0;
}

static const struct z_image_catalog *image(const struct z_runtime *runtime,
                                           uint32_t identity)
{
    for (size_t i = 0; i < runtime->catalog_count; ++i)
        if (runtime->catalog[i].identity == identity) return &runtime->catalog[i];
    return NULL;
}

static const struct z_manifest_template *template(const struct z_runtime *runtime,
                                                  uint32_t identity)
{
    for (unsigned i = 0; i < runtime->manifest->template_count; ++i)
        if (runtime->manifest->templates[i].identity == identity)
            return &runtime->manifest->templates[i];
    return NULL;
}

static void trace(struct z_runtime *runtime, enum z_runtime_event_kind kind,
                   unsigned caller, unsigned cell, uint64_t request, int result,
                   const struct z_host_transaction *transaction,
                   const struct z_runtime_record *record,
                   uint64_t parent_cap, uint64_t child_cap,
                   const struct z_wait_entry *wait, unsigned queued, unsigned pages)
{
    if (runtime->callbacks->trace == NULL) return;
    struct z_runtime_event event = {
        .kind = kind, .caller = caller, .cell = cell, .result = result,
        .caller_endpoint = caller < Z_CELL_COUNT ?
            (runtime->broker->policies[caller].generation << 8) | (caller + 1) : 0,
        .request = request,
        .parent_cap = parent_cap, .child_cap = child_cap,
        .queued = queued, .retired_pages = pages,
    };
    if (record != NULL) event.record = *record;
    else if (cell < Z_CELL_COUNT) event.record = runtime->records[cell];
    if (transaction != NULL) {
        event.transaction = *transaction;
        if (transaction->parent_endpoint) event.caller_endpoint = transaction->parent_endpoint;
    }
    if (wait != NULL) event.wait = *wait;
    runtime->callbacks->trace(runtime->context, &event);
}

static int control_slot(const struct z_runtime *runtime, uint64_t control)
{
    if (control == 0) return -1;
    for (unsigned i = Z_ROOT_COUNT; i < Z_CELL_COUNT; ++i)
        if (runtime->records[i].origin == Z_RUNTIME_CHILD &&
            runtime->records[i].control == control) return (int)i;
    return -1;
}

static struct z_manifest_cell configuration(const struct z_manifest_template *sealed,
                                             uint32_t identity)
{
    return (struct z_manifest_cell) {
        .identity = identity, .image = sealed->image, .abi = sealed->abi,
        .flags = Z_MANIFEST_ACTIVE, .entry = sealed->entry,
        .image_budget = sealed->image_budget, .stack_budget = sealed->stack_budget,
        .writable_budget = sealed->writable_budget, .boot_config = sealed->boot_config,
        .restart_limit = sealed->restart_limit, .restart_delay = sealed->restart_delay,
        .name = { 'r', 'u', 'n', 't', 'i', 'm', 'e', 0 },
    };
}

int z_runtime_init(struct z_runtime *runtime, struct z_broker *broker,
                    struct z_wait_table *waits, struct z_frame *frames,
                    const struct z_manifest *manifest,
                    const struct z_image_catalog *catalog, size_t catalog_count,
                    const struct z_runtime_callbacks *callbacks, void *context)
{
    if (runtime == NULL || broker == NULL || waits == NULL || frames == NULL ||
        manifest == NULL || catalog == NULL || catalog_count == 0 ||
        catalog_count > Z_MANIFEST_IMAGE_COUNT_MAX || callbacks == NULL ||
        callbacks->range == NULL || callbacks->copy_in == NULL || callbacks->copy_out == NULL ||
        callbacks->space_init == NULL || callbacks->space_reset == NULL ||
        callbacks->space_release == NULL || callbacks->frame_init == NULL ||
        callbacks->space_pages == NULL || callbacks->memory_check == NULL ||
        manifest->cell_count > Z_ROOT_COUNT || manifest->template_count > Z_HOST_TEMPLATES ||
        manifest->domain_count > Z_HOST_DOMAINS) return Z_INVALID;
    *runtime = (struct z_runtime) {
        .broker = broker, .waits = waits, .frames = frames, .manifest = manifest,
        .catalog = catalog, .catalog_count = catalog_count,
        .callbacks = callbacks, .context = context, .next_identity = 1000,
    };
    unsigned root_mask = 0, root_pages = 0;
    for (unsigned i = 0; i < manifest->cell_count; ++i) {
        unsigned pages = callbacks->space_pages(context, i);
        const struct z_image_catalog *approved = image(runtime, manifest->cells[i].image);
        if (approved == NULL || approved->role > Z_PROBE) return Z_INVALID;
        runtime->records[i] = (struct z_runtime_record) {
            .config = manifest->cells[i], .origin = Z_RUNTIME_ROOT,
            .published = broker->policies[i].phase == Z_POLICY_READY,
            .parent_slot = UINT32_MAX, .allocated_pages = pages,
            .role = approved->role,
        };
        if (broker->policies[i].phase == Z_POLICY_READY) {
            uint16_t stack, heap;
            if (!z_manifest_memory_pages(manifest->cells[i].stack_budget,
                                           manifest->cells[i].writable_budget, &stack, &heap) ||
                pages != (unsigned)stack + heap || root_pages > Z_HOST_PAGES - pages)
                return Z_INVALID;
            root_mask |= 1u << i; root_pages += pages;
        } else if (pages != 0) return Z_INVALID;
    }
    z_host_init(&runtime->hierarchy, root_mask, root_pages);
    struct z_host_template templates[Z_HOST_TEMPLATES] = {0};
    struct z_host_root roots[Z_HOST_DOMAINS] = {0};
    for (unsigned i = 0; i < manifest->template_count; ++i) {
        const struct z_manifest_template *sealed = &manifest->templates[i];
        uint16_t stack, heap;
        const struct z_image_catalog *approved = image(runtime, sealed->image);
        if (approved == NULL || approved->data == NULL || approved->length == 0 ||
            approved->length > sealed->image_budget || approved->role < Z_SUPERVISOR ||
            approved->role > Z_WORKER || sealed->abi != Z_ABI_VERSION ||
            sealed->entry != Z_IMAGE_BASE || approved->entry != sealed->entry ||
            !z_manifest_memory_pages(sealed->stack_budget, sealed->writable_budget, &stack, &heap))
            return Z_INVALID;
        templates[i] = (struct z_host_template) {
            .identity = sealed->identity, .pages = (uint32_t)stack + heap,
            .max_descendant_depth = sealed->max_descendant_depth,
            .child_template_mask = sealed->child_template_mask,
            .bootstrap_recipe = sealed->bootstrap_recipe,
        };
    }
    for (unsigned i = 0; i < manifest->domain_count; ++i) {
        const struct z_manifest_domain *domain = &manifest->domains[i];
        int owner = z_manifest_slot(manifest, domain->owner_identity);
        if (owner < 0) return Z_INVALID;
        roots[i] = (struct z_host_root) {
            .slot = (uint32_t)owner, .template_mask = domain->template_mask,
            .slot_limit = domain->slot_limit, .page_limit = domain->page_limit,
            .max_depth = domain->max_depth, .bootstrap_recipe = domain->bootstrap_recipe,
        };
    }
    int result = z_host_configure(&runtime->hierarchy, broker->policies, templates,
                                   manifest->template_count, roots, manifest->domain_count);
    if (result != Z_OK) return result;
    runtime->initialized = 1;
    return Z_OK;
}

static void abort_creation(struct z_runtime *runtime, unsigned caller,
                            const struct z_host_transaction *transaction,
                            uint64_t parent_cap, uint64_t child_cap, int result)
{
    unsigned cell = transaction->slot;
    struct z_runtime_record record = runtime->records[cell];
    z_caps_drop_channel(&runtime->broker->capabilities, parent_cap, child_cap);
    z_wait_cancel(runtime->waits, cell);
    runtime->broker->queues[cell] = (struct z_queue){0};
    runtime->callbacks->space_release(runtime->context, cell);
    z_host_abort(&runtime->hierarchy, transaction->transaction);
    runtime->records[cell] = (struct z_runtime_record){0};
    runtime->frames[cell] = (struct z_frame){0};
    trace(runtime, Z_RUNTIME_ABORT, caller, cell, transaction->request_id, result,
            transaction, &record, parent_cap, child_cap, NULL, 0, record.allocated_pages);
}

int z_runtime_create(struct z_runtime *runtime, unsigned caller,
                      uint64_t input, size_t length, uint64_t output)
{
    uint64_t owner = principal(runtime, caller);
    if (owner == 0) return Z_AGAIN;
    if (length != sizeof(struct z_create_request)) return Z_INVALID;
    if (!runtime->callbacks->range(runtime->context, caller, input, length, false) ||
        !runtime->callbacks->range(runtime->context, caller, output,
                                    sizeof(struct z_create_result), true)) return Z_BAD_ADDRESS;
    struct z_create_request request;
    if (!runtime->callbacks->copy_in(runtime->context, caller, &request, input, length))
        return Z_BAD_ADDRESS;
    struct z_host_request policy_request = {
        .domain = request.authority, .request_id = request.request,
        .template_id = request.template_id, .descendant_slots = request.descendant_slots,
        .descendant_pages = request.descendant_pages, .reserved = request.reserved,
    };
    struct z_host_transaction transaction = {
        .parent_endpoint = owner, .request_id = request.request,
        .template_id = request.template_id, .descendant_slots = request.descendant_slots,
        .descendant_pages = request.descendant_pages,
    };
    trace(runtime, Z_RUNTIME_REQUEST, caller, caller, request.request, Z_OK,
            &transaction, NULL, request.authority, 0, NULL, 0, 0);
    const struct z_manifest_template *sealed = template(runtime, request.template_id);
    const struct z_image_catalog *approved = sealed != NULL ? image(runtime, sealed->image) : NULL;
    int result = Z_INVALID;
    if (sealed == NULL || approved == NULL) goto rejected;
    if (runtime->next_identity == UINT32_MAX) { result = Z_NO_SPACE; goto rejected; }
    result = z_host_prepare(&runtime->hierarchy, runtime->broker->policies, owner,
                             &policy_request, &transaction);
    if (result != Z_OK) goto rejected;
    unsigned cell = transaction.slot;
    runtime->records[cell] = (struct z_runtime_record) {
        .config = configuration(sealed, runtime->next_identity++),
        .instance = transaction.instance, .control = transaction.control,
        .parent_instance = transaction.parent_instance, .parent_endpoint = owner,
        .creation = transaction.domain, .origin = Z_RUNTIME_CHILD,
        .parent_slot = caller, .template_id = request.template_id,
        .depth = transaction.depth, .reserved_slots = transaction.descendant_slots,
        .reserved_pages = transaction.descendant_pages,
        .role = approved->role,
    };
    trace(runtime, Z_RUNTIME_RESERVE, caller, cell, request.request, Z_OK,
            &transaction, NULL, 0, 0, NULL, 0, 0);
    uint64_t parent_cap = 0, child_cap = 0;
    if (approved == NULL || !runtime->callbacks->space_init(runtime->context, cell,
            approved->data, approved->length, &runtime->records[cell].config)) {
        result = Z_NO_SPACE; goto rollback;
    }
    runtime->records[cell].allocated_pages = runtime->callbacks->space_pages(runtime->context, cell);
    if (runtime->records[cell].allocated_pages != transaction.pages ||
        !runtime->callbacks->memory_check(runtime->context) ||
        !runtime->callbacks->frame_init(runtime->context, cell, &runtime->frames[cell])) {
        result = Z_INVALID; goto rollback;
    }
    trace(runtime, Z_RUNTIME_SPACE, caller, cell, request.request, Z_OK,
            &transaction, NULL, 0, 0, NULL, 0, 0);
    if (transaction.bootstrap_recipe != Z_HOST_RECIPE_RPC) {
        result = Z_DENIED; goto rollback;
    }
    result = z_caps_channel(&runtime->broker->capabilities, runtime->broker->policies,
                             owner, transaction.endpoint, &parent_cap, &child_cap);
    if (result != Z_OK) goto rollback;
    runtime->records[cell].parent_channel = child_cap;
    trace(runtime, Z_RUNTIME_CHANNEL, caller, cell, request.request, Z_OK,
            &transaction, NULL, parent_cap, child_cap, NULL, 0, 0);
    struct z_create_result created = {
        .instance = transaction.instance, .control = transaction.control,
        .endpoint = transaction.endpoint, .channel = parent_cap,
        .creation = transaction.domain, .slot = cell,
        .identity = runtime->records[cell].config.identity,
    };
    if (!runtime->callbacks->copy_out(runtime->context, caller, output, &created, sizeof(created))) {
        result = Z_BAD_ADDRESS; goto rollback;
    }
    /* Single publication point. No callback or user turn lies between the
     * checked result copy and READY publication. The final policy check still
     * rejects a parent retired by an injected host callback during copying. */
    runtime->records[cell].published = 1;
    result = z_host_commit(&runtime->hierarchy, runtime->broker->policies,
                            owner, transaction.transaction);
    if (result != Z_OK) goto rollback;
    trace(runtime, Z_RUNTIME_PUBLISH, caller, cell, request.request, Z_OK,
            &transaction, NULL, parent_cap, child_cap, NULL, 0, 0);
    trace(runtime, Z_RUNTIME_RESULT, caller, cell, request.request, Z_OK,
            &transaction, NULL, parent_cap, child_cap, NULL, 0, 0);
    return Z_OK;
rollback:
    abort_creation(runtime, caller, &transaction, parent_cap, child_cap, result);
rejected:
    trace(runtime, Z_RUNTIME_RESULT, caller, caller, request.request, result,
            &transaction, NULL, 0, 0, NULL, 0, 0);
    return result;
}

int z_runtime_status(struct z_runtime *runtime, unsigned caller, uint64_t control,
                      uint64_t output, size_t length)
{
    uint64_t owner = principal(runtime, caller);
    if (!owner) return Z_AGAIN;
    if (length != sizeof(struct z_cell_status)) return Z_INVALID;
    if (!runtime->callbacks->range(runtime->context, caller, output, length, true))
        return Z_BAD_ADDRESS;
    struct z_host_status status;
    int result = z_host_query(&runtime->hierarchy, runtime->broker->policies, owner, control, &status);
    if (result != Z_OK) return result;
    status.reason = runtime->records[status.slot].last_reason;
    if (!runtime->callbacks->copy_out(runtime->context, caller, output, &status, length))
        return Z_BAD_ADDRESS;
    trace(runtime, Z_RUNTIME_STATUS, caller, status.slot, 0, result,
            NULL, NULL, control, status.endpoint, NULL, 0, 0);
    return result;
}

int z_runtime_domain_status(struct z_runtime *runtime, unsigned caller, uint64_t domain,
                             uint64_t output, size_t length)
{
    uint64_t owner = principal(runtime, caller);
    if (!owner) return Z_AGAIN;
    if (length != sizeof(struct z_domain_status)) return Z_INVALID;
    if (!runtime->callbacks->range(runtime->context, caller, output, length, true)) return Z_BAD_ADDRESS;
    struct z_domain_status status;
    int result = z_host_domain_query(&runtime->hierarchy, runtime->broker->policies, owner, domain, &status);
    if (result != Z_OK) return result;
    if (!runtime->callbacks->copy_out(runtime->context, caller, output, &status, length)) return Z_BAD_ADDRESS;
    if (runtime->callbacks->trace != NULL) {
        struct z_runtime_event event = {
            .kind = Z_RUNTIME_DOMAIN, .caller = caller, .cell = caller,
            .caller_endpoint = owner, .record = runtime->records[caller], .domain = status,
        };
        runtime->callbacks->trace(runtime->context, &event);
    }
    return Z_OK;
}

/* Policy first removes scheduling eligibility for the whole affected set.
 * Bounded bottom-up mechanism cleanup then cancels waits, invalidates grants
 * and queued work, clears backing and frames, and retires orphaned records. */
static void cleanup(struct z_runtime *runtime, unsigned target, uint32_t mask,
                      const struct z_runtime_record before[Z_CELL_COUNT], bool recovering)
{
    for (unsigned level = Z_HOST_DEPTH + 1; level != 0; --level) {
        unsigned depth = level - 1;
        for (unsigned cell = 0; cell < Z_CELL_COUNT; ++cell) {
            if (!(mask & (1u << cell)) || before[cell].depth != depth) continue;
            struct z_wait_entry wait = runtime->waits->entries[cell];
            unsigned queued = runtime->broker->queues[cell].count;
            if (wait.kind != Z_WAIT_NONE)
                trace(runtime, Z_RUNTIME_CANCEL, target, cell, 0, Z_OK,
                        NULL, &before[cell], 0, 0, &wait, queued, 0);
            z_wait_cancel(runtime->waits, cell);
            z_broker_revoke(runtime->broker, cell);
            trace(runtime, Z_RUNTIME_INVALIDATE, target, cell, 0, Z_OK,
                    NULL, &before[cell], 0, 0, NULL, queued, 0);
            bool keep = recovering && cell == target;
            unsigned pages = keep ? 0 : runtime->callbacks->space_pages(runtime->context, cell);
            if (!keep) runtime->callbacks->space_release(runtime->context, cell);
            runtime->frames[cell] = (struct z_frame){0};
            bool retained = before[cell].origin == Z_RUNTIME_ROOT ||
                z_host_slot(&runtime->hierarchy, before[cell].instance) >= 0;
            if (retained) {
                runtime->records[cell].published = 0;
                runtime->records[cell].parent_channel = 0;
                runtime->records[cell].creation = 0;
                if (!keep) {
                    runtime->records[cell].allocated_pages = 0;
                    runtime->records[cell].reserved_slots = 0;
                    runtime->records[cell].reserved_pages = 0;
                }
            } else runtime->records[cell] = (struct z_runtime_record){0};
            trace(runtime, Z_RUNTIME_CLEANUP, target, cell, 0, Z_OK,
                    NULL, &before[cell], 0, 0, NULL, queued, pages);
            if (!keep && before[cell].origin == Z_RUNTIME_CHILD)
                trace(runtime, Z_RUNTIME_RETURN, target, cell, 0, Z_OK,
                        NULL, &before[cell], 0, 0, NULL, queued, pages);
        }
    }
}

static void snapshot(const struct z_runtime *runtime,
                       struct z_runtime_record records[Z_CELL_COUNT])
{
    for (unsigned i = 0; i < Z_CELL_COUNT; ++i) records[i] = runtime->records[i];
}

int z_runtime_stop(struct z_runtime *runtime, unsigned caller, uint64_t control)
{
    uint64_t owner = principal(runtime, caller);
    if (!owner) return Z_AGAIN;
    int cell = control_slot(runtime, control);
    struct z_runtime_record before[Z_CELL_COUNT]; snapshot(runtime, before);
    uint32_t mask = 0;
    int result = z_host_stop(&runtime->hierarchy, runtime->broker->policies, owner, control, &mask);
    if (result != Z_OK) return result;
    if (mask & (1u << cell)) runtime->records[cell].last_reason = Z_HOST_REASON_STOP;
    trace(runtime, Z_RUNTIME_STOP, caller, (unsigned)cell, 0, result,
            NULL, &before[cell], control, 0, NULL, 0, 0);
    cleanup(runtime, (unsigned)cell, mask, before, false);
    return result;
}

int z_runtime_reap(struct z_runtime *runtime, unsigned caller, uint64_t control)
{
    uint64_t owner = principal(runtime, caller);
    if (!owner) return Z_AGAIN;
    int cell = control_slot(runtime, control);
    int result = z_host_reap(&runtime->hierarchy, runtime->broker->policies, owner, control);
    if (result != Z_OK) return result;
    struct z_runtime_record before = runtime->records[cell];
    z_wait_cancel(runtime->waits, (unsigned)cell);
    z_broker_revoke(runtime->broker, (unsigned)cell);
    runtime->callbacks->space_release(runtime->context, (unsigned)cell);
    runtime->frames[cell] = (struct z_frame){0};
    runtime->records[cell] = (struct z_runtime_record){0};
    trace(runtime, Z_RUNTIME_REAP, caller, (unsigned)cell, 0, result,
            NULL, &before, control, 0, NULL, 0, 0);
    return result;
}

int z_runtime_fault(struct z_runtime *runtime, unsigned cell, uint64_t now, uint64_t reason)
{
    if (runtime == NULL || !runtime->initialized || cell >= Z_CELL_COUNT ||
        runtime->records[cell].origin == Z_RUNTIME_FREE) return Z_INVALID;
    struct z_runtime_record before[Z_CELL_COUNT]; snapshot(runtime, before);
    uint32_t mask = 0;
    int result = z_host_fault(&runtime->hierarchy, runtime->broker->policies, cell, now, &mask);
    if (result != Z_OK) return result;
    runtime->records[cell].last_reason = Z_TERMINATION_FAULT_BASE | (uint32_t)reason;
    trace(runtime, Z_RUNTIME_FAULT, cell, cell, 0, (int)reason,
            NULL, &before[cell], 0, 0, NULL, 0, 0);
    bool recovering = runtime->broker->policies[cell].phase == Z_POLICY_BACKOFF;
    cleanup(runtime, cell, mask, before, recovering);
    if (recovering)
        trace(runtime, Z_RUNTIME_BACKOFF, cell, cell, 0, Z_OK,
                NULL, NULL, 0, 0, NULL, 0, 0);
    return Z_OK;
}

int z_runtime_exit(struct z_runtime *runtime, unsigned cell)
{
    if (!principal(runtime, cell)) return Z_AGAIN;
    struct z_runtime_record before[Z_CELL_COUNT]; snapshot(runtime, before);
    uint32_t mask = 0;
    int result = z_host_exit(&runtime->hierarchy, runtime->broker->policies, cell, &mask);
    if (result != Z_OK) return result;
    runtime->records[cell].last_reason = Z_HOST_REASON_STOP;
    cleanup(runtime, cell, mask, before, false);
    return Z_OK;
}

static void discard_retired_initialization(struct z_runtime *runtime, unsigned cell,
                                            uint64_t instance, uint32_t origin)
{
    struct z_runtime_record *record = &runtime->records[cell];
    if (record->allocated_pages == 0 && (record->origin == Z_RUNTIME_FREE ||
        (record->origin == origin && record->instance == instance))) {
        /* A callback may inject retirement and then complete a partial space
         * initialization. Those pages have no surviving logical owner. */
        runtime->callbacks->space_release(runtime->context, cell);
        runtime->frames[cell] = (struct z_frame){0};
    }
}

int z_runtime_poll(struct z_runtime *runtime, unsigned cell, uint64_t now)
{
    if (runtime == NULL || !runtime->initialized || cell >= Z_CELL_COUNT ||
        runtime->records[cell].origin == Z_RUNTIME_FREE) return 0;
    if (runtime->broker->policies[cell].phase == Z_POLICY_DORMANT) return 0;
    uint32_t subtree = z_host_descendants(&runtime->hierarchy, cell) | (1u << cell);
    int restarted = z_host_poll(&runtime->hierarchy, runtime->broker->policies, cell, now);
    if (restarted == Z_STALE) {
        struct z_runtime_record before[Z_CELL_COUNT]; snapshot(runtime, before);
        cleanup(runtime, cell, subtree, before, false);
        return 0;
    }
    if (restarted <= 0) return restarted;
    struct z_runtime_record *record = &runtime->records[cell];
    uint64_t instance = record->instance;
    uint64_t endpoint = principal(runtime, cell);
    uint32_t origin = record->origin;
    const struct z_image_catalog *approved = image(runtime, record->config.image);
    struct z_manifest_cell config = record->config;
    if (approved == NULL || !runtime->callbacks->space_reset(runtime->context, cell,
            approved->data, approved->length, &config)) {
        if (principal(runtime, cell) == endpoint && record->instance == instance && record->origin == origin) {
            z_runtime_exit(runtime, cell);
            if (record->origin == origin && record->instance == instance)
                record->last_reason = Z_TERMINATION_INITIALIZATION;
        } else discard_retired_initialization(runtime, cell, instance, origin);
        return Z_NO_SPACE;
    }
    if (principal(runtime, cell) != endpoint || record->instance != instance || record->origin != origin) {
        discard_retired_initialization(runtime, cell, instance, origin);
        return Z_STALE;
    }
    if (!runtime->callbacks->frame_init(runtime->context, cell, &runtime->frames[cell])) {
        if (principal(runtime, cell) == endpoint && record->instance == instance && record->origin == origin) {
            z_runtime_exit(runtime, cell);
            if (record->origin == origin && record->instance == instance)
                record->last_reason = Z_TERMINATION_INITIALIZATION;
        } else discard_retired_initialization(runtime, cell, instance, origin);
        return Z_NO_SPACE;
    }
    if (principal(runtime, cell) != endpoint || record->instance != instance || record->origin != origin) {
        discard_retired_initialization(runtime, cell, instance, origin);
        return Z_STALE;
    }
    record->published = 1;
    trace(runtime, Z_RUNTIME_RESTART, cell, cell, 0, Z_OK,
            NULL, NULL, 0, 0, NULL, 0, 0);
    return 1;
}

int z_runtime_rebind(struct z_runtime *runtime, unsigned caller,
                      uint64_t input, size_t length, uint64_t output)
{
    uint64_t owner = principal(runtime, caller);
    if (!owner) return Z_AGAIN;
    if (length != sizeof(struct z_rebind_request)) return Z_INVALID;
    if (!runtime->callbacks->range(runtime->context, caller, input, length, false) ||
        !runtime->callbacks->range(runtime->context, caller, output,
                                    sizeof(struct z_create_result), true)) return Z_BAD_ADDRESS;
    struct z_rebind_request request;
    if (!runtime->callbacks->copy_in(runtime->context, caller, &request, input, length))
        return Z_BAD_ADDRESS;
    if (request.reserved != 0 || request.request == 0) return Z_INVALID;
    struct z_host_table before = runtime->hierarchy;
    struct z_host_transaction transaction;
    int result = z_host_rebind(&runtime->hierarchy, runtime->broker->policies, owner,
                               request.control, request.authority, request.request, &transaction);
    if (result != Z_OK) return result;
    uint64_t parent_cap = 0, child_cap = 0;
    result = z_caps_channel(&runtime->broker->capabilities, runtime->broker->policies,
                             owner, transaction.endpoint, &parent_cap, &child_cap);
    if (result != Z_OK) goto rollback;
    struct z_create_result rebound = {
        .instance = transaction.instance, .control = transaction.control,
        .endpoint = transaction.endpoint, .channel = parent_cap,
        .creation = transaction.domain, .slot = transaction.slot,
        .identity = runtime->records[transaction.slot].config.identity,
    };
    if (!runtime->callbacks->copy_out(runtime->context, caller, output, &rebound, sizeof(rebound))) {
        result = Z_BAD_ADDRESS; goto rollback;
    }
    struct z_host_status current;
    if (principal(runtime, caller) != owner ||
        z_host_query(&runtime->hierarchy, runtime->broker->policies,
                       owner, request.control, &current) != Z_OK ||
        current.instance != transaction.instance || current.endpoint != transaction.endpoint) {
        result = Z_STALE; goto rollback;
    }
    struct z_runtime_record *record = &runtime->records[transaction.slot];
    uint64_t old_child_cap = record->parent_channel;
    // Retire the previous recipe pair only after replacement and result copy.
    // Reverse targets are unique within this direct owner-child recipe.
    for (unsigned i = 0; i < Z_CAPACITY; ++i) {
        const struct z_cap_entry *entry = &runtime->broker->capabilities.entries[i];
        if (entry->live && entry->holder == owner && entry->target == transaction.endpoint &&
            entry->rights == Z_RIGHT(Z_HOST_REQUEST)) {
            uint64_t handle = (entry->epoch << 8) | (i + 1);
            if (handle != parent_cap) z_caps_drop_channel(&runtime->broker->capabilities, handle, 0);
        }
    }
    z_caps_drop_channel(&runtime->broker->capabilities, old_child_cap, 0);
    record->parent_channel = child_cap; record->creation = transaction.domain;
    transaction.request_id = request.request;
    trace(runtime, Z_RUNTIME_REBIND, caller, transaction.slot, request.request, Z_OK,
            &transaction, NULL, parent_cap, child_cap, NULL, 0, 0);
    return Z_OK;
rollback:
    z_caps_drop_channel(&runtime->broker->capabilities, parent_cap, child_cap);
    /* Architecture callbacks can inject owner/child/unrelated faults in host
     * tests. Never restore a table snapshot over mandatory subtree cleanup.
     * Rebind changes only a surviving child's execution-scoped domain token.
     * Restore those fields selectively; all epochs and parent request IDs
     * remain retired, and unrelated ledger/record changes stay intact. */
    struct z_host_status surviving;
    if (principal(runtime, caller) == owner &&
        z_host_query(&runtime->hierarchy, runtime->broker->policies,
                       owner, request.control, &surviving) == Z_OK &&
        surviving.instance == transaction.instance && surviving.endpoint == transaction.endpoint) {
        for (unsigned i = 0; i < Z_HOST_INSTANCES; ++i) {
            const struct z_host_record *old = &before.records[i];
            if (old->instance != transaction.instance || old->domain == UINT32_MAX) continue;
            struct z_host_domain *domain = &runtime->hierarchy.domains[old->domain];
            const struct z_host_domain *previous = &before.domains[old->domain];
            if (domain->instance == previous->instance && domain->holder == transaction.endpoint) {
                uint64_t used = domain->last_request;
                domain->token = previous->token; domain->holder = previous->holder;
                domain->last_request = previous->last_request;
                if (previous->token && domain->last_request < used) domain->last_request = used;
            }
        }
    }
    return result;
}

int z_runtime_revoke(struct z_runtime *runtime, unsigned caller, uint64_t domain)
{
    uint64_t owner = principal(runtime, caller);
    if (!owner) return Z_AGAIN;
    int result = z_host_revoke(&runtime->hierarchy, runtime->broker->policies, owner, domain);
    if (result == Z_OK)
        trace(runtime, Z_RUNTIME_REVOKE, caller, caller, 0, result,
                NULL, NULL, domain, 0, NULL, 0, 0);
    return result;
}

int z_runtime_boot(const struct z_runtime *runtime, unsigned caller, struct z_boot_info *info)
{
    uint64_t endpoint = principal(runtime, caller);
    if (!endpoint || info == NULL) return Z_AGAIN;
    const struct z_runtime_record *record = &runtime->records[caller];
    int64_t creation = record->origin == Z_RUNTIME_ROOT ?
        z_host_root_domain(&runtime->hierarchy, runtime->broker->policies, endpoint) :
        (int64_t)record->creation;
    *info = (struct z_boot_info) {
        .abi = Z_ABI_VERSION, .role = record->role,
        .generation = endpoint >> 8, .scenario = record->config.boot_config,
        .endpoint = endpoint, .parent_endpoint = record->parent_endpoint,
        .instance = record->instance, .creation = creation > 0 ? (uint64_t)creation : 0,
        .parent_channel = record->parent_channel, .template_id = record->template_id,
        .depth = record->depth, .identity = record->config.identity,
    };
    return Z_OK;
}

bool z_runtime_check(const struct z_runtime *runtime)
{
    if (runtime == NULL || !runtime->initialized ||
        !z_host_check(&runtime->hierarchy, runtime->broker->policies) ||
        !runtime->callbacks->memory_check(runtime->context)) return false;
    unsigned total_pages = 0;
    for (unsigned cell = 0; cell < Z_CELL_COUNT; ++cell) {
        const struct z_runtime_record *record = &runtime->records[cell];
        unsigned pages = runtime->callbacks->space_pages(runtime->context, cell);
        if (pages > Z_HOST_PAGES || pages != record->allocated_pages ||
            total_pages > Z_HOST_PAGES - pages) return false;
        total_pages += pages;
        if (record->origin == Z_RUNTIME_FREE) {
            if (pages != 0 || runtime->broker->policies[cell].phase != Z_POLICY_DORMANT ||
                runtime->waits->entries[cell].kind != Z_WAIT_NONE ||
                runtime->broker->queues[cell].count != 0) return false;
        } else if (record->origin == Z_RUNTIME_ROOT) {
            if (cell >= Z_ROOT_COUNT || record->instance != 0 || record->template_id != 0) return false;
        } else if (record->origin == Z_RUNTIME_CHILD) {
            if (cell < Z_ROOT_COUNT || record->depth == 0 || record->depth > Z_HOST_DEPTH ||
                z_host_slot(&runtime->hierarchy, record->instance) != (int)cell) return false;
            bool found = false;
            for (unsigned i = 0; i < Z_HOST_INSTANCES; ++i) {
                const struct z_host_record *logical = &runtime->hierarchy.records[i];
                if (logical->instance == record->instance) {
                    found = logical->pages == pages && logical->control == record->control &&
                        logical->parent_endpoint == record->parent_endpoint &&
                        logical->parent_instance == record->parent_instance &&
                        logical->slot == cell && logical->depth == record->depth;
                }
            }
            if (!found) return false;
        } else return false;
        if (record->published != (runtime->broker->policies[cell].phase == Z_POLICY_READY)) return false;
    }
    return total_pages <= Z_HOST_PAGES;
}
