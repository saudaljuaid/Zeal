#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <zeal/wait.h>
#include <zeal/memory.h>

static struct z_broker broker;
static struct z_wait_table waits;
static struct z_memory_pool memory;
static const uint8_t image[4096] = {0};
static struct z_memory_layout layouts[Z_CELL_COUNT];
static bool fail_copy[Z_CELL_COUNT];
static unsigned copies[Z_CELL_COUNT];
static bool inject_send;
static uint64_t injected_cap;
static const uint64_t destination = Z_STACK_BASE + 4090;
static const struct z_boot_grant initial[] = {
    { Z_BLOCK, Z_FS, Z_RIGHT(Z_READ_REPLY), 0 },
    { Z_FS, Z_BLOCK, Z_RIGHT(Z_READ) | Z_RIGHT(Z_BLOCK_WRITE), 0 },
    { Z_FS, Z_FS, Z_RIGHT(Z_FILE_READ) | Z_RIGHT_DELEGATE, 0 },
    { Z_CLIENT, Z_FS, Z_RIGHT(Z_FILE_READ) | Z_RIGHT(Z_FILE_WRITE), 0 },
    { Z_BLOCK, Z_BLOCK, Z_RIGHT(Z_FILE_READ) | Z_RIGHT_DELEGATE, 0 },
    { Z_CLIENT, Z_CLIENT, Z_RIGHT(Z_FILE_READ) | Z_RIGHT_DELEGATE, 0 },
    { Z_PROBE, Z_PROBE, Z_RIGHT(Z_FILE_READ) | Z_RIGHT_DELEGATE, 0 },
};

static uint64_t endpoint(unsigned cell)
{
    return z_policy_handle(&broker.policies[cell], cell);
}

static uint64_t cap(unsigned source, unsigned target, uint32_t rights)
{
    int64_t result = z_broker_find(&broker, source, endpoint(target), rights);
    if (result <= 0)
        fprintf(stderr, "cap source=%u target=%u rights=%u result=%lld generation=%llu\n",
                 source, target, rights, (long long)result,
                 (unsigned long long)broker.policies[source].generation);
    assert(result > 0);
    return (uint64_t)result;
}

static struct z_message message(uint32_t operation, uint64_t marker)
{
    struct z_message result = { .operation = operation, .length = 8 };
    memcpy(result.payload, &marker, sizeof(marker));
    return result;
}

static int send(unsigned source, unsigned target, uint64_t authority,
                 uint32_t operation, uint64_t marker)
{
    struct z_message input = message(operation, marker);
    return z_broker_send(&broker, source, endpoint(target), authority, &input);
}

static bool checked_copy(void *context, unsigned cell, uint64_t generation,
                          uint64_t address, const struct z_message *input)
{
    assert(context == &memory);
    assert(cell < Z_CELL_COUNT);
    if (generation != broker.policies[cell].generation)
        return false;
    if (inject_send && input == NULL) {
        inject_send = false;
        assert(send(Z_CLIENT, Z_FS, injected_cap, Z_FILE_READ, 71) == Z_OK);
    }
    if (!z_memory_copy_valid(&memory, cell, &layouts[cell], address,
                              sizeof(struct z_message), true))
        return false;
    if (input == NULL)
        return true;
    if (fail_copy[cell])
        return false;
    bool result = z_memory_copy_out(&memory, cell, &layouts[cell], address,
                                    input, sizeof(*input));
    if (result)
        ++copies[cell];
    return result;
}

static uint64_t output_marker(unsigned cell)
{
    struct z_message output;
    uint64_t marker;
    assert(z_memory_copy_in(&memory, cell, &layouts[cell], &output,
                            destination, sizeof(output)));
    memcpy(&marker, output.payload, sizeof(marker));
    return marker;
}

static void setup(void)
{
    z_broker_init(&broker);
    assert(z_broker_configure(&broker, initial, sizeof(initial) / sizeof(initial[0])) == Z_OK);
    assert(z_broker_refresh(&broker) == Z_OK);
    z_wait_init(&waits);
    assert(z_memory_init(&memory, Z_MANIFEST_POOL_PAGES));
    for (unsigned cell = 0; cell < Z_CELL_COUNT; ++cell) {
        assert(z_memory_allocate(&memory, cell, 8192, 16384));
        layouts[cell] = (struct z_memory_layout){ image, sizeof(image), 8192, 8192 };
        copies[cell] = 0;
        fail_copy[cell] = false;
    }
    inject_send = false;
}

static int receive(unsigned cell, uint64_t now, uint64_t duration, bool *blocked)
{
    return z_wait_receive(&waits, &broker, cell, now, duration, destination,
                          checked_copy, &memory, blocked);
}

static enum z_wait_status poll(unsigned cell, uint64_t now, int *result,
                                enum z_wake_reason *reason)
{
    return z_wait_poll(&waits, &broker, cell, now, checked_copy, &memory,
                       result, reason);
}

static void immediate_and_zero(void)
{
    setup();
    bool blocked = true;
    assert(z_wait_sleep(&waits, &broker, Z_CLIENT, 9, 0) == Z_OK);
    assert(z_wait_runnable(&waits, &broker, Z_CLIENT));
    assert(receive(Z_FS, 9, 0, &blocked) == Z_AGAIN && !blocked);
    assert(waits.entries[Z_FS].kind == Z_WAIT_NONE);
    uint64_t authority = cap(Z_CLIENT, Z_FS, Z_RIGHT(Z_FILE_READ));
    assert(send(Z_CLIENT, Z_FS, authority, Z_FILE_READ, 41) == Z_OK);
    assert(receive(Z_FS, 9, 0, &blocked) == Z_OK && !blocked);
    assert(output_marker(Z_FS) == 41 && copies[Z_FS] == 1);
    assert(send(Z_CLIENT, Z_FS, authority, Z_FILE_READ, 42) == Z_OK);
    assert(receive(Z_FS, 9, 10, &blocked) == Z_OK && !blocked);
    assert(output_marker(Z_FS) == 42 && waits.entries[Z_FS].kind == Z_WAIT_NONE);
}

static void deadlines_and_overflow(void)
{
    setup();
    uint64_t deadline = 99;
    assert(z_wait_deadline(100, 0, &deadline) == Z_OK && deadline == 100);
    assert(z_wait_deadline(100, Z_WAIT_MAX_TICKS, &deadline) == Z_OK &&
           deadline == 100 + Z_WAIT_MAX_TICKS);
    assert(z_wait_deadline(100, Z_WAIT_MAX_TICKS + 1, &deadline) == Z_INVALID);
    assert(z_wait_deadline(UINT64_MAX, 1, &deadline) == Z_INVALID);
    assert(z_wait_deadline(UINT64_MAX - 999, 1000, &deadline) == Z_INVALID);
    assert(z_wait_deadline(UINT64_MAX - 1000, 1000, &deadline) == Z_OK && deadline == UINT64_MAX);
    assert(z_wait_deadline(UINT64_MAX, 0, &deadline) == Z_OK && deadline == UINT64_MAX);
    assert(z_wait_deadline(0, 1, NULL) == Z_INVALID);
    assert(z_wait_sleep(&waits, &broker, Z_CLIENT, UINT64_MAX, 1) == Z_INVALID);
    assert(waits.entries[Z_CLIENT].kind == Z_WAIT_NONE);
    assert(z_wait_sleep(&waits, &broker, Z_CLIENT, UINT64_MAX - 1, 1) == Z_OK);
    int result = 77;
    enum z_wake_reason reason;
    assert(poll(Z_CLIENT, UINT64_MAX - 1, &result, &reason) == Z_WAIT_PENDING);
    assert(!z_wait_runnable(&waits, &broker, Z_CLIENT));
    assert(poll(Z_CLIENT, UINT64_MAX, &result, &reason) == Z_WAIT_DONE);
    assert(result == Z_OK && reason == Z_WAKE_SLEEP);
    bool blocked;
    uint64_t authority = cap(Z_CLIENT, Z_FS, Z_RIGHT(Z_FILE_READ));
    assert(send(Z_CLIENT, Z_FS, authority, Z_FILE_READ, 9) == Z_OK);
    assert(receive(Z_FS, UINT64_MAX, 1, &blocked) == Z_INVALID && !blocked);
    assert(receive(Z_FS, 0, Z_WAIT_MAX_TICKS + 1, &blocked) == Z_INVALID && !blocked);
    assert(broker.queues[Z_FS].count == 1 && copies[Z_FS] == 0);
    assert(receive(Z_FS, UINT64_MAX, 0, &blocked) == Z_OK && !blocked);
    assert(receive(Z_FS, 100, 10, &blocked) == Z_OK && blocked);
    assert(poll(Z_FS, 109, &result, &reason) == Z_WAIT_PENDING);
    assert(poll(Z_FS, 110, &result, &reason) == Z_WAIT_DONE);
    assert(result == Z_TIMEOUT && reason == Z_WAKE_TIMEOUT);
}

static void enqueue_transitions_and_timeout_order(void)
{
    setup();
    uint64_t authority = cap(Z_CLIENT, Z_FS, Z_RIGHT(Z_FILE_READ));
    bool blocked;
    int result;
    enum z_wake_reason reason;
    /* Before entry, during destination validation, and after wait publication. */
    assert(send(Z_CLIENT, Z_FS, authority, Z_FILE_READ, 70) == Z_OK);
    assert(receive(Z_FS, 10, 5, &blocked) == Z_OK && !blocked);
    assert(output_marker(Z_FS) == 70);
    injected_cap = authority;
    inject_send = true;
    assert(receive(Z_FS, 10, 5, &blocked) == Z_OK && !blocked);
    assert(output_marker(Z_FS) == 71);
    assert(receive(Z_FS, 10, 5, &blocked) == Z_OK && blocked);
    assert(send(Z_CLIENT, Z_FS, authority, Z_FILE_READ, 72) == Z_OK);
    assert(poll(Z_FS, 14, &result, &reason) == Z_WAIT_DONE);
    assert(result == Z_OK && reason == Z_WAKE_MESSAGE && output_marker(Z_FS) == 72);
    assert(receive(Z_FS, 20, 5, &blocked) == Z_OK && blocked);
    assert(send(Z_CLIENT, Z_FS, authority, Z_FILE_READ, 73) == Z_OK);
    assert(poll(Z_FS, 25, &result, &reason) == Z_WAIT_DONE);
    assert(result == Z_TIMEOUT && reason == Z_WAKE_TIMEOUT && broker.queues[Z_FS].count == 1);
    assert(receive(Z_FS, 25, 0, &blocked) == Z_OK && output_marker(Z_FS) == 73);
    assert(receive(Z_FS, 30, 1, &blocked) == Z_OK && blocked);
    assert(poll(Z_FS, 31, &result, &reason) == Z_WAIT_DONE && result == Z_TIMEOUT);
    assert(send(Z_CLIENT, Z_FS, authority, Z_FILE_READ, 74) == Z_OK);
    assert(receive(Z_FS, 32, 0, &blocked) == Z_OK && output_marker(Z_FS) == 74);
}

static void revocation_and_valid_fifo(void)
{
    setup();
    uint64_t app = cap(Z_CLIENT, Z_FS, Z_RIGHT(Z_FILE_READ));
    uint64_t parent = cap(Z_FS, Z_FS, Z_RIGHT(Z_FILE_READ) | Z_RIGHT_DELEGATE);
    int64_t child = z_broker_delegate(&broker, Z_FS, parent, endpoint(Z_FS), Z_RIGHT(Z_FILE_READ));
    assert(child > 0);
    uint64_t service = cap(Z_BLOCK, Z_FS, Z_RIGHT(Z_READ_REPLY));
    assert(send(Z_CLIENT, Z_FS, app, Z_FILE_READ, 1) == Z_OK);
    assert(send(Z_FS, Z_FS, (uint64_t)child, Z_FILE_READ, 2) == Z_OK);
    assert(send(Z_BLOCK, Z_FS, service, Z_READ_REPLY, 3) == Z_OK);
    /* Bypass eager compaction to exercise delivery-time authority revalidation. */
    assert(z_caps_revoke(&broker.capabilities, broker.policies, endpoint(Z_FS), (uint64_t)child) == Z_OK);
    bool blocked;
    assert(receive(Z_FS, 0, 5, &blocked) == Z_OK && !blocked && output_marker(Z_FS) == 1);
    assert(receive(Z_FS, 0, 5, &blocked) == Z_OK && !blocked && output_marker(Z_FS) == 3);
    assert(receive(Z_FS, 0, 5, &blocked) == Z_OK && blocked);
    assert(send(Z_CLIENT, Z_FS, app, Z_FILE_READ, 4) == Z_OK);
    uint64_t unrelated = cap(Z_PROBE, Z_PROBE, Z_RIGHT(Z_FILE_READ));
    assert(send(Z_PROBE, Z_PROBE, unrelated, Z_FILE_READ, 5) == Z_OK);
    assert(z_wait_sleep(&waits, &broker, Z_PROBE, 0, 9) == Z_OK);
    struct z_wait_entry saved = waits.entries[Z_PROBE];
    assert(z_broker_revoke_cap(&broker, Z_CLIENT, app) == Z_OK);
    assert(broker.queues[Z_FS].count == 0 && broker.queues[Z_PROBE].count == 1);
    assert(memcmp(&saved, &waits.entries[Z_PROBE], sizeof(saved)) == 0);
    int result;
    enum z_wake_reason reason;
    assert(poll(Z_FS, 4, &result, &reason) == Z_WAIT_PENDING);
    assert(poll(Z_FS, 5, &result, &reason) == Z_WAIT_DONE && result == Z_TIMEOUT);
    assert(poll(Z_PROBE, 9, &result, &reason) == Z_WAIT_DONE && reason == Z_WAKE_SLEEP);
    assert(receive(Z_PROBE, 9, 0, &blocked) == Z_OK && output_marker(Z_PROBE) == 5);
}

static void cancellation_and_generation_ownership(void)
{
    setup();
    bool blocked;
    int result;
    enum z_wake_reason reason;
    assert(receive(Z_FS, 100, 20, &blocked) == Z_OK && blocked);
    assert(z_wait_sleep(&waits, &broker, Z_PROBE, 100, 30) == Z_OK);
    struct z_wait_entry saved = waits.entries[Z_PROBE];
    uint64_t authority = cap(Z_PROBE, Z_PROBE, Z_RIGHT(Z_FILE_READ));
    assert(send(Z_PROBE, Z_PROBE, authority, Z_FILE_READ, 91) == Z_OK);
    uint8_t *private_page = z_memory_page(&memory, Z_PROBE, 0);
    private_page[17] = 0xa5;
    z_wait_cancel(&waits, Z_FS);
    z_broker_revoke(&broker, Z_FS);
    z_policy_fault(&broker.policies[Z_FS], 100);
    assert(poll(Z_FS, 120, &result, &reason) == Z_WAIT_PENDING && copies[Z_FS] == 0);
    assert(memcmp(&saved, &waits.entries[Z_PROBE], sizeof(saved)) == 0);
    assert(private_page[17] == 0xa5 && broker.queues[Z_PROBE].count == 1);
    assert(z_broker_query(&broker, Z_PROBE, authority, &(struct z_cap_info){0}) == Z_OK);
    assert(z_policy_poll(&broker.policies[Z_FS], 104) == 1);
    assert(z_broker_refresh(&broker) == Z_OK);
    assert(z_memory_reset(&memory, Z_FS));
    assert(z_wait_runnable(&waits, &broker, Z_FS));
    assert(poll(Z_FS, 200, &result, &reason) == Z_WAIT_PENDING && copies[Z_FS] == 0);
    /* Defensive poll cancellation also catches a lifecycle caller omitting clear. */
    assert(receive(Z_FS, 200, 20, &blocked) == Z_OK && blocked);
    ++broker.policies[Z_FS].generation;
    assert(poll(Z_FS, 201, &result, &reason) == Z_WAIT_CANCELLED);
    assert(result == Z_STALE && reason == Z_WAKE_CANCELLED && copies[Z_FS] == 0);
    assert(receive(Z_FS, 201, 20, &blocked) == Z_OK && blocked);
    z_policy_stop(&broker.policies[Z_FS]);
    assert(poll(Z_FS, 202, &result, &reason) == Z_WAIT_CANCELLED);
    broker.policies[Z_FS].phase = Z_POLICY_READY;
    assert(z_wait_sleep(&waits, &broker, Z_FS, 202, 20) == Z_OK);
    broker.policies[Z_FS].phase = Z_POLICY_QUARANTINED;
    assert(poll(Z_FS, 203, &result, &reason) == Z_WAIT_CANCELLED);
    z_wait_init(&waits);
    for (unsigned cell = 0; cell < Z_CELL_COUNT; ++cell)
        assert(waits.entries[cell].kind == Z_WAIT_NONE && waits.entries[cell].deadline == 0);
}

static void interrupted_storage_preserves_unrelated_waits_and_memory(void)
{
    setup();
    uint64_t file = cap(Z_CLIENT, Z_FS, Z_RIGHT(Z_FILE_WRITE));
    uint64_t block = cap(Z_FS, Z_BLOCK, Z_RIGHT(Z_BLOCK_WRITE));
    uint64_t unrelated = cap(Z_PROBE, Z_PROBE, Z_RIGHT(Z_FILE_READ));
    bool blocked;
    int result;
    enum z_wake_reason reason;
    assert(receive(Z_FS, 100, 7, &blocked) == Z_OK && blocked);
    assert(z_wait_sleep(&waits, &broker, Z_PROBE, 100, 11) == Z_OK);
    assert(send(Z_PROBE, Z_PROBE, unrelated, Z_FILE_READ, 201) == Z_OK);
    struct z_wait_entry saved_wait = waits.entries[Z_PROBE];
    struct z_queue saved_queue = broker.queues[Z_PROBE];
    uint8_t *private_page = z_memory_page(&memory, Z_PROBE, 0);
    private_page[31] = 0x96;
    assert(send(Z_CLIENT, Z_FS, file, Z_FILE_WRITE, 202) == Z_OK);
    /* A revoked queued write must never wake the filesystem receiver. */
    assert(z_caps_revoke(&broker.capabilities, broker.policies,
                         endpoint(Z_CLIENT), file) == Z_OK);
    assert(poll(Z_FS, 101, &result, &reason) == Z_WAIT_PENDING);
    assert(copies[Z_FS] == 0 && broker.queues[Z_FS].count == 0);
    assert(send(Z_CLIENT, Z_FS, file, Z_FILE_WRITE, 203) == Z_STALE);
    assert(poll(Z_FS, 107, &result, &reason) == Z_WAIT_DONE);
    assert(result == Z_TIMEOUT && reason == Z_WAKE_TIMEOUT);
    /* Block death drops the accepted downstream request, while its waiter
     * remains finite and independent cells retain their state. */
    assert(send(Z_FS, Z_BLOCK, block, Z_BLOCK_WRITE, 204) == Z_OK);
    assert(receive(Z_FS, 108, 5, &blocked) == Z_OK && blocked);
    z_broker_revoke(&broker, Z_BLOCK);
    z_policy_fault(&broker.policies[Z_BLOCK], 108);
    assert(broker.queues[Z_BLOCK].count == 0);
    assert(poll(Z_FS, 112, &result, &reason) == Z_WAIT_PENDING);
    assert(poll(Z_FS, 113, &result, &reason) == Z_WAIT_DONE && result == Z_TIMEOUT);
    assert(memcmp(&saved_wait, &waits.entries[Z_PROBE], sizeof(saved_wait)) == 0);
    assert(memcmp(&saved_queue, &broker.queues[Z_PROBE], sizeof(saved_queue)) == 0);
    assert(private_page[31] == 0x96);
    assert(z_broker_query(&broker, Z_PROBE, unrelated, &(struct z_cap_info){0}) == Z_OK);
    assert(z_policy_poll(&broker.policies[Z_BLOCK], 112) == 1);
    assert(z_broker_refresh(&broker) == Z_OK);
    assert(z_memory_reset(&memory, Z_BLOCK));
    assert(send(Z_FS, Z_BLOCK, block, Z_BLOCK_WRITE, 205) == Z_STALE);
    uint64_t rebound = cap(Z_FS, Z_BLOCK, Z_RIGHT(Z_BLOCK_WRITE));
    assert(rebound != block && send(Z_FS, Z_BLOCK, rebound, Z_BLOCK_WRITE, 206) == Z_OK);
    assert(receive(Z_BLOCK, 114, 0, &blocked) == Z_OK && !blocked);
    assert(output_marker(Z_BLOCK) == 206);
    assert(poll(Z_PROBE, 114, &result, &reason) == Z_WAIT_DONE && reason == Z_WAKE_SLEEP);
    assert(receive(Z_PROBE, 114, 0, &blocked) == Z_OK && output_marker(Z_PROBE) == 201);
    assert(private_page[31] == 0x96 && z_memory_check(&memory));
}

static void invalid_buffers_and_deferred_copy_failure(void)
{
    setup();
    bool blocked;
    uint64_t authority = cap(Z_CLIENT, Z_FS, Z_RIGHT(Z_FILE_READ));
    uint64_t invalid[] = { 0, Z_IMAGE_BASE, Z_STACK_BASE + 8192 - 47,
                           UINT64_MAX - 7, UINT64_C(0x0000800000000000) };
    for (unsigned i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i)
        assert(z_wait_receive(&waits, &broker, Z_FS, 0, 5, invalid[i],
                                checked_copy, &memory, &blocked) == Z_BAD_ADDRESS && !blocked);
    assert(receive(Z_FS, 0, 5, &blocked) == Z_OK && blocked);
    assert(send(Z_CLIENT, Z_FS, authority, Z_FILE_READ, 11) == Z_OK);
    layouts[Z_FS].stack_size = 4096;
    int result;
    enum z_wake_reason reason;
    assert(poll(Z_FS, 1, &result, &reason) == Z_WAIT_DONE);
    assert(result == Z_BAD_ADDRESS && reason == Z_WAKE_BAD_ADDRESS && broker.queues[Z_FS].count == 1);
    layouts[Z_FS].stack_size = 8192;
    fail_copy[Z_FS] = true;
    assert(receive(Z_FS, 1, 5, &blocked) == Z_BAD_ADDRESS && !blocked);
    assert(broker.queues[Z_FS].count == 1 && copies[Z_FS] == 0);
    fail_copy[Z_FS] = false;
    assert(receive(Z_FS, 1, 0, &blocked) == Z_OK && output_marker(Z_FS) == 11);
    assert(receive(Z_FS, 2, 5, &blocked) == Z_OK && blocked);
    assert(send(Z_CLIENT, Z_FS, authority, Z_FILE_READ, 12) == Z_OK);
    fail_copy[Z_FS] = true;
    assert(poll(Z_FS, 3, &result, &reason) == Z_WAIT_DONE && result == Z_BAD_ADDRESS);
    assert(broker.queues[Z_FS].count == 1 && copies[Z_FS] == 1);
    fail_copy[Z_FS] = false;
    assert(receive(Z_FS, 3, 0, &blocked) == Z_OK && output_marker(Z_FS) == 12);
    assert(receive(Z_FS, 4, 5, &blocked) == Z_OK && blocked);
    assert(send(Z_CLIENT, Z_FS, authority, Z_FILE_READ, 13) == Z_OK);
    unsigned physical = memory.cells[Z_FS].pages[1];
    memory.owners[physical] = Z_CLIENT + 1;
    assert(poll(Z_FS, 5, &result, &reason) == Z_WAIT_DONE && result == Z_BAD_ADDRESS);
    assert(broker.queues[Z_FS].count == 1 && copies[Z_FS] == 2);
    memory.owners[physical] = Z_FS + 1;
    assert(z_memory_check(&memory));
    assert(receive(Z_FS, 5, 0, &blocked) == Z_OK && output_marker(Z_FS) == 13);
}

static void idle_and_fair_selection(void)
{
    setup();
    unsigned after = Z_CELL_COUNT - 1;
    for (unsigned turn = 0; turn < 100; ++turn) {
        int next = z_wait_next(&waits, &broker, after);
        assert(next == (int)(turn % Z_CELL_COUNT));
        after = (unsigned)next;
    }
    for (unsigned cell = 0; cell < Z_CELL_COUNT; ++cell)
        assert(z_wait_sleep(&waits, &broker, cell, 10, 4 + 3 * cell) == Z_OK);
    assert(z_wait_next(&waits, &broker, after) == -1);
    int result;
    enum z_wake_reason reason;
    for (unsigned cell = 0; cell < Z_CELL_COUNT; ++cell)
        assert(poll(cell, 13, &result, &reason) == Z_WAIT_PENDING);
    assert(z_wait_next(&waits, &broker, after) == -1);
    assert(poll(Z_BLOCK, 14, &result, &reason) == Z_WAIT_DONE && reason == Z_WAKE_SLEEP);
    assert(z_wait_next(&waits, &broker, after) == Z_BLOCK);
    assert(z_wait_next(&waits, &broker, Z_BLOCK) == Z_BLOCK);
    assert(poll(Z_FS, 17, &result, &reason) == Z_WAIT_DONE);
    assert(z_wait_next(&waits, &broker, Z_BLOCK) == Z_FS);
    z_policy_stop(&broker.policies[Z_FS]);
    assert(z_wait_next(&waits, &broker, Z_BLOCK) == Z_BLOCK);
}

/* Independent state machine: it stores an abstract FIFO and wait mode, then
 * compares production transitions and scheduling after each generated action. */
struct model_cell { unsigned kind, count; uint64_t deadline, queue[Z_QUEUE_DEPTH]; };
static uint32_t rng = UINT32_C(0x5a17e39b);
static uint32_t random_next(void)
{
    rng ^= rng << 13; rng ^= rng >> 17; rng ^= rng << 5;
    return rng;
}

static uint64_t model_pop(struct model_cell *model)
{
    assert(model->count);
    uint64_t marker = model->queue[0];
    memmove(model->queue, model->queue + 1, --model->count * sizeof(*model->queue));
    return marker;
}

static void generated_model(void)
{
    setup();
    struct model_cell model[Z_CELL_COUNT] = {0};
    uint64_t authorities[Z_CELL_COUNT], parents[Z_CELL_COUNT];
    for (unsigned cell = 0; cell < Z_CELL_COUNT; ++cell) {
        parents[cell] = cap(cell, cell, Z_RIGHT(Z_FILE_READ) | Z_RIGHT_DELEGATE);
        int64_t delegated = z_broker_delegate(&broker, cell, parents[cell],
                                               endpoint(cell), Z_RIGHT(Z_FILE_READ));
        assert(delegated > 0);
        authorities[cell] = (uint64_t)delegated;
    }
    uint64_t now = 0;
    for (unsigned step = 0; step < 50000; ++step) {
        unsigned cell = random_next() % Z_CELL_COUNT;
        struct model_cell *current = &model[cell];
        unsigned choice = random_next() % 8;
        uint64_t duration = random_next() % 9;
        bool blocked;
        if (choice == 0) {
            now += random_next() % 4;
        } else if (choice == 1) {
            uint64_t marker = random_next();
            int result = send(cell, cell, authorities[cell], Z_FILE_READ, marker);
            assert(result == (current->count == Z_QUEUE_DEPTH ? Z_AGAIN : Z_OK));
            if (result == Z_OK)
                current->queue[current->count++] = marker;
        } else if (choice == 2 && !current->kind) {
            int result = receive(cell, now, duration, &blocked);
            if (current->count) {
                assert(result == Z_OK && !blocked && output_marker(cell) == model_pop(current));
            } else if (!duration) {
                assert(result == Z_AGAIN && !blocked);
            } else {
                assert(result == Z_OK && blocked);
                current->kind = 2;
                current->deadline = now + duration;
            }
        } else if (choice == 3 && !current->kind) {
            assert(z_wait_sleep(&waits, &broker, cell, now, duration) == Z_OK);
            if (duration) {
                current->kind = 1;
                current->deadline = now + duration;
            }
        } else if (choice == 4) {
            int result = 77;
            enum z_wake_reason reason;
            enum z_wait_status status = poll(cell, now, &result, &reason);
            if (!current->kind) {
                assert(status == Z_WAIT_PENDING);
            } else if (now >= current->deadline) {
                assert(status == Z_WAIT_DONE);
                assert(result == (current->kind == 1 ? Z_OK : Z_TIMEOUT));
                assert(reason == (current->kind == 1 ? Z_WAKE_SLEEP : Z_WAKE_TIMEOUT));
                current->kind = 0;
            } else if (current->kind == 2 && current->count) {
                assert(status == Z_WAIT_DONE && result == Z_OK && reason == Z_WAKE_MESSAGE);
                assert(output_marker(cell) == model_pop(current));
                current->kind = 0;
            } else {
                assert(status == Z_WAIT_PENDING);
            }
        } else if (choice == 5) {
            z_wait_cancel(&waits, cell);
            current->kind = 0;
        } else if (choice == 6) {
            assert(z_broker_revoke_cap(&broker, cell, authorities[cell]) == Z_OK);
            current->count = 0;
            int64_t delegated = z_broker_delegate(&broker, cell, parents[cell],
                                                   endpoint(cell), Z_RIGHT(Z_FILE_READ));
            assert(delegated > 0);
            authorities[cell] = (uint64_t)delegated;
        } else if (choice == 7 && current->kind) {
            unsigned copy_count = copies[cell];
            z_broker_revoke(&broker, cell);
            z_policy_fault(&broker.policies[cell], now);
            int result;
            enum z_wake_reason reason;
            assert(poll(cell, now, &result, &reason) == Z_WAIT_CANCELLED);
            assert(copies[cell] == copy_count);
            current->kind = current->count = 0;
            /* Fresh fixture-like policy boot avoids conflating generated wait
             * assertions with Rust's separately tested restart limit. */
            assert(z_policy_poll(&broker.policies[cell], now + 4) == 1);
            broker.policies[cell].faults = broker.policies[cell].restarts = 0;
            assert(z_broker_refresh(&broker) == Z_OK);
            parents[cell] = cap(cell, cell, Z_RIGHT(Z_FILE_READ) | Z_RIGHT_DELEGATE);
            int64_t delegated = z_broker_delegate(&broker, cell, parents[cell],
                                                   endpoint(cell), Z_RIGHT(Z_FILE_READ));
            assert(delegated > 0);
            authorities[cell] = (uint64_t)delegated;
        }
        for (unsigned index = 0; index < Z_CELL_COUNT; ++index) {
            assert(broker.queues[index].count == model[index].count);
            assert(waits.entries[index].kind == model[index].kind);
            assert(z_wait_runnable(&waits, &broker, index) == !model[index].kind);
            if (model[index].kind)
                assert(waits.entries[index].deadline == model[index].deadline);
        }
        unsigned after = random_next() % Z_CELL_COUNT;
        int expected = -1;
        for (unsigned offset = 1; offset <= Z_CELL_COUNT; ++offset) {
            unsigned index = (after + offset) % Z_CELL_COUNT;
            if (!model[index].kind) { expected = (int)index; break; }
        }
        assert(z_wait_next(&waits, &broker, after) == expected);
    }
}

int main(void)
{
    immediate_and_zero();
    deadlines_and_overflow();
    enqueue_transitions_and_timeout_order();
    revocation_and_valid_fifo();
    cancellation_and_generation_ownership();
    interrupted_storage_preserves_unrelated_waits_and_memory();
    invalid_buffers_and_deferred_copy_failure();
    idle_and_fair_selection();
    generated_model();
    puts("C waits: immediate/zero, deadlines/overflow, enqueue transitions, authority/FIFO, timeout ordering, generation cancellation, checked copies, unrelated preservation, idle/fairness, seed=0x5a17e39b, 50000 model steps PASS");
    return 0;
}
