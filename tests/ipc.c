#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <zeal/ipc.h>

static struct z_broker broker;
static const struct z_boot_grant initial[] = {
    { Z_BLOCK, Z_FS, Z_RIGHT(Z_READ_REPLY) | Z_RIGHT(Z_BLOCK_REPLY), 0 },
    { Z_FS, Z_BLOCK, Z_RIGHT(Z_READ) | Z_RIGHT(Z_BLOCK_READ) | Z_RIGHT(Z_BLOCK_WRITE), 0 },
    { Z_FS, Z_FS, Z_RIGHT(Z_FILE_READ) | Z_RIGHT_DELEGATE, 0 },
    { Z_FS, Z_CLIENT, Z_RIGHT(Z_FILE_REPLY) | Z_RIGHT(Z_CAP_OFFER) | Z_RIGHT(Z_FILE_RESULT), 0 },
    { Z_CLIENT, Z_FS, Z_RIGHT(Z_FILE_READ) | Z_RIGHT(Z_CAP_ACK) | Z_RIGHT(Z_FILE_OPEN) |
        Z_RIGHT(Z_FILE_CHUNK_READ) | Z_RIGHT(Z_FILE_WRITE) | Z_RIGHT(Z_FILE_CLOSE), 0 },
};

static uint64_t endpoint(unsigned cell)
{
    return z_policy_handle(&broker.policies[cell], cell);
}

static uint64_t grant(unsigned holder, unsigned target, uint32_t rights)
{
    int64_t result = z_broker_find(&broker, holder, endpoint(target), rights);
    assert(result > 0);
    return (uint64_t)result;
}

static void setup(void)
{
    z_broker_init(&broker);
    assert(z_broker_configure(&broker, initial, sizeof(initial) / sizeof(initial[0])) == Z_OK);
    assert(z_broker_refresh(&broker) == Z_OK);
}

static struct z_message message(uint32_t operation, uint64_t marker)
{
    struct z_message result = { .sender = UINT64_MAX, .operation = operation, .length = 8 };
    memcpy(result.payload, &marker, sizeof(marker));
    return result;
}

static void fifo_and_bounded_copy(void)
{
    setup();
    uint64_t cap = grant(Z_FS, Z_BLOCK, Z_RIGHT(Z_READ));
    for (uint64_t i = 0; i < Z_QUEUE_DEPTH; ++i) {
        struct z_message input = message(Z_READ, i);
        assert(z_broker_send(&broker, Z_FS, endpoint(Z_BLOCK), cap, &input) == Z_OK);
    }
    struct z_message extra = message(Z_READ, 9);
    assert(z_broker_send(&broker, Z_FS, endpoint(Z_BLOCK), cap, &extra) == Z_AGAIN);
    for (uint64_t i = 0; i < Z_QUEUE_DEPTH; ++i) {
        struct z_message output;
        uint64_t marker;
        assert(z_broker_receive(&broker, Z_BLOCK, &output) == Z_OK);
        memcpy(&marker, output.payload, sizeof(marker));
        assert(marker == i && output.sender == endpoint(Z_FS));
        assert(output.payload[8] == 0 && output.payload[31] == 0);
    }
    assert(z_broker_receive(&broker, Z_BLOCK, &(struct z_message){0}) == Z_AGAIN);
    assert(z_broker_send(&broker, Z_FS, endpoint(Z_BLOCK), cap, NULL) == Z_INVALID);
    extra.length = Z_PAYLOAD_SIZE + 1;
    assert(z_broker_send(&broker, Z_FS, endpoint(Z_BLOCK), cap, &extra) == Z_TOO_LARGE);
}

static void rights_and_delegation(void)
{
    setup();
    uint64_t parent = grant(Z_FS, Z_FS, Z_RIGHT(Z_FILE_READ) | Z_RIGHT_DELEGATE);
    uint64_t holder = endpoint(Z_CLIENT);
    int64_t child = z_broker_delegate(&broker, Z_FS, parent, holder, Z_RIGHT(Z_FILE_READ));
    assert(child > 0 && (uint64_t)child != parent);
    struct z_message allowed = message(Z_FILE_READ, 1);
    assert(z_broker_send(&broker, Z_CLIENT, endpoint(Z_FS), (uint64_t)child, &allowed) == Z_OK);
    struct z_message forbidden = message(Z_READ, 2);
    assert(z_broker_send(&broker, Z_CLIENT, endpoint(Z_FS), (uint64_t)child, &forbidden) == Z_DENIED);
    assert(z_broker_delegate(&broker, Z_CLIENT, (uint64_t)child, endpoint(Z_BLOCK),
                             Z_RIGHT(Z_READ)) == Z_DENIED);
    assert(z_broker_delegate(&broker, Z_FS, parent, holder,
                             Z_RIGHT(Z_FILE_READ) | Z_RIGHT_DELEGATE | Z_RIGHT(Z_READ)) == Z_DENIED);
    struct z_cap_info info;
    assert(z_broker_query(&broker, Z_CLIENT, (uint64_t)child, &info) == Z_OK);
    assert(info.holder == holder && info.target == endpoint(Z_FS) &&
           info.parent == parent && info.rights == Z_RIGHT(Z_FILE_READ));
    assert(z_broker_query(&broker, Z_BLOCK, (uint64_t)child, &info) == Z_DENIED);
    assert(z_broker_revoke_cap(&broker, Z_CLIENT, (uint64_t)child) == Z_OK);
    assert(broker.queues[Z_FS].count == 0);
    assert(z_broker_send(&broker, Z_CLIENT, endpoint(Z_FS), (uint64_t)child, &allowed) == Z_STALE);
    assert(z_broker_revoke_cap(&broker, Z_CLIENT, (uint64_t)child) == Z_STALE);
    assert(z_broker_send(&broker, Z_CLIENT, endpoint(Z_FS), 0, &allowed) == Z_INVALID);
    assert(z_broker_send(&broker, Z_CLIENT, UINT64_MAX, 1, &allowed) == Z_INVALID);
}

static void queued_revocation_preserves_unrelated_work(void)
{
    setup();
    uint64_t app_cap = grant(Z_CLIENT, Z_FS, Z_RIGHT(Z_FILE_READ));
    uint64_t parent = grant(Z_FS, Z_FS, Z_RIGHT(Z_FILE_READ) | Z_RIGHT_DELEGATE);
    int64_t child = z_broker_delegate(&broker, Z_FS, parent, endpoint(Z_CLIENT), Z_RIGHT(Z_FILE_READ));
    assert(child > 0);
    uint64_t service_cap = grant(Z_FS, Z_BLOCK, Z_RIGHT(Z_READ));
    uint64_t other_cap = grant(Z_BLOCK, Z_FS, Z_RIGHT(Z_READ_REPLY));
    struct z_message app = message(Z_FILE_READ, 1);
    struct z_message delegated = message(Z_FILE_READ, 4);
    struct z_message service = message(Z_READ, 2);
    struct z_message unrelated = message(Z_READ_REPLY, 3);
    assert(z_broker_send(&broker, Z_CLIENT, endpoint(Z_FS), app_cap, &app) == Z_OK);
    assert(z_broker_send(&broker, Z_CLIENT, endpoint(Z_FS), (uint64_t)child, &delegated) == Z_OK);
    assert(z_broker_send(&broker, Z_FS, endpoint(Z_BLOCK), service_cap, &service) == Z_OK);
    assert(z_broker_send(&broker, Z_BLOCK, endpoint(Z_FS), other_cap, &unrelated) == Z_OK);
    assert(z_broker_revoke_cap(&broker, Z_CLIENT, app_cap) == Z_OK);
    assert(z_broker_revoke_cap(&broker, Z_FS, parent) == Z_OK);
    struct z_message output;
    uint64_t marker;
    assert(z_broker_receive(&broker, Z_FS, &output) == Z_OK);
    memcpy(&marker, output.payload, 8);
    assert(marker == 3 && output.sender == endpoint(Z_BLOCK));
    assert(z_broker_receive(&broker, Z_FS, &output) == Z_AGAIN);
    assert(z_broker_receive(&broker, Z_BLOCK, &output) == Z_OK);
    memcpy(&marker, output.payload, 8);
    assert(marker == 2 && output.sender == endpoint(Z_FS));
}

static void restart_reissues_only_fresh_roots(void)
{
    setup();
    uint64_t old_endpoint = endpoint(Z_FS);
    uint64_t old_cap = grant(Z_CLIENT, Z_FS, Z_RIGHT(Z_FILE_READ));
    z_broker_revoke(&broker, Z_FS);
    z_policy_fault(&broker.policies[Z_FS], 100);
    assert(z_policy_poll(&broker.policies[Z_FS], 103) == 0);
    assert(z_policy_poll(&broker.policies[Z_FS], 104) == 1);
    assert(z_broker_refresh(&broker) == Z_OK);
    assert(endpoint(Z_FS) != old_endpoint);
    struct z_message request = message(Z_FILE_READ, 0);
    assert(z_broker_send(&broker, Z_CLIENT, endpoint(Z_FS), old_cap, &request) == Z_STALE);
    uint64_t fresh_cap = grant(Z_CLIENT, Z_FS, Z_RIGHT(Z_FILE_READ));
    assert(fresh_cap != old_cap);
    assert(z_broker_send(&broker, Z_CLIENT, endpoint(Z_FS), fresh_cap, &request) == Z_OK);
    assert(z_broker_receive(&broker, Z_FS, &(struct z_message){0}) == Z_OK);
}

static void capability_table_pressure_is_atomic(void)
{
    setup();
    uint64_t parent = grant(Z_FS, Z_FS, Z_RIGHT(Z_FILE_READ) | Z_RIGHT_DELEGATE);
    uint64_t holder = endpoint(Z_CLIENT);
    unsigned children = 0;
    for (; children < Z_CAPACITY; ++children) {
        int64_t result = z_broker_delegate(&broker, Z_FS, parent, holder, Z_RIGHT(Z_FILE_READ));
        if (result == Z_NO_SPACE) break;
        assert(result > 0);
    }
    assert(children == Z_CAPACITY - (sizeof(initial) / sizeof(initial[0])));
    struct z_cap_info info;
    assert(z_broker_query(&broker, Z_CLIENT, grant(Z_CLIENT, Z_FS, Z_RIGHT(Z_FILE_READ)), &info) == Z_OK);
    assert(z_broker_delegate(&broker, Z_FS, parent, holder, Z_RIGHT(Z_FILE_READ)) == Z_NO_SPACE);
}

static void storage_rights_are_per_operation(void)
{
    setup();
    uint64_t parent = grant(Z_FS, Z_FS, Z_RIGHT(Z_FILE_READ) | Z_RIGHT_DELEGATE);
    int64_t delegated = z_broker_delegate(&broker, Z_FS, parent,
                                          endpoint(Z_CLIENT), Z_RIGHT(Z_FILE_READ));
    assert(delegated > 0);
    struct z_broker before = broker;
    for (unsigned operation = Z_BLOCK_READ; operation <= Z_FILE_RESULT; ++operation) {
        struct z_message input = message(operation, operation);
        assert(z_broker_send(&broker, Z_CLIENT, endpoint(Z_FS),
                             (uint64_t)delegated, &input) == Z_DENIED);
        assert(memcmp(&broker, &before, sizeof(broker)) == 0);
    }
    assert(z_broker_delegate(&broker, Z_FS, parent, endpoint(Z_CLIENT),
                             Z_RIGHT(Z_FILE_WRITE)) == Z_DENIED);
    assert(z_broker_find(&broker, Z_CLIENT, endpoint(Z_BLOCK),
                         Z_RIGHT(Z_BLOCK_WRITE)) == Z_DENIED);
    uint64_t file = grant(Z_CLIENT, Z_FS, Z_RIGHT(Z_FILE_WRITE));
    uint64_t block = grant(Z_FS, Z_BLOCK, Z_RIGHT(Z_BLOCK_WRITE));
    struct z_message write = message(Z_FILE_WRITE, 31);
    assert(z_broker_send(&broker, Z_PROBE, endpoint(Z_FS), file, &write) == Z_DENIED);
    write.operation = Z_BLOCK_WRITE;
    assert(z_broker_send(&broker, Z_CLIENT, endpoint(Z_BLOCK), file, &write) == Z_DENIED);
    assert(z_broker_send(&broker, Z_FS, endpoint(Z_BLOCK), block, &write) == Z_OK);
    struct z_message output;
    assert(z_broker_receive(&broker, Z_BLOCK, &output) == Z_OK);
    assert(output.operation == Z_BLOCK_WRITE && output.sender == endpoint(Z_FS));
    for (unsigned operation = Z_FILE_OPEN; operation <= Z_FILE_CLOSE; ++operation) {
        write = message(operation, operation);
        assert(z_broker_send(&broker, Z_CLIENT, endpoint(Z_FS), file, &write) == Z_OK);
        assert(z_broker_receive(&broker, Z_FS, &output) == Z_OK);
        assert(output.operation == operation && output.sender == endpoint(Z_CLIENT));
    }
    write = message(Z_FILE_RESULT, 1);
    uint64_t reply = grant(Z_FS, Z_CLIENT, Z_RIGHT(Z_FILE_RESULT));
    assert(z_broker_send(&broker, Z_FS, endpoint(Z_CLIENT), reply, &write) == Z_OK);
    assert(z_broker_receive(&broker, Z_CLIENT, &output) == Z_OK);
    for (unsigned operation = 0; operation <= Z_FILE_RESULT + 1; operation += Z_FILE_RESULT + 1) {
        write = message(operation, 1);
        assert(z_broker_send(&broker, Z_CLIENT, endpoint(Z_FS), file, &write) == Z_INVALID);
    }
}

static void revoked_storage_is_revalidated_at_delivery(void)
{
    setup();
    uint64_t file = grant(Z_CLIENT, Z_FS, Z_RIGHT(Z_FILE_WRITE));
    uint64_t block = grant(Z_FS, Z_BLOCK, Z_RIGHT(Z_BLOCK_WRITE));
    uint64_t reply = grant(Z_BLOCK, Z_FS, Z_RIGHT(Z_BLOCK_REPLY));
    struct z_message write = message(Z_FILE_WRITE, 100);
    assert(z_broker_send(&broker, Z_CLIENT, endpoint(Z_FS), file, &write) == Z_OK);
    write = message(Z_BLOCK_WRITE, 101);
    assert(z_broker_send(&broker, Z_FS, endpoint(Z_BLOCK), block, &write) == Z_OK);
    write = message(Z_BLOCK_REPLY, 102);
    assert(z_broker_send(&broker, Z_BLOCK, endpoint(Z_FS), reply, &write) == Z_OK);
    struct z_queue saved = broker.queues[Z_BLOCK];
    struct z_policy_state probe = broker.policies[Z_PROBE];
    /* Exercise lazy revalidation independently of eager broker compaction. */
    assert(z_caps_revoke(&broker.capabilities, broker.policies,
                         endpoint(Z_CLIENT), file) == Z_OK);
    struct z_message output;
    assert(z_broker_receive(&broker, Z_FS, &output) == Z_OK);
    assert(output.operation == Z_BLOCK_REPLY && output.sender == endpoint(Z_BLOCK));
    assert(z_broker_receive(&broker, Z_FS, &output) == Z_AGAIN);
    assert(memcmp(&saved, &broker.queues[Z_BLOCK], sizeof(saved)) == 0);
    assert(memcmp(&probe, &broker.policies[Z_PROBE], sizeof(probe)) == 0);
    assert(z_broker_query(&broker, Z_FS, block, &(struct z_cap_info){0}) == Z_OK);
    write = message(Z_FILE_WRITE, 103);
    assert(z_broker_send(&broker, Z_CLIENT, endpoint(Z_FS), file, &write) == Z_STALE);
}

static uint32_t rng = 0x6d2b79f5;
static uint32_t random_next(void)
{
    rng ^= rng << 13; rng ^= rng >> 17; rng ^= rng << 5; return rng;
}

static void generated_transitions(void)
{
    setup();
    uint64_t parent = grant(Z_FS, Z_FS, Z_RIGHT(Z_FILE_READ) | Z_RIGHT_DELEGATE);
    uint64_t cap = 0;
    unsigned expected = 0;
    uint64_t model[Z_QUEUE_DEPTH];
    for (unsigned step = 0; step < 50000; ++step) {
        if (cap == 0) {
            int64_t created = z_broker_delegate(&broker, Z_FS, parent,
                endpoint(Z_FS), Z_RIGHT(Z_FILE_READ));
            assert(created > 0);
            cap = (uint64_t)created;
        }
        unsigned choice = random_next() % 10;
        if (choice < 5) {
            uint64_t marker = random_next();
            struct z_message input = message(Z_FILE_READ, marker);
            int result = z_broker_send(&broker, Z_FS, endpoint(Z_FS), cap, &input);
            assert(result == (expected == Z_QUEUE_DEPTH ? Z_AGAIN : Z_OK));
            if (result == Z_OK) model[expected++] = marker;
        } else if (choice < 7) {
            struct z_message forbidden = message(Z_READ, random_next());
            assert(z_broker_send(&broker, Z_FS, endpoint(Z_FS), cap, &forbidden) == Z_DENIED);
            assert(broker.queues[Z_FS].count == expected);
        } else if (choice < 9) {
            struct z_message output;
            int result = z_broker_receive(&broker, Z_FS, &output);
            assert(result == (expected ? Z_OK : Z_AGAIN));
            if (expected) {
                uint64_t marker;
                memcpy(&marker, output.payload, 8);
                assert(marker == model[0]);
                memmove(model, model + 1, --expected * sizeof(*model));
            }
        } else {
            assert(z_broker_revoke_cap(&broker, Z_FS, cap) == Z_OK);
            expected = 0;
            assert(broker.queues[Z_FS].count == 0);
            struct z_message stale = message(Z_FILE_READ, 0);
            assert(z_broker_send(&broker, Z_FS, endpoint(Z_FS), cap, &stale) == Z_STALE);
            cap = 0;
        }
        assert(broker.queues[Z_FS].count == expected);
    }
}

int main(void)
{
    _Static_assert(sizeof(struct z_policy_state) == 32, "Rust policy ABI");
    _Static_assert(sizeof(struct z_cap_entry) == 48, "Rust capability ABI");
    fifo_and_bounded_copy();
    rights_and_delegation();
    queued_revocation_preserves_unrelated_work();
    restart_reissues_only_fresh_roots();
    capability_table_pressure_is_atomic();
    storage_rights_are_per_operation();
    revoked_storage_is_revalidated_at_delivery();
    generated_transitions();
    puts("C IPC: bounded queues, per-operation storage rights, write denial/revocation/delivery checks, delegation, restart, seed=0x6d2b79f5, 50000 steps PASS");
    return 0;
}
