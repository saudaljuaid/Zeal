#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <zeal/ipc.h>
#include <zeal/memory.h>

static uint64_t random_state = UINT64_C(0x52ea19a780de3b61);

static uint64_t random_value(void)
{
    random_state ^= random_state << 13;
    random_state ^= random_state >> 7;
    random_state ^= random_state << 17;
    return random_state;
}

static struct z_message request(unsigned tag, unsigned length)
{
    struct z_message message = {0};
    message.sender = UINT64_MAX;
    message.operation = tag;
    message.length = length;
    memset(message.payload, (int)(tag & 255), sizeof(message.payload));
    return message;
}

static uint64_t endpoint(struct z_broker *broker, unsigned target)
{
    return z_policy_handle(&broker->policies[target], target);
}

static void bounded_fifo(void)
{
    struct z_broker broker;
    z_broker_init(&broker);
    for (unsigned cycle = 0; cycle < 128; ++cycle) {
        for (unsigned i = 0; i < Z_QUEUE_DEPTH; ++i) {
            struct z_message input = request(i + cycle * 8, i % 33);
            assert(z_broker_send(&broker, Z_CLIENT, endpoint(&broker, Z_FS), &input) == Z_OK);
            memset(&input, 0x99, sizeof(input));
        }
        struct z_message extra = request(255, 0);
        assert(z_broker_send(&broker, Z_CLIENT, endpoint(&broker, Z_FS), &extra) == Z_AGAIN);
        for (unsigned i = 0; i < Z_QUEUE_DEPTH; ++i) {
            struct z_message output;
            memset(&output, 0xa5, sizeof(output));
            assert(z_broker_receive(&broker, Z_FS, &output) == Z_OK);
            assert(output.operation == i + cycle * 8);
            assert(output.sender == endpoint(&broker, Z_CLIENT));
            assert(output.length == i % 33);
            for (unsigned n = 0; n < Z_PAYLOAD_SIZE; ++n)
                assert(output.payload[n] == (n < output.length ? (output.operation & 255) : 0));
        }
        struct z_message unchanged = request(123, 5), saved = unchanged;
        assert(z_broker_receive(&broker, Z_FS, &unchanged) == Z_AGAIN);
        assert(memcmp(&unchanged, &saved, sizeof(saved)) == 0);
    }
}

static void authority_and_restarts(void)
{
    struct z_broker broker;
    z_broker_init(&broker);
    struct z_message message = request(1, 1);
    const bool rights[4][4] = {
        { false, true, false, false }, { true, false, true, false },
        { false, true, false, false }, { false, false, false, false }
    };
    for (unsigned source = 0; source < 4; ++source)
        for (unsigned target = 0; target < 4; ++target) {
            assert(z_broker_send(&broker, source, endpoint(&broker, target), &message)
                   == (rights[source][target] ? Z_OK : Z_DENIED));
            assert(z_broker_lookup(&broker, source, target)
                   == (rights[source][target] ? (int64_t)endpoint(&broker, target) : Z_DENIED));
        }
    assert(z_broker_send(&broker, 4, 257, &message) == Z_INVALID);
    assert(z_broker_lookup(&broker, 0, UINT32_MAX) == Z_INVALID);
    assert(z_broker_send(&broker, 0, 0, &message) == Z_INVALID);
    assert(z_broker_send(&broker, 0, UINT64_MAX, &message) == Z_INVALID);
    assert(z_broker_send(&broker, 0, endpoint(&broker, 1), NULL) == Z_INVALID);
    assert(z_broker_receive(&broker, 1, NULL) == Z_INVALID);
    message.length = 33;
    assert(z_broker_send(&broker, 0, endpoint(&broker, 1), &message) == Z_TOO_LARGE);
    message.length = UINT32_MAX;
    assert(z_broker_send(&broker, 0, endpoint(&broker, 1), &message) == Z_TOO_LARGE);
    uint64_t old = endpoint(&broker, Z_BLOCK);
    z_broker_revoke(&broker, Z_BLOCK);
    z_policy_fault(&broker.policies[Z_BLOCK], 10);
    assert(z_broker_send(&broker, Z_FS, old, &message) == Z_AGAIN);
    assert(z_policy_poll(&broker.policies[Z_BLOCK], 13) == 0);
    assert(z_policy_poll(&broker.policies[Z_BLOCK], 14) == 1);
    assert(z_broker_send(&broker, Z_FS, old, &message) == Z_STALE);
    assert(endpoint(&broker, Z_BLOCK) != old);
    struct z_message output;
    assert(z_broker_receive(&broker, Z_FS, &output) == Z_OK);
    assert(output.sender == endpoint(&broker, Z_CLIENT));
    assert(z_broker_receive(&broker, Z_FS, &output) == Z_AGAIN);
    assert(z_broker_receive(&broker, Z_BLOCK, &output) == Z_AGAIN);
    assert(z_broker_receive(&broker, Z_CLIENT, &output) == Z_OK);
}

static void stale_sender_discard(void)
{
    struct z_broker broker;
    z_broker_init(&broker);
    struct z_message message = request(1, 1), output;
    assert(z_broker_send(&broker, Z_BLOCK, endpoint(&broker, Z_FS), &message) == Z_OK);
    assert(z_broker_send(&broker, Z_CLIENT, endpoint(&broker, Z_FS), &message) == Z_OK);
    z_policy_fault(&broker.policies[Z_BLOCK], 0);
    assert(z_broker_receive(&broker, Z_FS, &output) == Z_OK);
    assert(output.sender == endpoint(&broker, Z_CLIENT));
    assert(z_broker_receive(&broker, Z_FS, &output) == Z_AGAIN);
}

static bool reference_range(uint64_t address, size_t length, bool write)
{
    if (length > UINT64_MAX - address)
        return false;
    uint64_t end = address + length;
    bool stack = address >= Z_STACK_BASE && end <= Z_STACK_BASE + Z_STACK_SIZE;
    bool image = address >= Z_IMAGE_BASE && end <= Z_IMAGE_BASE + Z_IMAGE_SIZE;
    return stack || (!write && image);
}

static void address_boundaries(void)
{
    assert(z_canonical_address(0));
    assert(z_canonical_address(UINT64_C(0x00007fffffffffff)));
    assert(z_canonical_address(UINT64_C(0xffff800000000000)));
    assert(z_canonical_address(UINT64_MAX));
    assert(!z_canonical_address(UINT64_C(0x0000800000000000)));
    assert(!z_canonical_address(UINT64_C(0xffff7fffffffffff)));
    const uint64_t boundaries[] = {
        0, 0x10000, Z_IMAGE_BASE, Z_IMAGE_BASE + Z_IMAGE_SIZE,
        Z_STACK_BASE, Z_STACK_BASE + Z_STACK_SIZE, UINT64_MAX - 64, UINT64_MAX
    };
    const size_t sizes[] = { 0, 1, 24, 48, 4096, 65536, SIZE_MAX };
    for (unsigned b = 0; b < sizeof(boundaries) / sizeof(*boundaries); ++b)
        for (int d = -64; d <= 64; ++d)
            for (unsigned n = 0; n < sizeof(sizes) / sizeof(*sizes); ++n)
                for (unsigned write = 0; write < 2; ++write) {
                    uint64_t address = boundaries[b] + (uint64_t)d;
                    assert(z_user_range(address, sizes[n], write) ==
                           reference_range(address, sizes[n], write));
                }
    for (unsigned i = 0; i < 100000; ++i) {
        uint64_t address = random_value();
        size_t size = random_value();
        bool write = random_value() & 1;
        assert(z_user_range(address, size, write) == reference_range(address, size, write));
    }
}

struct model_queue {
    struct z_message list[8];
    unsigned count;
};

static void adversarial_broker(void)
{
    struct z_broker broker;
    struct model_queue model[4] = {0};
    z_broker_init(&broker);
    const unsigned sources[] = { Z_BLOCK, Z_FS, Z_CLIENT, Z_FS };
    const unsigned targets[] = { Z_FS, Z_BLOCK, Z_FS, Z_CLIENT };
    for (unsigned step = 0; step < 100000; ++step) {
        unsigned operation = random_value() % 10;
        unsigned edge = random_value() % 4;
        unsigned target = targets[edge], source = sources[edge];
        struct model_queue *queue = &model[target];
        if (operation < 6) {
            struct z_message input = request(step, random_value() % 33);
            int expected = queue->count == 8 ? Z_AGAIN : Z_OK;
            assert(z_broker_send(&broker, source, endpoint(&broker, target), &input) == expected);
            if (expected == Z_OK) {
                struct z_message *copy = &queue->list[queue->count++];
                *copy = (struct z_message){0};
                copy->sender = endpoint(&broker, source);
                copy->operation = input.operation;
                copy->length = input.length;
                memcpy(copy->payload, input.payload, input.length);
            }
        } else if (operation < 9) {
            struct z_message output;
            assert(z_broker_receive(&broker, target, &output) == (queue->count ? Z_OK : Z_AGAIN));
            if (queue->count) {
                assert(memcmp(&output, &queue->list[0], sizeof(output)) == 0);
                --queue->count;
                memmove(queue->list, queue->list + 1, queue->count * sizeof(output));
            }
        } else {
            unsigned revoked = random_value() % 4;
            z_broker_revoke(&broker, revoked);
            for (unsigned slot = 0; slot < 4; ++slot) {
                if (slot == revoked) {
                    model[slot].count = 0;
                    continue;
                }
                for (unsigned i = 0; i < model[slot].count;) {
                    if ((model[slot].list[i].sender & 255) == revoked + 1) {
                        --model[slot].count;
                        memmove(&model[slot].list[i], &model[slot].list[i + 1],
                                (model[slot].count - i) * sizeof(struct z_message));
                    } else {
                        ++i;
                    }
                }
            }
        }
        for (unsigned slot = 0; slot < 4; ++slot)
            assert(broker.queues[slot].count == model[slot].count);
    }
}

int main(void)
{
    _Static_assert(sizeof(struct z_policy_state) == 32, "Rust policy ABI");
    bounded_fifo();
    authority_and_restarts();
    stale_sender_discard();
    address_boundaries();
    adversarial_broker();
    puts("C IPC: FIFO, authority, revocation, address boundaries, 100000 model steps PASS");
    return 0;
}
