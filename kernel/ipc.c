#include <stddef.h>
#include <zeal/ipc.h>

static int resolve(const struct z_broker *broker, uint64_t endpoint)
{
    int result = z_policy_resolve(broker->policies, Z_CELL_COUNT, endpoint);
    if (result == Z_POLICY_STALE)
        return Z_STALE;
    if (result == Z_POLICY_UNAVAILABLE)
        return Z_AGAIN;
    return result;
}

void z_broker_init(struct z_broker *broker)
{
    *broker = (struct z_broker){0};
    for (unsigned i = 0; i < Z_CELL_COUNT; ++i)
        z_policy_init(&broker->policies[i], 0);
}

int64_t z_broker_lookup(const struct z_broker *broker, unsigned source,
                        unsigned target)
{
    if (source >= Z_CELL_COUNT || target >= Z_CELL_COUNT)
        return Z_INVALID;
    if (!z_policy_allow(source, target))
        return Z_DENIED;
    uint64_t endpoint = z_policy_handle(&broker->policies[target], target);
    return endpoint ? (int64_t)endpoint : Z_AGAIN;
}

int z_broker_send(struct z_broker *broker, unsigned source, uint64_t endpoint,
                  const struct z_message *message)
{
    if (source >= Z_CELL_COUNT || message == NULL)
        return Z_INVALID;
    if (broker->policies[source].phase != Z_POLICY_READY)
        return Z_AGAIN;
    int target = resolve(broker, endpoint);
    if (target < 0)
        return target;
    if (!z_policy_allow(source, (unsigned)target))
        return Z_DENIED;
    if (message->length > Z_PAYLOAD_SIZE)
        return Z_TOO_LARGE;
    struct z_queue *queue = &broker->queues[target];
    if (queue->count == Z_QUEUE_DEPTH)
        return Z_AGAIN;
    struct z_message copy = {0};
    copy.sender = z_policy_handle(&broker->policies[source], source);
    copy.operation = message->operation;
    copy.length = message->length;
    for (unsigned i = 0; i < message->length; ++i)
        copy.payload[i] = message->payload[i];
    queue->entries[(queue->head + queue->count) % Z_QUEUE_DEPTH] = copy;
    ++queue->count;
    return Z_OK;
}

int z_broker_receive(struct z_broker *broker, unsigned receiver,
                     struct z_message *message)
{
    if (receiver >= Z_CELL_COUNT || message == NULL)
        return Z_INVALID;
    if (broker->policies[receiver].phase != Z_POLICY_READY)
        return Z_AGAIN;
    struct z_queue *queue = &broker->queues[receiver];
    while (queue->count) {
        struct z_message copy = queue->entries[queue->head];
        queue->entries[queue->head] = (struct z_message){0};
        queue->head = (queue->head + 1) % Z_QUEUE_DEPTH;
        --queue->count;
        if (resolve(broker, copy.sender) >= 0) {
            *message = copy;
            return Z_OK;
        }
    }
    return Z_AGAIN;
}

void z_broker_revoke(struct z_broker *broker, unsigned cell)
{
    if (cell >= Z_CELL_COUNT)
        return;
    broker->queues[cell] = (struct z_queue){0};
    for (unsigned i = 0; i < Z_CELL_COUNT; ++i) {
        struct z_queue *queue = &broker->queues[i];
        struct z_queue retained = {0};
        for (unsigned n = 0; n < queue->count; ++n) {
            struct z_message copy = queue->entries[(queue->head + n) % Z_QUEUE_DEPTH];
            if ((copy.sender & 255u) != cell + 1)
                retained.entries[retained.count++] = copy;
        }
        *queue = retained;
    }
}
