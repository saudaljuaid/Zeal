#include <stddef.h>
#include <stdbool.h>
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

static uint64_t principal(const struct z_broker *broker, unsigned cell)
{
    return cell < Z_CELL_COUNT ? z_policy_handle(&broker->policies[cell], cell) : 0;
}

static uint32_t operation_right(uint32_t operation)
{
    return operation >= Z_READ && operation <= Z_CAP_ACK ? Z_RIGHT(operation) : 0;
}

static bool delivery_valid(const struct z_broker *broker,
                            const struct z_queued_message *entry)
{
    uint32_t rights = operation_right(entry->message.operation);
    return rights && z_caps_check(&broker->capabilities, broker->policies,
             entry->message.sender, entry->authority, entry->target, rights) == Z_OK;
}

static void compact(struct z_broker *broker)
{
    for (unsigned i = 0; i < Z_CELL_COUNT; ++i) {
        struct z_queue *queue = &broker->queues[i];
        struct z_queue retained = {0};
        for (unsigned n = 0; n < queue->count; ++n) {
            struct z_queued_message copy = queue->entries[(queue->head + n) % Z_QUEUE_DEPTH];
            if (delivery_valid(broker, &copy))
                retained.entries[retained.count++] = copy;
        }
        *queue = retained;
    }
}

void z_broker_init(struct z_broker *broker)
{
    *broker = (struct z_broker){0};
    for (unsigned i = 0; i < Z_CELL_COUNT; ++i)
        z_policy_init(&broker->policies[i], 0);
    z_caps_init(&broker->capabilities);
}

int z_broker_configure(struct z_broker *broker, const struct z_boot_grant *grants,
                       unsigned count)
{
    if (broker == NULL)
        return Z_INVALID;
    return z_caps_configure(&broker->capabilities, grants, count);
}

int z_broker_refresh(struct z_broker *broker)
{
    if (broker == NULL)
        return Z_INVALID;
    return z_caps_refresh(&broker->capabilities, broker->policies);
}

int64_t z_broker_lookup(const struct z_broker *broker, unsigned source,
                        unsigned target)
{
    if (source >= Z_CELL_COUNT || target >= Z_CELL_COUNT)
        return Z_INVALID;
    if (!principal(broker, source))
        return Z_AGAIN;
    uint64_t endpoint = principal(broker, target);
    return endpoint ? (int64_t)endpoint : Z_AGAIN;
}

int64_t z_broker_find(const struct z_broker *broker, unsigned source,
                      uint64_t endpoint, uint32_t rights)
{
    if (source >= Z_CELL_COUNT)
        return Z_INVALID;
    int target = resolve(broker, endpoint);
    if (target < 0)
        return target;
    return z_caps_find(&broker->capabilities, broker->policies,
                        principal(broker, source), endpoint, rights);
}

int64_t z_broker_delegate(struct z_broker *broker, unsigned source,
                          uint64_t parent, uint64_t holder, uint32_t rights)
{
    if (source >= Z_CELL_COUNT)
        return Z_INVALID;
    int target = resolve(broker, holder);
    if (target < 0)
        return target;
    return z_caps_delegate(&broker->capabilities, broker->policies,
                           principal(broker, source), parent, holder, rights);
}

int z_broker_query(const struct z_broker *broker, unsigned source,
                    uint64_t capability, struct z_cap_info *info)
{
    if (source >= Z_CELL_COUNT || info == NULL)
        return Z_INVALID;
    return z_caps_query(&broker->capabilities, broker->policies,
                        principal(broker, source), capability, info);
}

int z_broker_revoke_cap(struct z_broker *broker, unsigned source, uint64_t capability)
{
    if (source >= Z_CELL_COUNT)
        return Z_INVALID;
    int result = z_caps_revoke(&broker->capabilities, broker->policies,
                               principal(broker, source), capability);
    if (result == Z_OK)
        compact(broker);
    return result;
}

int z_broker_send(struct z_broker *broker, unsigned source, uint64_t endpoint,
                  uint64_t capability, const struct z_message *message)
{
    if (source >= Z_CELL_COUNT || message == NULL)
        return Z_INVALID;
    uint64_t sender = principal(broker, source);
    if (!sender)
        return Z_AGAIN;
    int target = resolve(broker, endpoint);
    if (target < 0)
        return target;
    uint32_t rights = operation_right(message->operation);
    if (!rights)
        return Z_INVALID;
    int allowed = z_caps_check(&broker->capabilities, broker->policies,
                               sender, capability, endpoint, rights);
    if (allowed != Z_OK)
        return allowed;
    if (message->length > Z_PAYLOAD_SIZE)
        return Z_TOO_LARGE;
    struct z_queue *queue = &broker->queues[target];
    if (queue->count == Z_QUEUE_DEPTH)
        return Z_AGAIN;
    struct z_queued_message copy = {0};
    copy.message.sender = sender;
    copy.message.operation = message->operation;
    copy.message.length = message->length;
    for (unsigned i = 0; i < message->length; ++i)
        copy.message.payload[i] = message->payload[i];
    copy.authority = capability;
    copy.target = endpoint;
    queue->entries[(queue->head + queue->count) % Z_QUEUE_DEPTH] = copy;
    ++queue->count;
    return Z_OK;
}

int z_broker_receive(struct z_broker *broker, unsigned receiver,
                     struct z_message *message)
{
    if (receiver >= Z_CELL_COUNT || message == NULL)
        return Z_INVALID;
    if (!principal(broker, receiver))
        return Z_AGAIN;
    struct z_queue *queue = &broker->queues[receiver];
    while (queue->count) {
        struct z_queued_message copy = queue->entries[queue->head];
        queue->entries[queue->head] = (struct z_queued_message){0};
        queue->head = (queue->head + 1) % Z_QUEUE_DEPTH;
        --queue->count;
        if (delivery_valid(broker, &copy)) {
            *message = copy.message;
            return Z_OK;
        }
    }
    return Z_AGAIN;
}

void z_broker_revoke(struct z_broker *broker, unsigned cell)
{
    if (cell >= Z_CELL_COUNT)
        return;
    z_caps_invalidate(&broker->capabilities, cell);
    broker->queues[cell] = (struct z_queue){0};
    compact(broker);
}
