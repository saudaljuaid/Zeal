#ifndef ZEAL_IPC_H
#define ZEAL_IPC_H

#include <zeal/abi.h>
#include <zeal/policy.h>

struct z_queue {
    struct z_message entries[Z_QUEUE_DEPTH];
    uint32_t head;
    uint32_t count;
};

struct z_broker {
    struct z_policy_state policies[Z_CELL_COUNT];
    struct z_queue queues[Z_CELL_COUNT];
};

void z_broker_init(struct z_broker *broker);
int z_broker_send(struct z_broker *broker, unsigned source, uint64_t endpoint,
                  const struct z_message *message);
int z_broker_receive(struct z_broker *broker, unsigned receiver,
                     struct z_message *message);
int64_t z_broker_lookup(const struct z_broker *broker, unsigned source,
                        unsigned target);
void z_broker_revoke(struct z_broker *broker, unsigned cell);

#endif
