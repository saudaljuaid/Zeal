#ifndef ZEAL_IPC_H
#define ZEAL_IPC_H

#include <stdbool.h>
#include <zeal/abi.h>
#include <zeal/policy.h>

struct z_queued_message {
    struct z_message message;
    uint64_t authority;
    uint64_t target;
};

struct z_queue {
    struct z_queued_message entries[Z_QUEUE_DEPTH];
    uint32_t head;
    uint32_t count;
};

struct z_broker {
    struct z_policy_state policies[Z_CELL_COUNT];
    struct z_cap_table capabilities;
    struct z_queue queues[Z_CELL_COUNT];
};

/* Privileged static-grant recovery state. This is not a syscall or a runtime
 * channel entitlement. Missing root grants retry at most once per four ticks;
 * an unrepresentable retry or exhausted pending epoch batch closes recovery. */
#define Z_REFRESH_RETRY_TICKS UINT64_C(4)
struct z_refresh_state {
    uint64_t deadline;
    uint32_t pending, closed;
};
_Static_assert(sizeof(struct z_refresh_state) == 16, "bounded root grant refresh state");
void z_broker_refresh_state_init(struct z_refresh_state *state);
int z_broker_refresh_bounded(struct z_broker *broker, struct z_refresh_state *state,
                              uint64_t now, bool changed);

void z_broker_init(struct z_broker *broker);
int z_broker_configure(struct z_broker *broker, const struct z_boot_grant *grants,
                       unsigned count);
int z_broker_refresh(struct z_broker *broker);
int z_broker_send(struct z_broker *broker, unsigned source, uint64_t endpoint,
                  uint64_t capability, const struct z_message *message);
int z_broker_receive(struct z_broker *broker, unsigned receiver,
                     struct z_message *message);
typedef bool (*z_receive_copy_fn)(void *context, unsigned cell,
                                  uint64_t generation, uint64_t destination,
                                  const struct z_message *message);
int z_broker_receive_checked(struct z_broker *broker, unsigned receiver,
                             uint64_t destination, z_receive_copy_fn copy,
                             void *context);
int64_t z_broker_lookup(const struct z_broker *broker, unsigned source,
                        unsigned target);
void z_broker_revoke(struct z_broker *broker, unsigned cell);
int64_t z_broker_find(const struct z_broker *broker, unsigned source,
                      uint64_t endpoint, uint32_t rights);
int64_t z_broker_delegate(struct z_broker *broker, unsigned source,
                          uint64_t parent, uint64_t holder, uint32_t rights);
int z_broker_query(const struct z_broker *broker, unsigned source,
                    uint64_t capability, struct z_cap_info *info);
int z_broker_revoke_cap(struct z_broker *broker, unsigned source, uint64_t capability);

#endif
