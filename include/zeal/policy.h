#ifndef ZEAL_POLICY_H
#define ZEAL_POLICY_H

#include <stdint.h>

#define Z_POLICY_CELLS 4u
#define Z_POLICY_RESTART_LIMIT 3u
#define Z_POLICY_GENERATION_MAX (INT64_MAX >> 8)

enum z_policy_phase {
    Z_POLICY_DORMANT = 0,
    Z_POLICY_READY = 1,
    Z_POLICY_BACKOFF = 2,
    Z_POLICY_QUARANTINED = 3,
    Z_POLICY_STOPPED = 4,
};

enum z_policy_error {
    Z_POLICY_INVALID = -1,
    Z_POLICY_STALE = -2,
    Z_POLICY_UNAVAILABLE = -3,
};

struct z_policy_state {
    uint64_t generation;
    uint64_t deadline;
    uint32_t faults;
    uint32_t restarts;
    uint32_t phase;
    uint32_t reserved;
};

_Static_assert(sizeof(struct z_policy_state) == 32, "policy ABI");

void z_policy_init(struct z_policy_state *state, uint64_t now);
void z_policy_fault(struct z_policy_state *state, uint64_t now);
void z_policy_stop(struct z_policy_state *state);
int32_t z_policy_poll(struct z_policy_state *state, uint64_t now);
uint64_t z_policy_handle(const struct z_policy_state *state, uint32_t slot);
int32_t z_policy_resolve(const struct z_policy_state *states, uint32_t length,
                         uint64_t handle);
int32_t z_policy_allow(uint32_t sender, uint32_t target);
int32_t z_policy_check(const struct z_policy_state *state);

#endif
