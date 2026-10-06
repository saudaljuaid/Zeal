#ifndef ZEAL_POLICY_H
#define ZEAL_POLICY_H

#include <stdint.h>
#include <zeal/abi.h>

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
int32_t z_policy_check(const struct z_policy_state *state);

struct z_boot_grant {
    uint32_t holder;
    uint32_t target;
    uint32_t rights;
    uint32_t reserved;
};

struct z_cap_entry {
    uint64_t epoch;
    uint64_t holder;
    uint64_t target;
    uint64_t parent;
    uint64_t issuer;
    uint32_t rights;
    uint32_t live;
};

struct z_cap_root {
    struct z_boot_grant grant;
    uint64_t holder_generation;
    uint64_t target_generation;
};

struct z_cap_table {
    struct z_cap_entry entries[Z_CAPACITY];
    struct z_cap_root roots[Z_BOOT_GRANTS];
    uint64_t next_epoch;
    uint32_t root_count;
    uint32_t reserved;
};

_Static_assert(sizeof(struct z_boot_grant) == 16, "boot grant policy ABI");
_Static_assert(sizeof(struct z_cap_entry) == 48, "capability policy ABI");
_Static_assert(sizeof(struct z_cap_root) == 32, "root policy ABI");
_Static_assert(sizeof(struct z_cap_table) == 2064, "table policy ABI");

void z_caps_init(struct z_cap_table *table);
int32_t z_caps_configure(struct z_cap_table *table,
                         const struct z_boot_grant *grants, uint32_t count);
int32_t z_caps_refresh(struct z_cap_table *table, const struct z_policy_state *states);
int32_t z_caps_check(const struct z_cap_table *table,
                     const struct z_policy_state *states, uint64_t holder,
                     uint64_t cap, uint64_t target, uint32_t rights);
int64_t z_caps_find(const struct z_cap_table *table,
                    const struct z_policy_state *states, uint64_t holder,
                    uint64_t target, uint32_t rights);
int64_t z_caps_delegate(struct z_cap_table *table,
                        const struct z_policy_state *states, uint64_t caller,
                        uint64_t parent, uint64_t holder, uint32_t rights);
int32_t z_caps_query(const struct z_cap_table *table,
                     const struct z_policy_state *states, uint64_t caller,
                     uint64_t cap, struct z_cap_info *info);
int32_t z_caps_revoke(struct z_cap_table *table,
                      const struct z_policy_state *states, uint64_t caller, uint64_t cap);
void z_caps_invalidate(struct z_cap_table *table, uint32_t cell);

#endif
