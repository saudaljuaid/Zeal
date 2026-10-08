#ifndef ZEAL_HOSTING_POLICY_H
#define ZEAL_HOSTING_POLICY_H

#include <stdint.h>
#include <zeal/policy.h>

#define Z_HOST_SLOTS 8u
#define Z_HOST_ROOTS 4u
#define Z_HOST_INSTANCES 8u
#define Z_HOST_DOMAINS 8u
#define Z_HOST_TEMPLATES 8u
#define Z_HOST_DEPTH 2u
#define Z_HOST_PAGES 128u
#define Z_HOST_DYNAMIC_SLOTS 4u
#define Z_HOST_QUERY 1u
#define Z_HOST_STOP 2u
#define Z_HOST_REAP 4u
#define Z_HOST_RECIPE_RPC 1u
#define Z_HOST_RECIPE_SNAPSHOT 2u
#define Z_HOST_INSTANCE_TAG 0x40u
#define Z_HOST_CONTROL_TAG 0x50u
#define Z_HOST_DOMAIN_TAG 0x60u
#define Z_HOST_TRANSACTION_TAG 0x70u

enum z_host_record_phase { Z_HOST_FREE, Z_HOST_PREPARED, Z_HOST_ACTIVE, Z_HOST_TERMINAL };
enum z_host_reason { Z_HOST_REASON_NONE, Z_HOST_REASON_FAULT, Z_HOST_REASON_STOP,
                     Z_HOST_REASON_OWNER, Z_HOST_REASON_EXHAUSTED };

/* Trusted policy inputs derived from the validated, sealed manifest. */
struct z_host_template {
    uint32_t identity, pages, max_descendant_depth, child_template_mask;
    uint32_t bootstrap_recipe, reserved;
};
struct z_host_root {
    uint32_t slot, template_mask, slot_limit, page_limit;
    uint32_t max_depth, bootstrap_recipe, reserved0, reserved1;
};
struct z_host_request {
    uint64_t domain, request_id;
    uint32_t template_id, descendant_slots, descendant_pages, reserved;
};

/* Preparation exports future identities, but never a resolvable endpoint.
 * Copy this exact result to the checked output before commit publishes READY. */
struct z_host_transaction {
    uint64_t transaction, instance, control, endpoint, domain;
    uint64_t parent_instance, parent_endpoint, request_id;
    uint32_t slot, template_id, depth, pages;
    uint32_t descendant_slots, descendant_pages, template_mask, bootstrap_recipe;
};
struct z_host_status {
    uint64_t instance, control, endpoint, domain, parent_instance, parent_endpoint;
    uint64_t generation;
    uint32_t slot, template_id, depth, phase, faults, restarts, reason, own_pages;
    uint32_t reserved_slots, reserved_pages, available_slots, available_pages;
};

struct z_host_record {
    uint64_t instance, control, transaction, parent_instance, parent_endpoint;
    uint64_t generation, request_id;
    uint32_t slot, parent_slot, parent_domain, domain;
    uint32_t template_id, depth, pages, phase, rights, reason, recipe, reserved;
};
struct z_host_domain {
    uint64_t token, instance, holder, last_request;
    uint32_t parent, holder_slot, template_mask, max_depth, recipe, revoked;
    uint32_t slot_limit, page_limit, owned_slots, owned_pages;
    uint32_t reserved_slots, reserved_pages;
};
struct z_host_table {
    uint64_t history[Z_HOST_SLOTS];
    struct z_host_record records[Z_HOST_INSTANCES];
    struct z_host_domain domains[Z_HOST_DOMAINS];
    struct z_host_template templates[Z_HOST_TEMPLATES];
    struct z_host_root roots[Z_HOST_ROOTS];
    uint64_t next_epoch;
    uint32_t root_mask, root_pages, template_mask, configured;
};
struct z_domain_status;

_Static_assert(sizeof(struct z_host_template) == 24, "hosting template policy ABI");
_Static_assert(sizeof(struct z_host_root) == 32, "hosting root policy ABI");
_Static_assert(sizeof(struct z_host_request) == 32, "hosting request policy ABI");
_Static_assert(sizeof(struct z_host_transaction) == 96, "hosting transaction policy ABI");
_Static_assert(sizeof(struct z_host_status) == 104, "hosting status policy ABI");
_Static_assert(sizeof(struct z_host_record) == 104, "hosting record policy ABI");
_Static_assert(sizeof(struct z_host_domain) == 80, "hosting domain policy ABI");
_Static_assert(sizeof(struct z_host_table) == 1880, "hosting table policy ABI");

void z_host_init(struct z_host_table *table, uint32_t root_mask, uint32_t root_pages);
int32_t z_host_configure(struct z_host_table *table,
                         const struct z_policy_state *states,
                         const struct z_host_template *templates, uint32_t template_count,
                         const struct z_host_root *roots, uint32_t root_count);
int64_t z_host_root_domain(const struct z_host_table *table,
                           const struct z_policy_state *states, uint64_t caller);
int32_t z_host_bind_root(struct z_host_table *table,
                         const struct z_policy_state *states, uint32_t slot);
int32_t z_host_prepare(struct z_host_table *table,
                       const struct z_policy_state *states, uint64_t caller,
                       const struct z_host_request *request, struct z_host_transaction *result);
int32_t z_host_abort(struct z_host_table *table, uint64_t transaction);
int32_t z_host_commit(struct z_host_table *table, struct z_policy_state *states,
                      uint64_t caller, uint64_t transaction);
int32_t z_host_query(const struct z_host_table *table,
                     const struct z_policy_state *states, uint64_t caller,
                     uint64_t control, struct z_host_status *status);
int32_t z_host_stop(struct z_host_table *table, struct z_policy_state *states,
                    uint64_t caller, uint64_t control, uint32_t *cleanup_mask);
int32_t z_host_reap(struct z_host_table *table, struct z_policy_state *states,
                    uint64_t caller, uint64_t control);
int32_t z_host_fault(struct z_host_table *table, struct z_policy_state *states,
                     uint32_t slot, uint64_t now, uint32_t *cleanup_mask);
int32_t z_host_exit(struct z_host_table *table, struct z_policy_state *states,
                    uint32_t slot, uint32_t *cleanup_mask);
int32_t z_host_poll(struct z_host_table *table, struct z_policy_state *states,
                    uint32_t slot, uint64_t now);
int32_t z_host_rebind(struct z_host_table *table,
                      const struct z_policy_state *states, uint64_t caller,
                      uint64_t control, uint64_t creation_domain,
                      uint64_t request_id,
                      struct z_host_transaction *result);
int32_t z_host_revoke(struct z_host_table *table,
                      const struct z_policy_state *states, uint64_t caller, uint64_t domain);
int32_t z_host_domain_query(const struct z_host_table *table,
                            const struct z_policy_state *states, uint64_t caller,
                            uint64_t domain, struct z_domain_status *status);
uint32_t z_host_descendants(const struct z_host_table *table, uint32_t slot);
int32_t z_host_slot(const struct z_host_table *table, uint64_t instance);
int32_t z_host_check(const struct z_host_table *table,
                     const struct z_policy_state *states);

#endif
