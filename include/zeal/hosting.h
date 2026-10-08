#ifndef ZEAL_HOSTING_H
#define ZEAL_HOSTING_H

#include <stdbool.h>
#include <zeal/arch.h>
#include <zeal/hosting_policy.h>
#include <zeal/wait.h>

enum z_runtime_origin { Z_RUNTIME_FREE, Z_RUNTIME_ROOT, Z_RUNTIME_CHILD };

/* The runtime registry is separate from sealed images and boot root records.
 * A retained terminal child still occupies this record and its runtime slot. */
struct z_runtime_record {
    struct z_manifest_cell config;
    uint64_t instance, control, parent_instance, parent_endpoint;
    uint64_t creation, parent_channel;
    uint64_t storage_endpoint, storage_read, storage_reply;
    uint32_t origin, published, parent_slot, template_id;
    uint32_t depth, allocated_pages, reserved_slots, reserved_pages;
    uint32_t last_reason, role;
};

enum z_runtime_event_kind {
    Z_RUNTIME_REQUEST, Z_RUNTIME_RESERVE, Z_RUNTIME_SPACE, Z_RUNTIME_CHANNEL,
    Z_RUNTIME_PUBLISH, Z_RUNTIME_ABORT, Z_RUNTIME_RESULT, Z_RUNTIME_STATUS,
    Z_RUNTIME_STOP, Z_RUNTIME_REAP, Z_RUNTIME_FAULT, Z_RUNTIME_BACKOFF,
    Z_RUNTIME_RESTART, Z_RUNTIME_REBIND, Z_RUNTIME_REVOKE, Z_RUNTIME_CANCEL,
    Z_RUNTIME_INVALIDATE, Z_RUNTIME_CLEANUP, Z_RUNTIME_RETURN, Z_RUNTIME_DOMAIN,
    Z_RUNTIME_EVENT_COUNT
};

struct z_runtime_event {
    uint32_t kind, caller, cell;
    int32_t result;
    uint64_t caller_endpoint, request;
    struct z_runtime_record record;
    struct z_host_transaction transaction;
    uint64_t parent_cap, child_cap;
    struct z_wait_entry wait;
    uint32_t queued, retired_pages;
    struct z_domain_status domain;
};

/* Kernel callbacks use checked physical backing and the x86 architecture.
 * Sanitized host fixtures inject ordinary failures through this same engine.
 * No callback selection or injection mechanism is exposed to user cells. */
struct z_runtime_callbacks {
    bool (*range)(void *, unsigned, uint64_t, size_t, bool);
    bool (*copy_in)(void *, unsigned, void *, uint64_t, size_t);
    bool (*copy_out)(void *, unsigned, uint64_t, const void *, size_t);
    bool (*space_init)(void *, unsigned, const void *, size_t,
                       const struct z_manifest_cell *);
    bool (*space_reset)(void *, unsigned, const void *, size_t,
                        const struct z_manifest_cell *);
    void (*space_release)(void *, unsigned);
    bool (*frame_init)(void *, unsigned, struct z_frame *);
    unsigned (*space_pages)(void *, unsigned);
    bool (*memory_check)(void *);
    void (*trace)(void *, const struct z_runtime_event *);
};

struct z_runtime {
    struct z_runtime_record records[Z_CELL_COUNT];
    struct z_host_table hierarchy;
    struct z_broker *broker;
    struct z_wait_table *waits;
    struct z_frame *frames;
    const struct z_manifest *manifest;
    const struct z_image_catalog *catalog;
    size_t catalog_count;
    const struct z_runtime_callbacks *callbacks;
    void *context;
    uint32_t next_identity, initialized;
};

/* Internal causal evidence captured from the exact checked caller buffers.
 * This is neither a user ABI object nor an authority-bearing kernel record.
 * Input is copied before a management operation can overwrite an overlapping
 * output; output is copied only after successful production completion. */
union z_management_input {
    struct z_create_request create;
    struct z_rebind_request rebind;
};
union z_management_output {
    struct z_create_result create;
    struct z_cell_status status;
    struct z_domain_status domain;
};
struct z_management_capture {
    union z_management_input input;
    union z_management_output output;
    uint64_t caller_endpoint, call, arg0, arg1, arg2;
    bool input_copied, output_copied;
};

void z_runtime_capture_begin(struct z_runtime *, unsigned, uint64_t,
                              uint64_t, uint64_t, uint64_t,
                              struct z_management_capture *);
void z_runtime_capture_end(struct z_runtime *, unsigned, uint64_t,
                            uint64_t, uint64_t, uint64_t, int,
                            struct z_management_capture *);

int z_runtime_init(struct z_runtime *, struct z_broker *, struct z_wait_table *,
                    struct z_frame *, const struct z_manifest *,
                    const struct z_image_catalog *, size_t,
                    const struct z_runtime_callbacks *, void *);
int z_runtime_create(struct z_runtime *, unsigned, uint64_t, size_t, uint64_t);
int z_runtime_status(struct z_runtime *, unsigned, uint64_t, uint64_t, size_t);
int z_runtime_domain_status(struct z_runtime *, unsigned, uint64_t, uint64_t, size_t);
int z_runtime_stop(struct z_runtime *, unsigned, uint64_t);
int z_runtime_reap(struct z_runtime *, unsigned, uint64_t);
int z_runtime_rebind(struct z_runtime *, unsigned, uint64_t, size_t, uint64_t);
int z_runtime_revoke(struct z_runtime *, unsigned, uint64_t);
int z_runtime_fault(struct z_runtime *, unsigned, uint64_t, uint64_t);
int z_runtime_exit(struct z_runtime *, unsigned);
int z_runtime_poll(struct z_runtime *, unsigned, uint64_t);
int z_runtime_boot(const struct z_runtime *, unsigned, struct z_boot_info *);
bool z_runtime_check(const struct z_runtime *);

#endif
