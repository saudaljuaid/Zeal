#ifndef ZEAL_ABI_H
#define ZEAL_ABI_H

#include <stddef.h>
#include <stdint.h>

#define Z_ROOT_COUNT 4u
#define Z_CELL_COUNT 8u
#define Z_IMAGE_BASE UINT64_C(0x40000000)
#define Z_IMAGE_SIZE UINT64_C(0x10000)
#define Z_STACK_BASE UINT64_C(0x40020000)
#define Z_STACK_SIZE UINT64_C(0x4000)
#define Z_WRITABLE_BASE UINT64_C(0x40030000)
#define Z_WRITABLE_SIZE UINT64_C(0x10000)
#define Z_ABI_VERSION 4u
#define Z_PAYLOAD_SIZE 32u
#define Z_QUEUE_DEPTH 8u
#define Z_RIGHT(operation) (UINT32_C(1) << ((operation) - 1u))
#define Z_RIGHT_DELEGATE UINT32_C(0x80000000)
#define Z_RIGHT_OPERATIONS UINT32_C(0x3fffff)
#define Z_RIGHT_ALL (Z_RIGHT_OPERATIONS | Z_RIGHT_DELEGATE)
#define Z_CAPACITY 32u
#define Z_BOOT_GRANTS 16u
#define Z_WAIT_MAX_TICKS UINT64_C(1000)
#define Z_TERMINATION_FAULT_BASE UINT32_C(0x10000)
#define Z_TERMINATION_INITIALIZATION 5u
#define Z_CONSOLE_LIMIT 64u
#define Z_BUILD_ID_SIZE 48u

enum z_call {
    Z_YIELD, Z_SEND, Z_RECV, Z_LOOKUP, Z_REPORT, Z_BOOT, Z_EXIT,
    Z_CAP_FIND, Z_CAP_DELEGATE, Z_CAP_QUERY, Z_CAP_REVOKE, Z_SLEEP, Z_RECV_WAIT,
    Z_CREATE, Z_CELL_STATUS, Z_CELL_STOP, Z_CELL_REAP, Z_CELL_REBIND,
    Z_CREATION_REVOKE, Z_DOMAIN_STATUS, Z_CONSOLE_READ, Z_CONSOLE_WRITE, Z_SYSTEM_INFO
};
enum z_error {
    Z_OK = 0, Z_INVALID = -1, Z_DENIED = -2, Z_STALE = -3,
    Z_AGAIN = -4, Z_BAD_ADDRESS = -5, Z_TOO_LARGE = -6, Z_NO_SPACE = -7,
    Z_TIMEOUT = -8, Z_NOT_FOUND = -9
};
enum z_role { Z_BLOCK, Z_FS, Z_CLIENT, Z_PROBE, Z_SUPERVISOR, Z_WORKER };
enum z_operation {
    Z_READ = 1, Z_READ_REPLY, Z_FILE_READ, Z_FILE_REPLY, Z_CAP_OFFER, Z_CAP_ACK,
    Z_BLOCK_READ, Z_BLOCK_WRITE, Z_BLOCK_REPLY, Z_FILE_OPEN,
    Z_FILE_CHUNK_READ, Z_FILE_WRITE, Z_FILE_CLOSE, Z_FILE_RESULT,
    Z_HOST_REQUEST, Z_HOST_REPLY, Z_SNAPSHOT_CONTROL, Z_SNAPSHOT_READ,
    Z_SNAPSHOT_REPLY, Z_SNAPSHOT_RELEASE, Z_FILE_LIST, Z_FILE_TRUNCATE
};

struct z_message {
    uint64_t sender;
    uint32_t operation;
    uint32_t length;
    uint8_t payload[Z_PAYLOAD_SIZE];
};

/* Additive file-list payload. Integers are encoded little-endian on the wire.
 * metadata < 0 is an error; otherwise name length occupies bits 0..7,
 * read-only status bit 8, and file length bits 16..23. Other bits are zero. */
struct z_file_entry_reply {
    uint64_t request;
    uint32_t index;
    int32_t metadata;
    uint8_t name[16];
};

struct z_boot_info {
    uint32_t abi;
    uint32_t role;
    uint64_t generation;
    uint64_t scenario;
    uint64_t endpoint;
    uint64_t parent_endpoint;
    uint64_t instance;
    uint64_t creation;
    uint64_t parent_channel;
    uint32_t template_id;
    uint32_t depth;
    uint32_t identity;
    uint32_t reserved;
};

/* Additive ABI v4 call; existing boot and IPC layouts remain unchanged. */
struct z_system_info {
    uint32_t abi, console_limit, image_budget, stack_budget, writable_budget, console_entitled;
    uint64_t ticks;
    uint8_t build_id[Z_BUILD_ID_SIZE];
};

struct z_create_request {
    uint64_t authority, request;
    uint32_t template_id, descendant_slots, descendant_pages, reserved;
};

struct z_create_result {
    uint64_t instance, control, endpoint, channel, creation;
    uint32_t slot, identity;
};

struct z_rebind_request {
    uint64_t authority, control, request, reserved;
};

struct z_cell_status {
    uint64_t instance, control, endpoint, domain, parent_instance, parent_endpoint;
    uint64_t generation;
    uint32_t slot, template_id, depth, phase, faults, restarts, reason, own_pages;
    uint32_t reserved_slots, reserved_pages, available_slots, available_pages;
};

struct z_domain_status {
    uint64_t domain, holder, instance;
    uint32_t slot_limit, page_limit, owned_slots, owned_pages;
    uint32_t reserved_slots, reserved_pages, available_slots, available_pages;
    uint32_t max_depth, template_mask, recipe, revoked;
};

struct z_cap_request {
    uint64_t parent;
    uint64_t holder;
    uint32_t rights;
    uint32_t reserved;
};

struct z_cap_info {
    uint64_t holder;
    uint64_t target;
    uint32_t rights;
    uint32_t reserved;
    uint64_t parent;
};

_Static_assert(sizeof(struct z_message) == 48, "message ABI");
_Static_assert(sizeof(struct z_file_entry_reply) == 32, "file entry payload ABI");
_Static_assert(offsetof(struct z_file_entry_reply, index) == 8, "file entry index ABI");
_Static_assert(offsetof(struct z_file_entry_reply, metadata) == 12, "file entry metadata ABI");
_Static_assert(offsetof(struct z_file_entry_reply, name) == 16, "file entry name ABI");
_Static_assert(offsetof(struct z_message, payload) == 16, "message payload ABI");
_Static_assert(sizeof(struct z_boot_info) == 80, "boot ABI");
_Static_assert(sizeof(struct z_system_info) == 80, "system information ABI");
_Static_assert(offsetof(struct z_system_info, ticks) == 24, "system information ticks ABI");
_Static_assert(offsetof(struct z_system_info, build_id) == 32, "system information build ABI");
_Static_assert(offsetof(struct z_boot_info, endpoint) == 24, "boot endpoint ABI");
_Static_assert(offsetof(struct z_boot_info, template_id) == 64, "boot template ABI");
_Static_assert(sizeof(struct z_create_request) == 32, "creation request ABI");
_Static_assert(sizeof(struct z_create_result) == 48, "creation result ABI");
_Static_assert(sizeof(struct z_rebind_request) == 32, "rebind request ABI");
_Static_assert(sizeof(struct z_cell_status) == 104, "cell status ABI");
_Static_assert(sizeof(struct z_domain_status) == 72, "domain status ABI");
_Static_assert(sizeof(struct z_cap_request) == 24, "delegation ABI");
_Static_assert(offsetof(struct z_cap_request, rights) == 16, "delegation rights ABI");
_Static_assert(sizeof(struct z_cap_info) == 32, "capability query ABI");
_Static_assert(offsetof(struct z_cap_info, parent) == 24, "capability parent ABI");

#endif
