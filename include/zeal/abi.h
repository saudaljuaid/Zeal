#ifndef ZEAL_ABI_H
#define ZEAL_ABI_H

#include <stddef.h>
#include <stdint.h>

#define Z_CELL_COUNT 4u
#define Z_IMAGE_BASE UINT64_C(0x40000000)
#define Z_IMAGE_SIZE UINT64_C(0x10000)
#define Z_STACK_BASE UINT64_C(0x40020000)
#define Z_STACK_SIZE UINT64_C(0x4000)
#define Z_WRITABLE_BASE UINT64_C(0x40030000)
#define Z_WRITABLE_SIZE UINT64_C(0x10000)
#define Z_ABI_VERSION 2u
#define Z_PAYLOAD_SIZE 32u
#define Z_QUEUE_DEPTH 8u
#define Z_RIGHT(operation) (UINT32_C(1) << ((operation) - 1u))
#define Z_RIGHT_DELEGATE UINT32_C(0x80000000)
#define Z_RIGHT_OPERATIONS UINT32_C(0x3f)
#define Z_RIGHT_ALL (Z_RIGHT_OPERATIONS | Z_RIGHT_DELEGATE)
#define Z_CAPACITY 32u
#define Z_BOOT_GRANTS 16u
#define Z_WAIT_MAX_TICKS UINT64_C(1000)

enum z_call {
    Z_YIELD, Z_SEND, Z_RECV, Z_LOOKUP, Z_REPORT, Z_BOOT, Z_EXIT,
    Z_CAP_FIND, Z_CAP_DELEGATE, Z_CAP_QUERY, Z_CAP_REVOKE, Z_SLEEP, Z_RECV_WAIT
};
enum z_error {
    Z_OK = 0, Z_INVALID = -1, Z_DENIED = -2, Z_STALE = -3,
    Z_AGAIN = -4, Z_BAD_ADDRESS = -5, Z_TOO_LARGE = -6, Z_NO_SPACE = -7,
    Z_TIMEOUT = -8
};
enum z_role { Z_BLOCK, Z_FS, Z_CLIENT, Z_PROBE };
enum z_operation {
    Z_READ = 1, Z_READ_REPLY, Z_FILE_READ, Z_FILE_REPLY, Z_CAP_OFFER, Z_CAP_ACK
};

struct z_message {
    uint64_t sender;
    uint32_t operation;
    uint32_t length;
    uint8_t payload[Z_PAYLOAD_SIZE];
};

struct z_boot_info {
    uint32_t abi;
    uint32_t role;
    uint64_t generation;
    uint64_t scenario;
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
_Static_assert(offsetof(struct z_message, payload) == 16, "message payload ABI");
_Static_assert(sizeof(struct z_boot_info) == 24, "boot ABI");
_Static_assert(sizeof(struct z_cap_request) == 24, "delegation ABI");
_Static_assert(offsetof(struct z_cap_request, rights) == 16, "delegation rights ABI");
_Static_assert(sizeof(struct z_cap_info) == 32, "capability query ABI");
_Static_assert(offsetof(struct z_cap_info, parent) == 24, "capability parent ABI");

#endif
