#ifndef ZEAL_ABI_H
#define ZEAL_ABI_H

#include <stdint.h>

#define Z_CELL_COUNT 4u
#define Z_IMAGE_BASE UINT64_C(0x40000000)
#define Z_IMAGE_SIZE UINT64_C(0x10000)
#define Z_STACK_BASE UINT64_C(0x40020000)
#define Z_STACK_SIZE UINT64_C(0x4000)
#define Z_ABI_VERSION 1u
#define Z_PAYLOAD_SIZE 32u
#define Z_QUEUE_DEPTH 8u

enum z_call {
    Z_YIELD, Z_SEND, Z_RECV, Z_LOOKUP, Z_REPORT, Z_BOOT, Z_EXIT
};
enum z_error {
    Z_OK = 0, Z_INVALID = -1, Z_DENIED = -2, Z_STALE = -3,
    Z_AGAIN = -4, Z_BAD_ADDRESS = -5, Z_TOO_LARGE = -6
};
enum z_role { Z_BLOCK, Z_FS, Z_CLIENT, Z_PROBE };
enum z_operation { Z_READ = 1, Z_READ_REPLY, Z_FILE_READ, Z_FILE_REPLY };

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

_Static_assert(sizeof(struct z_message) == 48, "message ABI");
_Static_assert(sizeof(struct z_boot_info) == 24, "boot ABI");

#endif
