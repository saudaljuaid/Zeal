#ifndef ZEAL_MEMORY_H
#define ZEAL_MEMORY_H

#include <stdbool.h>
#include <stddef.h>
#include <zeal/abi.h>

static inline bool z_canonical_address(uint64_t address)
{
    return address <= UINT64_C(0x00007fffffffffff) ||
           address >= UINT64_C(0xffff800000000000);
}

static inline bool z_region_contains(uint64_t base, uint64_t size,
                                      uint64_t address, size_t length)
{
    return address >= base && address - base <= size &&
           length <= size - (address - base);
}

static inline bool z_user_range(uint64_t address, size_t length, bool write)
{
    if (z_region_contains(Z_STACK_BASE, Z_STACK_SIZE, address, length))
        return true;
    return !write && z_region_contains(Z_IMAGE_BASE, Z_IMAGE_SIZE, address, length);
}

#endif
