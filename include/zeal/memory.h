#ifndef ZEAL_MEMORY_H
#define ZEAL_MEMORY_H

#include <stdbool.h>
#include <stddef.h>
#include <zeal/abi.h>
#include <zeal/manifest.h>

#define Z_HEAP_BASE UINT64_C(0x40030000)

struct z_memory_allocation {
    uint16_t pages[Z_MANIFEST_PAGES_PER_CELL];
    uint16_t count;
    uint16_t stack_pages;
    uint16_t heap_pages;
};

struct z_memory_pool {
    _Alignas(Z_MANIFEST_PAGE_SIZE) uint8_t data[Z_MANIFEST_POOL_PAGES][Z_MANIFEST_PAGE_SIZE];
    uint8_t owners[Z_MANIFEST_POOL_PAGES];
    struct z_memory_allocation cells[Z_CELL_COUNT];
    uint16_t page_count;
};

struct z_memory_layout {
    const uint8_t *image;
    size_t image_size;
    uint32_t stack_size;
    uint32_t heap_size;
};

bool z_memory_init(struct z_memory_pool *pool, unsigned page_count);
bool z_memory_allocate(struct z_memory_pool *pool, unsigned cell,
                         uint32_t stack_budget, uint32_t writable_budget);
bool z_memory_reset(struct z_memory_pool *pool, unsigned cell);
bool z_memory_release(struct z_memory_pool *pool, unsigned cell);
void *z_memory_page(struct z_memory_pool *pool, unsigned cell, unsigned page);
bool z_memory_check(const struct z_memory_pool *pool);
bool z_memory_user_range(const struct z_memory_layout *layout,
                         uint64_t address, size_t length, bool write);
bool z_memory_copy_in(struct z_memory_pool *pool, unsigned cell,
                      const struct z_memory_layout *layout, void *destination,
                      uint64_t source, size_t length);
bool z_memory_copy_valid(struct z_memory_pool *pool, unsigned cell,
                         const struct z_memory_layout *layout, uint64_t address,
                         size_t length, bool write);
bool z_memory_copy_out(struct z_memory_pool *pool, unsigned cell,
                       const struct z_memory_layout *layout, uint64_t destination,
                       const void *source, size_t length);

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
