#include <zeal/memory.h>

static void clear(void *pointer, size_t length)
{
    uint8_t *bytes = pointer;
    for (size_t i = 0; i < length; ++i)
        bytes[i] = 0;
}

bool z_memory_init(struct z_memory_pool *pool, unsigned page_count)
{
    if (pool == NULL || page_count == 0 || page_count > Z_MANIFEST_POOL_PAGES)
        return false;
    clear(pool, sizeof(*pool));
    pool->page_count = (uint16_t)page_count;
    return true;
}

bool z_memory_allocate(struct z_memory_pool *pool, unsigned cell,
                         uint32_t stack_budget, uint32_t writable_budget)
{
    uint16_t stack, heap;
    if (pool == NULL || cell >= Z_MANIFEST_CELL_MAX || pool->page_count == 0 ||
        pool->page_count > Z_MANIFEST_POOL_PAGES || pool->cells[cell].count != 0 ||
        !z_manifest_memory_pages(stack_budget, writable_budget, &stack, &heap))
        return false;
    struct z_memory_allocation allocation = { .stack_pages = stack, .heap_pages = heap };
    unsigned needed = stack + heap;
    for (unsigned i = 0; i < pool->page_count && allocation.count < needed; ++i)
        if (pool->owners[i] == 0)
            allocation.pages[allocation.count++] = (uint16_t)i;
    if (allocation.count != needed)
        return false;
    for (unsigned i = 0; i < allocation.count; ++i) {
        unsigned page = allocation.pages[i];
        clear(pool->data[page], Z_MANIFEST_PAGE_SIZE);
        pool->owners[page] = (uint8_t)(cell + 1);
    }
    pool->cells[cell] = allocation;
    return true;
}

void *z_memory_page(struct z_memory_pool *pool, unsigned cell, unsigned page)
{
    if (pool == NULL || cell >= Z_MANIFEST_CELL_MAX ||
        page >= pool->cells[cell].count || page >= Z_MANIFEST_PAGES_PER_CELL)
        return NULL;
    unsigned physical = pool->cells[cell].pages[page];
    if (physical >= pool->page_count || physical >= Z_MANIFEST_POOL_PAGES ||
        pool->owners[physical] != cell + 1)
        return NULL;
    return pool->data[physical];
}

bool z_memory_reset(struct z_memory_pool *pool, unsigned cell)
{
    if (pool == NULL || cell >= Z_MANIFEST_CELL_MAX || pool->cells[cell].count == 0 ||
        pool->cells[cell].count > Z_MANIFEST_PAGES_PER_CELL)
        return false;
    for (unsigned i = 0; i < pool->cells[cell].count; ++i)
        if (z_memory_page(pool, cell, i) == NULL)
            return false;
    for (unsigned i = 0; i < pool->cells[cell].count; ++i)
        clear(z_memory_page(pool, cell, i), Z_MANIFEST_PAGE_SIZE);
    return true;
}

bool z_memory_release(struct z_memory_pool *pool, unsigned cell)
{
    if (!z_memory_reset(pool, cell))
        return false;
    for (unsigned i = 0; i < pool->cells[cell].count; ++i)
        pool->owners[pool->cells[cell].pages[i]] = 0;
    clear(&pool->cells[cell], sizeof(pool->cells[cell]));
    return true;
}

bool z_memory_check(const struct z_memory_pool *pool)
{
    if (pool == NULL || pool->page_count == 0 || pool->page_count > Z_MANIFEST_POOL_PAGES)
        return false;
    uint8_t seen[Z_MANIFEST_POOL_PAGES] = {0};
    for (unsigned cell = 0; cell < Z_MANIFEST_CELL_MAX; ++cell) {
        const struct z_memory_allocation *allocation = &pool->cells[cell];
        if (allocation->count > Z_MANIFEST_PAGES_PER_CELL ||
            allocation->count != allocation->stack_pages + allocation->heap_pages ||
            allocation->stack_pages > Z_MANIFEST_STACK_MAX / Z_MANIFEST_PAGE_SIZE ||
            allocation->heap_pages > Z_MANIFEST_HEAP_MAX / Z_MANIFEST_PAGE_SIZE)
            return false;
        for (unsigned i = 0; i < allocation->count; ++i) {
            unsigned page = allocation->pages[i];
            if (page >= pool->page_count || seen[page] || pool->owners[page] != cell + 1)
                return false;
            seen[page] = (uint8_t)(cell + 1);
        }
    }
    for (unsigned page = 0; page < Z_MANIFEST_POOL_PAGES; ++page)
        if (pool->owners[page] != seen[page])
            return false;
    return true;
}

bool z_memory_user_range(const struct z_memory_layout *layout,
                         uint64_t address, size_t length, bool write)
{
    if (layout == NULL)
        return false;
    if (z_region_contains(Z_STACK_BASE, layout->stack_size, address, length) ||
        (layout->heap_size && z_region_contains(Z_HEAP_BASE, layout->heap_size, address, length)))
        return true;
    return !write && z_region_contains(Z_IMAGE_BASE, layout->image_size, address, length);
}

static bool checked_copy(struct z_memory_pool *pool, unsigned cell,
                         const struct z_memory_layout *layout, uint64_t address,
                         void *buffer, size_t length, bool write)
{
    if (pool == NULL || cell >= Z_MANIFEST_CELL_MAX || buffer == NULL ||
        !z_memory_user_range(layout, address, length, write))
        return false;
    const struct z_memory_allocation *allocation = &pool->cells[cell];
    if (allocation->count == 0 ||
        layout->stack_size != (uint32_t)allocation->stack_pages * Z_MANIFEST_PAGE_SIZE ||
        layout->heap_size != (uint32_t)allocation->heap_pages * Z_MANIFEST_PAGE_SIZE ||
        layout->image == NULL || layout->image_size == 0 ||
        layout->image_size > Z_MANIFEST_IMAGE_MAX)
        return false;
    uint8_t *bytes = buffer;
    if (z_region_contains(Z_IMAGE_BASE, layout->image_size, address, length)) {
        if (write)
            return false;
        size_t offset = (size_t)(address - Z_IMAGE_BASE);
        for (size_t i = 0; i < length; ++i)
            bytes[i] = layout->image[offset + i];
        return true;
    }
    uint64_t base = address >= Z_HEAP_BASE ? Z_HEAP_BASE : Z_STACK_BASE;
    unsigned first = base == Z_HEAP_BASE ? allocation->stack_pages : 0;
    size_t offset = (size_t)(address - base);
    if (length != 0) {
        unsigned start = first + (unsigned)(offset / Z_MANIFEST_PAGE_SIZE);
        unsigned end = first + (unsigned)((offset + length - 1) / Z_MANIFEST_PAGE_SIZE);
        for (unsigned page = start; page <= end; ++page)
            if (z_memory_page(pool, cell, page) == NULL)
                return false;
    }
    for (size_t i = 0; i < length; ++i) {
        unsigned page = first + (unsigned)((offset + i) / Z_MANIFEST_PAGE_SIZE);
        uint8_t *backing = z_memory_page(pool, cell, page);
        if (backing == NULL)
            return false;
        size_t within = (offset + i) % Z_MANIFEST_PAGE_SIZE;
        if (write)
            backing[within] = bytes[i];
        else
            bytes[i] = backing[within];
    }
    return true;
}

bool z_memory_copy_in(struct z_memory_pool *pool, unsigned cell,
                      const struct z_memory_layout *layout, void *destination,
                      uint64_t source, size_t length)
{
    return checked_copy(pool, cell, layout, source, destination, length, false);
}

bool z_memory_copy_out(struct z_memory_pool *pool, unsigned cell,
                       const struct z_memory_layout *layout, uint64_t destination,
                       const void *source, size_t length)
{
    return checked_copy(pool, cell, layout, destination, (void *)source, length, true);
}
