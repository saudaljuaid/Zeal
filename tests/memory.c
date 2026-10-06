#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <zeal/memory.h>

static struct z_memory_pool pool;
static uint8_t image[8192];

static void exact_budget_and_rollback(void)
{
    assert(z_memory_init(&pool, 19));
    assert(!z_memory_allocate(&pool, 0, 16384, 81920));
    assert(z_memory_check(&pool));
    for (unsigned i = 0; i < Z_MANIFEST_POOL_PAGES; ++i) assert(pool.owners[i] == 0);
    assert(z_memory_init(&pool, 20));
    assert(z_memory_allocate(&pool, 0, 16384, 81920));
    assert(pool.cells[0].count == 20 && pool.cells[0].stack_pages == 4 && pool.cells[0].heap_pages == 16);
    assert(!z_memory_allocate(&pool, 1, 4096, 4096));
    assert(z_memory_check(&pool));
    for (unsigned i = 0; i < 20; ++i) assert(pool.owners[i] == 1);
    assert(z_memory_release(&pool, 0));
    assert(z_memory_check(&pool));
    assert(z_memory_allocate(&pool, 1, 16384, 81920));
    assert(z_memory_check(&pool));
}

static void independent_backing_and_cold_clear(void)
{
    assert(z_memory_init(&pool, 40));
    assert(z_memory_allocate(&pool, 0, 8192, 16384));
    assert(z_memory_allocate(&pool, 1, 8192, 16384));
    uint8_t *first = z_memory_page(&pool, 0, 0);
    uint8_t *second = z_memory_page(&pool, 1, 0);
    assert(first && second && first != second);
    first[11] = 0xa5; second[11] = 0x5a;
    assert(first[11] == 0xa5 && second[11] == 0x5a);
    assert(z_memory_reset(&pool, 0));
    assert(first[11] == 0 && second[11] == 0x5a);
    for (unsigned restart = 0; restart < 1000; ++restart) {
        first[restart % Z_MANIFEST_PAGE_SIZE] = (uint8_t)(restart + 1);
        assert(z_memory_reset(&pool, 0));
        for (unsigned page = 0; page < pool.cells[0].count; ++page) {
            const uint8_t *bytes = z_memory_page(&pool, 0, page);
            for (unsigned offset = 0; offset < Z_MANIFEST_PAGE_SIZE; ++offset)
                assert(bytes[offset] == 0);
        }
        assert(z_memory_check(&pool));
    }
    for (unsigned restart = 0; restart < 1000; ++restart) {
        first[restart % Z_MANIFEST_PAGE_SIZE] = (uint8_t)(restart + 1);
        assert(z_memory_reset(&pool, 0));
        for (unsigned page = 0; page < pool.cells[0].count; ++page) {
            const uint8_t *bytes = z_memory_page(&pool, 0, page);
            for (unsigned offset = 0; offset < Z_MANIFEST_PAGE_SIZE; ++offset)
                assert(bytes[offset] == 0);
        }
        assert(z_memory_check(&pool));
    }
    assert(z_memory_release(&pool, 1));
    assert(z_memory_check(&pool));
}

static void checked_ranges_and_copies(void)
{
    assert(z_memory_init(&pool, 20));
    assert(z_memory_allocate(&pool, 0, 8192, 16384));
    memset(image, 0x3c, sizeof(image));
    struct z_memory_layout layout = { image, sizeof(image), 8192, 8192 };
    uint8_t bytes[16];
    assert(z_memory_user_range(&layout, Z_IMAGE_BASE, sizeof(bytes), false));
    assert(!z_memory_user_range(&layout, Z_IMAGE_BASE, sizeof(bytes), true));
    assert(!z_memory_user_range(&layout, Z_IMAGE_BASE - 1, 1, false));
    assert(!z_memory_user_range(&layout, Z_STACK_BASE - 1, 1, true));
    assert(!z_memory_user_range(&layout, Z_STACK_BASE + 8192, 1, true));
    assert(!z_memory_user_range(&layout, Z_HEAP_BASE + 8192, 1, true));
    assert(!z_memory_user_range(&layout, UINT64_MAX - 7, 16, true));
    assert(z_memory_copy_in(&pool, 0, &layout, bytes, Z_IMAGE_BASE + 3, sizeof(bytes)));
    for (unsigned i = 0; i < sizeof(bytes); ++i) assert(bytes[i] == 0x3c);
    memset(bytes, 0x91, sizeof(bytes));
    assert(z_memory_copy_out(&pool, 0, &layout, Z_STACK_BASE + 17, bytes, sizeof(bytes)));
    memset(bytes, 0, sizeof(bytes));
    assert(z_memory_copy_in(&pool, 0, &layout, bytes, Z_STACK_BASE + 17, sizeof(bytes)));
    for (unsigned i = 0; i < sizeof(bytes); ++i) assert(bytes[i] == 0x91);
    assert(!z_memory_copy_out(&pool, 0, &layout, Z_IMAGE_BASE, bytes, sizeof(bytes)));
    assert(!z_memory_copy_in(&pool, 0, &layout, bytes, Z_STACK_BASE - 1, sizeof(bytes)));
}

int main(void)
{
    exact_budget_and_rollback();
    independent_backing_and_cold_clear();
    checked_ranges_and_copies();
    puts("C memory: exact budgets, rollback, reuse, independent pages, cold clear, checked copies PASS");
    return 0;
}
