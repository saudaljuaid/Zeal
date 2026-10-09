#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <zeal/console.h>
#include <zeal/memory.h>

static struct z_memory_pool pool;
static uint8_t image[Z_IMAGE_SIZE];
static const struct z_memory_layout layout = { image, Z_IMAGE_SIZE, Z_STACK_SIZE, Z_WRITABLE_SIZE };
struct fixture {
    uint8_t input[128], output[128];
    size_t input_size, input_at, output_size, output_limit;
    unsigned ranges, copies_in, copies_out, reads, writes;
    bool reject_in, reject_out;
};

static bool range(void *context, uint64_t address, size_t length, bool write)
{
    struct fixture *f = context; ++f->ranges;
    return z_memory_copy_valid(&pool, 0, &layout, address, length, write);
}
static bool copy_in(void *context, void *destination, uint64_t source, size_t length)
{
    struct fixture *f = context; ++f->copies_in;
    return !f->reject_in && z_memory_copy_in(&pool, 0, &layout, destination, source, length);
}
static bool copy_out(void *context, uint64_t destination, const void *source, size_t length)
{
    struct fixture *f = context; ++f->copies_out;
    return !f->reject_out && z_memory_copy_out(&pool, 0, &layout, destination, source, length);
}
static bool read_byte(void *context, uint8_t *byte)
{
    struct fixture *f = context; ++f->reads;
    if (f->input_at == f->input_size) return false;
    *byte = f->input[f->input_at++]; return true;
}
static bool write_byte(void *context, uint8_t byte)
{
    struct fixture *f = context; ++f->writes;
    if (f->output_size == f->output_limit) return false;
    f->output[f->output_size++] = byte; return true;
}
static const struct z_console_callbacks callbacks = { range, copy_in, copy_out, read_byte, write_byte };

static struct fixture fresh(void)
{
    struct fixture f = { .input_size = 80, .output_limit = sizeof(f.output) };
    for (unsigned i = 0; i < sizeof(f.input); ++i) f.input[i] = (uint8_t)(i + 128);
    return f;
}

static void denied_and_argument_boundaries(void)
{
    struct fixture f = fresh();
    assert(z_console_read(&callbacks, &f, false, Z_WRITABLE_BASE, 64, 0) == Z_DENIED);
    assert(z_console_write(&callbacks, &f, false, Z_WRITABLE_BASE, 64, 0) == Z_DENIED);
    assert(z_console_read(NULL, &f, false, UINT64_MAX, UINT64_MAX, 1) == Z_DENIED);
    assert(!f.ranges && !f.reads && !f.writes && !f.copies_in && !f.copies_out);
    for (unsigned i = 0; i < 2; ++i) {
        int64_t (*call)(const struct z_console_callbacks *, void *, bool, uint64_t, uint64_t, uint64_t) =
            i ? z_console_write : z_console_read;
        assert(call(&callbacks, &f, true, Z_WRITABLE_BASE, 65, 0) == Z_TOO_LARGE);
        assert(call(&callbacks, &f, true, Z_WRITABLE_BASE, UINT64_MAX, 0) == Z_TOO_LARGE);
        assert(call(&callbacks, &f, true, Z_WRITABLE_BASE, 1, 1) == Z_INVALID);
        assert(call(NULL, &f, true, Z_WRITABLE_BASE, 1, 0) == Z_INVALID);
        assert(call(&callbacks, &f, true, UINT64_MAX, 0, 0) == 0);
    }
    assert(!f.ranges && !f.reads && !f.writes);
}

static void invalid_private_addresses(void)
{
    const uint64_t invalid[] = { 0, UINT64_MAX, UINT64_C(0x8000000000000000),
        Z_STACK_BASE - 1, Z_STACK_BASE + Z_STACK_SIZE - 1, Z_WRITABLE_BASE + Z_WRITABLE_SIZE - 1 };
    struct fixture f = fresh();
    for (unsigned i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
        assert(z_console_read(&callbacks, &f, true, invalid[i], 2, 0) == Z_BAD_ADDRESS);
        assert(z_console_write(&callbacks, &f, true, invalid[i], 2, 0) == Z_BAD_ADDRESS);
    }
    assert(z_console_read(&callbacks, &f, true, Z_IMAGE_BASE, 2, 0) == Z_BAD_ADDRESS);
    assert(!f.reads && !f.writes && !f.copies_in && !f.copies_out);
}

static void bounded_transfers_and_partial_device_progress(void)
{
    struct fixture f = fresh();
    assert(z_console_read(&callbacks, &f, true, Z_WRITABLE_BASE, 64, 0) == 64);
    uint8_t actual[64];
    assert(z_memory_copy_in(&pool, 0, &layout, actual, Z_WRITABLE_BASE, sizeof(actual)));
    assert(memcmp(actual, f.input, sizeof(actual)) == 0 && f.reads == 64 && f.copies_out == 1);
    f = fresh(); f.input_size = 3;
    assert(z_console_read(&callbacks, &f, true, Z_WRITABLE_BASE, 64, 0) == 3);
    assert(f.reads == 4 && f.copies_out == 1);
    f = fresh(); f.input_size = 0;
    assert(z_console_read(&callbacks, &f, true, Z_WRITABLE_BASE, 64, 0) == 0);
    assert(f.reads == 1 && f.copies_out == 0);
    f = fresh();
    assert(z_memory_copy_out(&pool, 0, &layout, Z_WRITABLE_BASE, f.input, 64));
    assert(z_console_write(&callbacks, &f, true, Z_WRITABLE_BASE, 64, 0) == 64);
    assert(memcmp(f.output, f.input, 64) == 0 && f.writes == 64 && f.copies_in == 1);
    f = fresh(); f.output_limit = 3;
    assert(z_console_write(&callbacks, &f, true, Z_WRITABLE_BASE, 64, 0) == 3);
    assert(f.writes == 4 && f.output_size == 3);
    f = fresh(); f.output_limit = 0;
    assert(z_console_write(&callbacks, &f, true, Z_WRITABLE_BASE, 64, 0) == 0);
    assert(f.writes == 1 && f.output_size == 0);
    f = fresh(); image[0] = 42;
    assert(z_console_write(&callbacks, &f, true, Z_IMAGE_BASE, 1, 0) == 1);
    assert(f.output[0] == 42); /* Immutable images are valid readable sources. */
    f = fresh(); f.reject_in = true;
    assert(z_console_write(&callbacks, &f, true, Z_WRITABLE_BASE, 64, 0) == Z_BAD_ADDRESS);
    assert(f.writes == 0);
    f = fresh(); f.reject_out = true;
    assert(z_console_read(&callbacks, &f, true, Z_WRITABLE_BASE, 64, 0) == Z_BAD_ADDRESS);
    assert(f.reads == 64);
}

static void own_system_information_checked_copy(void)
{
    struct fixture f = fresh();
    struct z_system_info info = { .abi = 4, .console_limit = 64, .image_budget = 65536,
        .stack_budget = 16384, .writable_budget = 81920, .console_entitled = 0,
        .ticks = 123, .build_id = "test-actual-build" }, actual;
    assert(z_console_system_info(&callbacks, &f, &info, Z_STACK_BASE, 80, 0) == Z_OK);
    assert(z_memory_copy_in(&pool, 0, &layout, &actual, Z_STACK_BASE, sizeof(actual)));
    assert(memcmp(&info, &actual, sizeof(info)) == 0);
    assert(z_console_system_info(&callbacks, &f, &info, Z_IMAGE_BASE, 80, 0) == Z_BAD_ADDRESS);
    assert(z_console_system_info(&callbacks, &f, &info, UINT64_MAX, 80, 0) == Z_BAD_ADDRESS);
    assert(z_console_system_info(&callbacks, &f, &info, Z_STACK_BASE, 79, 0) == Z_INVALID);
    assert(z_console_system_info(&callbacks, &f, &info, Z_STACK_BASE, 81, 0) == Z_INVALID);
    assert(z_console_system_info(&callbacks, &f, &info, Z_STACK_BASE, 80, 1) == Z_INVALID);
    assert(!f.reads && !f.writes); /* Device permission is unnecessary for own info. */
}

int main(void)
{
    assert(z_memory_init(&pool, Z_MANIFEST_POOL_PAGES));
    assert(z_memory_allocate(&pool, 0, Z_STACK_SIZE, Z_STACK_SIZE + Z_WRITABLE_SIZE));
    denied_and_argument_boundaries(); invalid_private_addresses();
    bounded_transfers_and_partial_device_progress(); own_system_information_checked_copy();
    puts("C console: explicit authority, checked private copies, maximum/empty/partial operations and own system info PASS");
    return 0;
}
