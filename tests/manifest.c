#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <zeal/abi.h>
#include <zeal/manifest.h>

#define BASE_SIZE (32 + 4 * 64 + 5 * 16)
#define MAX_SIZE (32 + 4 * 64 + 16 * 16)
static uint8_t artifact[MAX_SIZE];
static size_t artifact_length;
static uint8_t images[4][64];
static struct z_image_catalog catalog[4];
static struct z_manifest parsed;

static void put32(size_t at, uint32_t value)
{
    artifact[at] = (uint8_t)value; artifact[at + 1] = (uint8_t)(value >> 8);
    artifact[at + 2] = (uint8_t)(value >> 16); artifact[at + 3] = (uint8_t)(value >> 24);
}

static void put64(size_t at, uint64_t value)
{
    put32(at, (uint32_t)value); put32(at + 4, (uint32_t)(value >> 32));
}

static void base_manifest(void)
{
    memset(artifact, 0, sizeof(artifact));
    put32(0, Z_MANIFEST_MAGIC); put32(4, Z_MANIFEST_VERSION);
    put32(8, BASE_SIZE); put32(12, 4); put32(16, 5); artifact_length = BASE_SIZE;
    for (unsigned i = 0; i < 4; ++i) {
        size_t at = 32 + i * 64;
        put32(at, 100 + i * 100); put32(at + 4, i + 1); put32(at + 8, Z_ABI_VERSION);
        put32(at + 12, Z_MANIFEST_ACTIVE); put64(at + 16, Z_IMAGE_BASE);
        put32(at + 24, 65536); put32(at + 28, 16384); put32(at + 32, 81920);
        put32(at + 36, 0); put32(at + 40, 3); put32(at + 44, 4);
        const char *names[] = { "block", "filesystem", "client", "probe" };
        memcpy(&artifact[at + 48], names[i], strlen(names[i]));
    }
    const uint32_t grants[5][3] = {
        {100, 200, 2}, {200, 100, 1}, {200, 200, 0x80000004},
        {200, 300, 24}, {300, 200, 36},
    };
    for (unsigned i = 0; i < 5; ++i) {
        size_t at = 32 + 4 * 64 + i * 16;
        put32(at, grants[i][0]); put32(at + 4, grants[i][1]); put32(at + 8, grants[i][2]);
    }
    for (unsigned i = 0; i < 4; ++i)
        catalog[i] = (struct z_image_catalog){ .identity = i + 1, .data = images[i],
                                               .length = 64, .entry = Z_IMAGE_BASE };
}

static bool validate(void)
{
    return z_manifest_validate(artifact, artifact_length, catalog, 4, &parsed, NULL);
}

static void reject_at(size_t at, uint32_t value)
{
    base_manifest(); put32(at, value);
    if (validate()) { fprintf(stderr, "manifest unexpectedly accepted offset=%zu value=%u\n", at, value); assert(0); }
}

static void header_and_count_boundaries(void)
{
    base_manifest(); assert(validate());
    for (size_t length = 0; length < 32; ++length)
        assert(!z_manifest_validate(artifact, length, catalog, 4, &parsed, NULL));
    reject_at(0, 0); reject_at(4, 2); reject_at(8, UINT32_MAX);
    reject_at(12, 0); reject_at(12, UINT32_MAX); reject_at(16, 17);
    reject_at(20, 1); reject_at(24, 1); reject_at(28, 1);
    assert(!z_manifest_validate(artifact, SIZE_MAX, catalog, 4, &parsed, NULL));
    assert(!z_manifest_validate(artifact, MAX_SIZE + 1, catalog, 4, &parsed, NULL));
    assert(!z_manifest_validate(NULL, artifact_length, catalog, 4, &parsed, NULL));
    assert(!z_manifest_validate(artifact, artifact_length, NULL, 4, &parsed, NULL));
    base_manifest(); put32(8, 32 + 64); put32(12, 1); put32(16, 0); artifact_length = 32 + 64;
    assert(validate());
    base_manifest(); put32(12, 1); put32(16, 0); put32(8, 32 + 64); artifact_length = 32 + 64;
    assert(validate());
}

static void cell_field_boundaries(void)
{
    const size_t cell = 32;
    reject_at(cell, 0); reject_at(cell, 200); /* duplicate stable identity */
    reject_at(cell + 4, 99); /* unknown image */
    reject_at(cell + 8, 1); reject_at(cell + 8, 2); reject_at(cell + 8, UINT32_MAX);
    reject_at(cell + 12, 2); reject_at(cell + 12, UINT32_MAX);
    base_manifest(); put64(cell + 16, Z_IMAGE_BASE + 1); assert(!validate());
    base_manifest(); put64(cell + 16, UINT64_MAX); assert(!validate());
    reject_at(cell + 24, 0); reject_at(cell + 24, 63); reject_at(cell + 24, UINT32_MAX);
    reject_at(cell + 28, 0); reject_at(cell + 28, 4095); reject_at(cell + 28, 16385);
    reject_at(cell + 32, 0); reject_at(cell + 32, 4095); reject_at(cell + 32, 81921);
    reject_at(cell + 36, 21); reject_at(cell + 40, 2); reject_at(cell + 44, UINT32_MAX);
    base_manifest(); put32(cell + 36, 20); assert(validate());
    base_manifest(); artifact[cell + 48] = 0; assert(!validate());
    base_manifest(); artifact[cell + 48] = 'x'; artifact[cell + 49] = 0; artifact[cell + 50] = 'y'; assert(!validate());
    base_manifest(); memset(&artifact[cell + 48], 'a', 16); assert(!validate());
    base_manifest(); artifact[cell + 48] = '!'; assert(!validate());
    base_manifest(); put32(cell + 28, 4096); put32(cell + 32, 4096); assert(validate());
    base_manifest(); put32(cell + 28, 16384); put32(cell + 32, 16384); assert(validate());
    base_manifest(); put32(cell + 28, 16384); put32(cell + 32, 81920); assert(validate());
}

static void grant_and_catalog_boundaries(void)
{
    const size_t grant = 32 + 4 * 64;
    reject_at(grant, 999); reject_at(grant + 4, 999);
    reject_at(grant + 8, 0); reject_at(grant + 8, 0x4000); reject_at(grant + 8, UINT32_MAX);
    reject_at(grant + 8, Z_RIGHT_DELEGATE);
    for (unsigned operation = Z_BLOCK_READ; operation <= Z_FILE_RESULT; ++operation) {
        base_manifest(); put32(grant + 8, Z_RIGHT(operation)); assert(validate());
    }
    reject_at(grant + 12, 1);
    base_manifest(); put32(grant + 16, 100); put32(grant + 20, 200); assert(!validate());
    base_manifest(); catalog[0].entry++; assert(!validate());
    base_manifest(); catalog[0].length = 65537; assert(!validate());
    base_manifest(); catalog[0].length = 0; assert(!validate());
    base_manifest(); catalog[0].data = NULL; assert(!validate());
    base_manifest(); catalog[1].identity = 1; assert(!validate());
    base_manifest(); put32(32 + 12, 0); put32(32 + 64 + 12, 0);
    put32(32 + 128 + 12, 0); put32(32 + 192 + 12, 0); assert(!validate());
    base_manifest(); put32(8, MAX_SIZE); put32(16, 16); artifact_length = MAX_SIZE;
    for (unsigned i = 0; i < 16; ++i) {
        size_t at = grant + i * 16;
        put32(at, 100 + (i / 4) * 100); put32(at + 4, 100 + (i % 4) * 100);
        put32(at + 8, i == 10 ? 0x80000004 : 1);
    }
    assert(validate());
}

static void page_rounding_boundaries(void)
{
    uint16_t stack, heap;
    assert(z_manifest_memory_pages(4096, 4096, &stack, &heap));
    assert(stack == 1 && heap == 0);
    assert(z_manifest_memory_pages(16384, 81920, &stack, &heap));
    assert(stack == 4 && heap == 16);
    assert(!z_manifest_memory_pages(0, 0, &stack, &heap));
    assert(!z_manifest_memory_pages(UINT32_MAX, UINT32_MAX, &stack, &heap));
    assert(!z_manifest_memory_pages(4096, 4096, NULL, &heap));
    assert(!z_manifest_memory_pages(4096, 4096, &stack, NULL));
}

int main(void)
{
    header_and_count_boundaries();
    cell_field_boundaries();
    grant_and_catalog_boundaries();
    page_rounding_boundaries();
    puts("C manifest: all header, cell, budget, lifecycle, reference, rights and catalog boundaries PASS");
    return 0;
}
