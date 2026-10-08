#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <zeal/abi.h>
#include <zeal/manifest.h>

#define HEADER_SIZE 40
#define BASE_SIZE (HEADER_SIZE + 4 * 64 + 5 * 16)
#define MAX_SIZE (HEADER_SIZE + 4 * 64 + 16 * 16)
static uint8_t artifact[Z_MANIFEST_ARTIFACT_MAX];
static size_t artifact_length;
static uint8_t images[8][64];
static struct z_image_catalog catalog[8];
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
        size_t at = HEADER_SIZE + i * 64;
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
        size_t at = HEADER_SIZE + 4 * 64 + i * 16;
        put32(at, grants[i][0]); put32(at + 4, grants[i][1]); put32(at + 8, grants[i][2]);
    }
    for (unsigned i = 0; i < 8; ++i)
        catalog[i] = (struct z_image_catalog){ .identity = i + 1, .role = i < 6 ? i : Z_WORKER, .data = images[i],
                                               .length = 64, .entry = Z_IMAGE_BASE };
}

static bool validate(void)
{
    return z_manifest_validate(artifact, artifact_length, catalog, 8, &parsed, NULL);
}

static void reject_at(size_t at, uint32_t value)
{
    base_manifest(); put32(at, value);
    if (validate()) { fprintf(stderr, "manifest unexpectedly accepted offset=%zu value=%u\n", at, value); assert(0); }
}

static void header_and_count_boundaries(void)
{
    base_manifest(); assert(validate());
    for (size_t length = 0; length < HEADER_SIZE; ++length)
        assert(!z_manifest_validate(artifact, length, catalog, 8, &parsed, NULL));
    reject_at(0, 0); reject_at(4, 1); reject_at(8, UINT32_MAX);
    reject_at(12, 0); reject_at(12, UINT32_MAX); reject_at(16, 17);
    reject_at(20, 9); reject_at(24, 9);
    reject_at(28, 1); reject_at(32, 1); reject_at(36, 1);
    assert(!z_manifest_validate(artifact, SIZE_MAX, catalog, 8, &parsed, NULL));
    assert(!z_manifest_validate(artifact, MAX_SIZE + 1, catalog, 8, &parsed, NULL));
    assert(!z_manifest_validate(NULL, artifact_length, catalog, 8, &parsed, NULL));
    assert(!z_manifest_validate(artifact, artifact_length, NULL, 4, &parsed, NULL));
    base_manifest(); put32(8, HEADER_SIZE + 64); put32(12, 1); put32(16, 0); artifact_length = HEADER_SIZE + 64;
    assert(validate());
    base_manifest(); put32(12, 1); put32(16, 0); put32(8, HEADER_SIZE + 64); artifact_length = HEADER_SIZE + 64;
    assert(validate());
}

static void cell_field_boundaries(void)
{
    const size_t cell = HEADER_SIZE;
    reject_at(cell, 0); reject_at(cell, 200); /* duplicate stable identity */
    reject_at(cell + 4, 99); /* unknown image */
    reject_at(cell + 8, 1); reject_at(cell + 8, 2); reject_at(cell + 8, UINT32_MAX);
    reject_at(cell + 12, 2); reject_at(cell + 12, UINT32_MAX);
    base_manifest(); put64(cell + 16, Z_IMAGE_BASE + 1); assert(!validate());
    base_manifest(); put64(cell + 16, UINT64_MAX); assert(!validate());
    reject_at(cell + 24, 0); reject_at(cell + 24, 63); reject_at(cell + 24, UINT32_MAX);
    reject_at(cell + 28, 0); reject_at(cell + 28, 4095); reject_at(cell + 28, 16385);
    reject_at(cell + 32, 0); reject_at(cell + 32, 4095); reject_at(cell + 32, 81921);
    reject_at(cell + 36, Z_MANIFEST_CONFIG_MAX + 1); reject_at(cell + 40, 2); reject_at(cell + 44, UINT32_MAX);
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
    const size_t grant = HEADER_SIZE + 4 * 64;
    reject_at(grant, 999); reject_at(grant + 4, 999);
    reject_at(grant + 8, 0); reject_at(grant + 8, 0x100000); reject_at(grant + 8, UINT32_MAX);
    reject_at(grant + 8, Z_RIGHT_DELEGATE);
    for (unsigned operation = Z_BLOCK_READ; operation <= Z_SNAPSHOT_RELEASE; ++operation) {
        base_manifest(); put32(grant + 8, Z_RIGHT(operation)); assert(validate());
    }
    reject_at(grant + 12, 1);
    base_manifest(); put32(grant + 16, 100); put32(grant + 20, 200); assert(!validate());
    base_manifest(); catalog[0].entry++; assert(!validate());
    base_manifest(); catalog[0].role = Z_WORKER; assert(!validate());
    base_manifest(); catalog[4].role = Z_WORKER + 1; assert(!validate());
    base_manifest(); catalog[0].length = 65537; assert(!validate());
    base_manifest(); catalog[0].length = 0; assert(!validate());
    base_manifest(); catalog[0].data = NULL; assert(!validate());
    base_manifest(); catalog[1].identity = 1; assert(!validate());
    base_manifest(); put32(HEADER_SIZE + 12, 0); put32(HEADER_SIZE + 64 + 12, 0);
    put32(HEADER_SIZE + 128 + 12, 0); put32(HEADER_SIZE + 192 + 12, 0); assert(!validate());
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
    assert(z_manifest_memory_pages(4097, 8194, &stack, &heap));
    assert(stack == 2 && heap == 2); /* Round stack and heap independently. */
    assert(z_manifest_memory_pages(4096, 69632, &stack, &heap));
    assert(stack == 1 && heap == 16);
    assert(!z_manifest_memory_pages(4096, 69633, &stack, &heap));
    assert(!z_manifest_memory_pages(4097, 4096, &stack, &heap));
    assert(!z_manifest_memory_pages(0, 0, &stack, &heap));
    assert(!z_manifest_memory_pages(UINT32_MAX, UINT32_MAX, &stack, &heap));
    assert(!z_manifest_memory_pages(4096, 4096, NULL, &heap));
    assert(!z_manifest_memory_pages(4096, 4096, &stack, NULL));
}

#define TEMPLATE_AT BASE_SIZE
#define DOMAIN_AT (TEMPLATE_AT + 2 * 64)

static void hosting_manifest(void)
{
    base_manifest();
    put32(20, 2); put32(24, 1);
    put32(HEADER_SIZE + 3 * 64 + 36, 21);
    for (unsigned i = 0; i < 2; ++i) {
        size_t at = TEMPLATE_AT + i * 64;
        put32(at, i + 1); put32(at + 4, i + 5); put32(at + 8, Z_ABI_VERSION);
        put64(at + 16, Z_IMAGE_BASE); put32(at + 24, Z_MANIFEST_IMAGE_MAX);
        put32(at + 28, i ? 4096 : 8192); put32(at + 32, i ? 8192 : 16384);
        put32(at + 36, 21); put32(at + 40, 3); put32(at + 44, 4);
        put32(at + 48, i ? 0 : 1); put32(at + 52, i ? 0 : 2); put32(at + 56, 1);
    }
    put32(DOMAIN_AT, 400); put32(DOMAIN_AT + 4, 3);
    put32(DOMAIN_AT + 8, 4); put32(DOMAIN_AT + 12, 48);
    put32(DOMAIN_AT + 16, 2); put32(DOMAIN_AT + 20, 1);
    artifact_length = DOMAIN_AT + 32; put32(8, (uint32_t)artifact_length);
}

static void reject_host_at(size_t at, uint32_t value)
{
    hosting_manifest(); put32(at, value);
    struct z_manifest before;
    memset(&before, 0xa5, sizeof(before)); parsed = before;
    enum z_manifest_error error = Z_MANIFEST_OK;
    if (z_manifest_validate(artifact, artifact_length, catalog, 8, &parsed, &error)) {
        fprintf(stderr, "hosting manifest unexpectedly accepted offset=%zu value=%u\n", at, value);
        assert(0);
    }
    assert(error != Z_MANIFEST_OK);
    assert(memcmp(&parsed, &before, sizeof(parsed)) == 0); /* Atomic privileged parse. */
}

static void sealed_template_and_domain_boundaries(void)
{
    hosting_manifest(); assert(validate());
    hosting_manifest(); catalog[4].role = Z_PROBE; assert(!validate());
    hosting_manifest(); catalog[5].role = Z_CLIENT; assert(!validate());
    hosting_manifest(); assert(validate());
    assert(parsed.cell_count == 4 && parsed.template_count == 2 && parsed.domain_count == 1);
    assert(z_manifest_template_index(&parsed, 1) == 0);
    assert(z_manifest_template_index(&parsed, 2) == 1);
    assert(z_manifest_template_index(&parsed, 0) == -1);
    assert(z_manifest_template_index(&parsed, 9) == -1);
    assert(z_manifest_template_index(NULL, 1) == -1);
    reject_host_at(TEMPLATE_AT, 0); reject_host_at(TEMPLATE_AT, 2);
    reject_host_at(TEMPLATE_AT, 9); reject_host_at(TEMPLATE_AT + 4, 4);
    reject_host_at(TEMPLATE_AT + 4, 9); reject_host_at(TEMPLATE_AT + 8, 3);
    reject_host_at(TEMPLATE_AT + 12, 1); reject_host_at(TEMPLATE_AT + 60, 1);
    reject_host_at(TEMPLATE_AT + 16, (uint32_t)Z_IMAGE_BASE + 1);
    reject_host_at(TEMPLATE_AT + 24, 63); reject_host_at(TEMPLATE_AT + 24, UINT32_MAX);
    reject_host_at(TEMPLATE_AT + 28, 0); reject_host_at(TEMPLATE_AT + 28, UINT32_MAX);
    reject_host_at(TEMPLATE_AT + 32, 8191); reject_host_at(TEMPLATE_AT + 32, UINT32_MAX);
    reject_host_at(TEMPLATE_AT + 36, Z_MANIFEST_CONFIG_MAX + 1); reject_host_at(TEMPLATE_AT + 40, 0);
    reject_host_at(TEMPLATE_AT + 44, 0); reject_host_at(TEMPLATE_AT + 48, 2);
    reject_host_at(TEMPLATE_AT + 48, UINT32_MAX); reject_host_at(TEMPLATE_AT + 52, 0);
    reject_host_at(TEMPLATE_AT + 52, 4); reject_host_at(TEMPLATE_AT + 56, 2);
    reject_host_at(TEMPLATE_AT + 56, 0); /* Domain recipe entitlement must also match. */
    reject_host_at(TEMPLATE_AT + 64 + 48, 1);
    reject_host_at(TEMPLATE_AT + 64 + 52, 1);
    reject_host_at(DOMAIN_AT, 0); reject_host_at(DOMAIN_AT, 100);
    reject_host_at(DOMAIN_AT, 300); reject_host_at(DOMAIN_AT + 4, 0);
    reject_host_at(DOMAIN_AT + 4, 4); reject_host_at(DOMAIN_AT + 4, UINT32_MAX);
    reject_host_at(DOMAIN_AT + 8, 0); reject_host_at(DOMAIN_AT + 8, 5);
    reject_host_at(DOMAIN_AT + 12, 0); reject_host_at(DOMAIN_AT + 12, 49);
    reject_host_at(DOMAIN_AT + 12, UINT32_MAX); reject_host_at(DOMAIN_AT + 16, 0);
    reject_host_at(DOMAIN_AT + 16, 3); reject_host_at(DOMAIN_AT + 20, 0);
    reject_host_at(DOMAIN_AT + 20, 2); reject_host_at(DOMAIN_AT + 24, 1);
    reject_host_at(DOMAIN_AT + 28, 1);
    reject_host_at(HEADER_SIZE + 3 * 64 + 36, 20);
    reject_host_at(HEADER_SIZE + 3 * 64 + 12, 0);
    hosting_manifest(); put32(DOMAIN_AT + 8, 1); put32(DOMAIN_AT + 12, 1);
    put32(DOMAIN_AT + 16, 1); assert(validate()); /* Empty credit is bounded, not amplified. */
    hosting_manifest(); put32(TEMPLATE_AT + 28, 4096); put32(TEMPLATE_AT + 32, 4096);
    assert(validate()); /* Minimum stack, zero heap. */
    hosting_manifest(); put32(TEMPLATE_AT + 28, 16384); put32(TEMPLATE_AT + 32, 81920);
    assert(validate()); /* Maximum approved fixed configuration. */
    hosting_manifest(); put32(TEMPLATE_AT + 28, 4097); put32(TEMPLATE_AT + 32, 8194);
    assert(validate()); /* Independent page rounding. */
    hosting_manifest(); put32(24, 2); memcpy(&artifact[DOMAIN_AT + 32], &artifact[DOMAIN_AT], 32);
    artifact_length += 32; put32(8, (uint32_t)artifact_length); assert(!validate());
    hosting_manifest();
    uint8_t domain[32]; memcpy(domain, &artifact[DOMAIN_AT], sizeof(domain));
    for (unsigned i = 2; i < 8; ++i) {
        memcpy(&artifact[TEMPLATE_AT + i * 64], &artifact[TEMPLATE_AT + 64], 64);
        put32(TEMPLATE_AT + i * 64, i + 1);
    }
    memcpy(&artifact[TEMPLATE_AT + 8 * 64], domain, sizeof(domain));
    put32(20, 8); artifact_length = TEMPLATE_AT + 8 * 64 + 32; put32(8, (uint32_t)artifact_length);
    assert(validate()); assert(parsed.template_count == 8);
    /* Catalog maximum is distinct from root records and template records. */
    assert(!z_manifest_validate(artifact, artifact_length, catalog, 9, &parsed, NULL));
}

int main(void)
{
    header_and_count_boundaries();
    cell_field_boundaries();
    grant_and_catalog_boundaries();
    page_rounding_boundaries();
    sealed_template_and_domain_boundaries();
    puts("C manifest: v2 header, root, template/domain, budget, lifecycle, reference, rights and sealed catalog boundaries PASS");
    return 0;
}
