#ifndef ZEAL_MANIFEST_H
#define ZEAL_MANIFEST_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define Z_MANIFEST_CONSTANT(name, value) enum { Z_MANIFEST_##name = value };
#define Z_MANIFEST_BEGIN(name) struct z_manifest_##name {
#define Z_MANIFEST_U32(name) uint32_t name;
#define Z_MANIFEST_U64(name) uint64_t name;
#define Z_MANIFEST_BYTES(name, count) uint8_t name[count];
#define Z_MANIFEST_END(name, size) }; \
    _Static_assert(sizeof(struct z_manifest_##name) == size, "manifest " #name " layout");
#include <zeal/manifest_schema.def>
#undef Z_MANIFEST_CONSTANT
#undef Z_MANIFEST_BEGIN
#undef Z_MANIFEST_U32
#undef Z_MANIFEST_U64
#undef Z_MANIFEST_BYTES
#undef Z_MANIFEST_END

struct z_image_catalog {
    uint32_t identity;
    const void *data;
    size_t length;
    uint64_t entry;
};

struct z_manifest {
    uint32_t cell_count;
    uint32_t grant_count;
    struct z_manifest_cell cells[Z_MANIFEST_CELL_MAX];
    struct z_manifest_grant grants[Z_MANIFEST_GRANT_MAX];
};

enum z_manifest_error {
    Z_MANIFEST_OK, Z_MANIFEST_ARGUMENT, Z_MANIFEST_TRUNCATED,
    Z_MANIFEST_MAGIC_ERROR, Z_MANIFEST_VERSION_ERROR, Z_MANIFEST_SIZE_ERROR,
    Z_MANIFEST_COUNT_ERROR, Z_MANIFEST_RESERVED_ERROR, Z_MANIFEST_IDENTITY_ERROR,
    Z_MANIFEST_NAME_ERROR, Z_MANIFEST_IMAGE_ERROR, Z_MANIFEST_ABI_ERROR,
    Z_MANIFEST_ENTRY_ERROR, Z_MANIFEST_BUDGET_ERROR, Z_MANIFEST_CONFIG_ERROR,
    Z_MANIFEST_LIFECYCLE_ERROR, Z_MANIFEST_REFERENCE_ERROR,
    Z_MANIFEST_RIGHTS_ERROR, Z_MANIFEST_DUPLICATE_GRANT
};

bool z_manifest_validate(const void *data, size_t length,
                         const struct z_image_catalog *catalog, size_t catalog_count,
                         struct z_manifest *output, enum z_manifest_error *error);
const char *z_manifest_diagnostic(enum z_manifest_error error);
int z_manifest_slot(const struct z_manifest *manifest, uint32_t identity);
bool z_manifest_memory_pages(uint32_t stack_budget, uint32_t writable_budget,
                              uint16_t *stack_pages, uint16_t *heap_pages);

#endif
