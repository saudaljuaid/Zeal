#include <zeal/manifest.h>
#include <zeal/abi.h>

_Static_assert(Z_MANIFEST_ABI == Z_ABI_VERSION, "manifest cell ABI");
_Static_assert(Z_MANIFEST_RIGHTS == Z_RIGHT_ALL, "manifest operation rights");

static uint32_t read32(const uint8_t *bytes)
{
    return (uint32_t)bytes[0] | (uint32_t)bytes[1] << 8 |
           (uint32_t)bytes[2] << 16 | (uint32_t)bytes[3] << 24;
}

static uint64_t read64(const uint8_t *bytes)
{
    return (uint64_t)read32(bytes) | (uint64_t)read32(bytes + 4) << 32;
}

static bool fail(enum z_manifest_error *error, enum z_manifest_error reason)
{
    if (error != NULL)
        *error = reason;
    return false;
}

int z_manifest_slot(const struct z_manifest *manifest, uint32_t identity)
{
    if (manifest == NULL || manifest->cell_count > Z_MANIFEST_CELL_MAX || identity == 0)
        return -1;
    for (unsigned i = 0; i < manifest->cell_count; ++i)
        if (manifest->cells[i].identity == identity)
            return (int)i;
    return -1;
}

bool z_manifest_memory_pages(uint32_t stack_budget, uint32_t writable_budget,
                              uint16_t *stack_pages, uint16_t *heap_pages)
{
    if (stack_pages == NULL || heap_pages == NULL ||
        stack_budget < Z_MANIFEST_STACK_MIN || stack_budget > Z_MANIFEST_STACK_MAX ||
        writable_budget < stack_budget || writable_budget > Z_MANIFEST_WRITABLE_MAX)
        return false;
    uint32_t heap = writable_budget - stack_budget;
    if (heap > Z_MANIFEST_HEAP_MAX)
        return false;
    uint32_t stack = (stack_budget + Z_MANIFEST_PAGE_SIZE - 1) / Z_MANIFEST_PAGE_SIZE;
    heap = (heap + Z_MANIFEST_PAGE_SIZE - 1) / Z_MANIFEST_PAGE_SIZE;
    if (stack + heap > Z_MANIFEST_PAGES_PER_CELL)
        return false;
    *stack_pages = (uint16_t)stack;
    *heap_pages = (uint16_t)heap;
    return true;
}

static bool valid_name(const uint8_t name[16])
{
    bool ended = false;
    for (unsigned i = 0; i < 16; ++i) {
        uint8_t ch = name[i];
        if (ch == 0) {
            if (i == 0)
                return false;
            ended = true;
        } else if (ended || !((ch >= 'a' && ch <= 'z') ||
                   (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') ||
                   ch == '_' || ch == '-')) {
            return false;
        }
    }
    return ended;
}

bool z_manifest_validate(const void *data, size_t length,
                         const struct z_image_catalog *catalog, size_t catalog_count,
                         struct z_manifest *output, enum z_manifest_error *error)
{
    if (data == NULL || catalog == NULL || output == NULL || catalog_count == 0 ||
        catalog_count > Z_MANIFEST_CELL_MAX || length > Z_MANIFEST_ARTIFACT_MAX)
        return fail(error, Z_MANIFEST_ARGUMENT);
    if (length < sizeof(struct z_manifest_header))
        return fail(error, Z_MANIFEST_TRUNCATED);
    const uint8_t *bytes = data;
    if (read32(bytes) != Z_MANIFEST_MAGIC)
        return fail(error, Z_MANIFEST_MAGIC_ERROR);
    if (read32(bytes + 4) != Z_MANIFEST_VERSION)
        return fail(error, Z_MANIFEST_VERSION_ERROR);
    uint32_t cell_count = read32(bytes + 12), grant_count = read32(bytes + 16);
    if (cell_count == 0 || cell_count > Z_MANIFEST_CELL_MAX ||
        grant_count > Z_MANIFEST_GRANT_MAX)
        return fail(error, Z_MANIFEST_COUNT_ERROR);
    size_t expected = sizeof(struct z_manifest_header) +
        cell_count * sizeof(struct z_manifest_cell) + grant_count * sizeof(struct z_manifest_grant);
    if (length != expected || read32(bytes + 8) != expected)
        return fail(error, Z_MANIFEST_SIZE_ERROR);
    if (read32(bytes + 20) || read32(bytes + 24) || read32(bytes + 28))
        return fail(error, Z_MANIFEST_RESERVED_ERROR);
    for (unsigned i = 0; i < catalog_count; ++i) {
        if (catalog[i].identity == 0 || catalog[i].data == NULL || catalog[i].length == 0 ||
            catalog[i].length > Z_MANIFEST_IMAGE_MAX)
            return fail(error, Z_MANIFEST_IMAGE_ERROR);
        for (unsigned j = 0; j < i; ++j)
            if (catalog[i].identity == catalog[j].identity)
                return fail(error, Z_MANIFEST_IMAGE_ERROR);
    }
    struct z_manifest parsed = { .cell_count = cell_count, .grant_count = grant_count };
    unsigned total_pages = 0, active = 0;
    for (unsigned i = 0; i < cell_count; ++i) {
        const uint8_t *record = bytes + sizeof(struct z_manifest_header) +
            i * sizeof(struct z_manifest_cell);
        struct z_manifest_cell *cell = &parsed.cells[i];
        cell->identity = read32(record);
        cell->image = read32(record + 4);
        cell->abi = read32(record + 8);
        cell->flags = read32(record + 12);
        cell->entry = read64(record + 16);
        cell->image_budget = read32(record + 24);
        cell->stack_budget = read32(record + 28);
        cell->writable_budget = read32(record + 32);
        cell->boot_config = read32(record + 36);
        cell->restart_limit = read32(record + 40);
        cell->restart_delay = read32(record + 44);
        for (unsigned j = 0; j < sizeof(cell->name); ++j)
            cell->name[j] = record[48 + j];
        if (cell->identity == 0)
            return fail(error, Z_MANIFEST_IDENTITY_ERROR);
        for (unsigned j = 0; j < i; ++j)
            if (parsed.cells[j].identity == cell->identity)
                return fail(error, Z_MANIFEST_IDENTITY_ERROR);
        if (!valid_name(cell->name))
            return fail(error, Z_MANIFEST_NAME_ERROR);
        if (cell->flags & ~((uint32_t)Z_MANIFEST_ACTIVE))
            return fail(error, Z_MANIFEST_RESERVED_ERROR);
        active += !!(cell->flags & Z_MANIFEST_ACTIVE);
        if (cell->abi != Z_MANIFEST_ABI)
            return fail(error, Z_MANIFEST_ABI_ERROR);
        const struct z_image_catalog *image = NULL;
        for (unsigned j = 0; j < catalog_count; ++j)
            if (catalog[j].identity == cell->image)
                image = &catalog[j];
        if (image == NULL)
            return fail(error, Z_MANIFEST_IMAGE_ERROR);
        if (cell->entry != image->entry || cell->entry != UINT64_C(0x40000000))
            return fail(error, Z_MANIFEST_ENTRY_ERROR);
        uint16_t stack, heap;
        if (cell->image_budget == 0 || cell->image_budget > Z_MANIFEST_IMAGE_MAX ||
            image->length > cell->image_budget ||
            !z_manifest_memory_pages(cell->stack_budget, cell->writable_budget, &stack, &heap))
            return fail(error, Z_MANIFEST_BUDGET_ERROR);
        total_pages += stack + heap;
        if (total_pages > Z_MANIFEST_POOL_PAGES)
            return fail(error, Z_MANIFEST_BUDGET_ERROR);
        if (cell->boot_config > Z_MANIFEST_CONFIG_MAX)
            return fail(error, Z_MANIFEST_CONFIG_ERROR);
        if (cell->restart_limit != Z_MANIFEST_RESTART_LIMIT ||
            cell->restart_delay != Z_MANIFEST_RESTART_DELAY)
            return fail(error, Z_MANIFEST_LIFECYCLE_ERROR);
    }
    if (active == 0)
        return fail(error, Z_MANIFEST_CONFIG_ERROR);
    for (unsigned i = 0; i < grant_count; ++i) {
        const uint8_t *record = bytes + sizeof(struct z_manifest_header) +
            cell_count * sizeof(struct z_manifest_cell) + i * sizeof(struct z_manifest_grant);
        struct z_manifest_grant *grant = &parsed.grants[i];
        grant->holder = read32(record);
        grant->target = read32(record + 4);
        grant->rights = read32(record + 8);
        grant->flags = read32(record + 12);
        if (z_manifest_slot(&parsed, grant->holder) < 0 ||
            z_manifest_slot(&parsed, grant->target) < 0)
            return fail(error, Z_MANIFEST_REFERENCE_ERROR);
        if (grant->flags)
            return fail(error, Z_MANIFEST_RESERVED_ERROR);
        if ((grant->rights & ~((uint32_t)Z_MANIFEST_RIGHTS)) ||
            !(grant->rights & Z_RIGHT_OPERATIONS))
            return fail(error, Z_MANIFEST_RIGHTS_ERROR);
        for (unsigned j = 0; j < i; ++j)
            if (parsed.grants[j].holder == grant->holder &&
                parsed.grants[j].target == grant->target)
                return fail(error, Z_MANIFEST_DUPLICATE_GRANT);
    }
    *output = parsed;
    if (error != NULL)
        *error = Z_MANIFEST_OK;
    return true;
}

const char *z_manifest_diagnostic(enum z_manifest_error error)
{
    static const char *const names[] = {
        "valid", "invalid argument", "truncated header", "bad magic", "unsupported version",
        "inconsistent artifact size", "unsupported record count", "nonzero reserved field",
        "invalid or duplicate cell identity", "invalid diagnostic name", "invalid image identity",
        "unsupported cell ABI", "invalid image entry", "impossible memory budget",
        "unsupported boot configuration", "unsupported lifecycle policy", "invalid grant reference",
        "malformed operation rights", "duplicate initial grant"
    };
    return (unsigned)error < sizeof(names) / sizeof(*names) ? names[error] : "unknown manifest error";
}
