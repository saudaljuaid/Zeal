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

int z_manifest_template_index(const struct z_manifest *manifest, uint32_t identity)
{
    if (manifest == NULL || manifest->template_count > Z_MANIFEST_TEMPLATE_MAX || identity == 0)
        return -1;
    for (unsigned i = 0; i < manifest->template_count; ++i)
        if (manifest->templates[i].identity == identity)
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
        catalog_count > Z_MANIFEST_IMAGE_COUNT_MAX || length > Z_MANIFEST_ARTIFACT_MAX)
        return fail(error, Z_MANIFEST_ARGUMENT);
    if (length < sizeof(struct z_manifest_header))
        return fail(error, Z_MANIFEST_TRUNCATED);
    const uint8_t *bytes = data;
    if (read32(bytes) != Z_MANIFEST_MAGIC)
        return fail(error, Z_MANIFEST_MAGIC_ERROR);
    if (read32(bytes + 4) != Z_MANIFEST_VERSION)
        return fail(error, Z_MANIFEST_VERSION_ERROR);
    uint32_t cell_count = read32(bytes + 12), grant_count = read32(bytes + 16);
    uint32_t template_count = read32(bytes + 20), domain_count = read32(bytes + 24);
    if (cell_count == 0 || cell_count > Z_MANIFEST_CELL_MAX ||
        grant_count > Z_MANIFEST_GRANT_MAX || template_count > Z_MANIFEST_TEMPLATE_MAX ||
        domain_count > Z_MANIFEST_DOMAIN_MAX)
        return fail(error, Z_MANIFEST_COUNT_ERROR);
    size_t expected = sizeof(struct z_manifest_header) +
        cell_count * sizeof(struct z_manifest_cell) + grant_count * sizeof(struct z_manifest_grant) +
        template_count * sizeof(struct z_manifest_template) + domain_count * sizeof(struct z_manifest_domain);
    if (length != expected || read32(bytes + 8) != expected)
        return fail(error, Z_MANIFEST_SIZE_ERROR);
    if (read32(bytes + 28) || read32(bytes + 32) || read32(bytes + 36))
        return fail(error, Z_MANIFEST_RESERVED_ERROR);
    for (unsigned i = 0; i < catalog_count; ++i) {
        if (catalog[i].identity == 0 || catalog[i].identity > Z_MANIFEST_IMAGE_COUNT_MAX ||
            catalog[i].role > Z_WORKER || catalog[i].entry != Z_IMAGE_BASE || catalog[i].data == NULL || catalog[i].length == 0 ||
            catalog[i].length > Z_MANIFEST_IMAGE_MAX)
            return fail(error, Z_MANIFEST_IMAGE_ERROR);
        for (unsigned j = 0; j < i; ++j)
            if (catalog[i].identity == catalog[j].identity)
                return fail(error, Z_MANIFEST_IMAGE_ERROR);
    }
    struct z_manifest parsed = { .cell_count = cell_count, .grant_count = grant_count,
        .template_count = template_count, .domain_count = domain_count };
    unsigned total_pages = 0, active = 0, consoles = 0;
    bool console_configuration = false;
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
        if (cell->flags & ~((uint32_t)(Z_MANIFEST_ACTIVE | Z_MANIFEST_CONSOLE)))
            return fail(error, Z_MANIFEST_RESERVED_ERROR);
        if (cell->flags & Z_MANIFEST_CONSOLE) {
            if (!(cell->flags & Z_MANIFEST_ACTIVE) || ++consoles > 1)
                return fail(error, Z_MANIFEST_CONFIG_ERROR);
        }
        active += !!(cell->flags & Z_MANIFEST_ACTIVE);
        if (cell->abi != Z_MANIFEST_ABI)
            return fail(error, Z_MANIFEST_ABI_ERROR);
        const struct z_image_catalog *image = NULL;
        for (unsigned j = 0; j < catalog_count; ++j)
            if (catalog[j].identity == cell->image)
                image = &catalog[j];
        if (image == NULL || cell->image > Z_MANIFEST_CELL_MAX || image->role > Z_PROBE)
            return fail(error, Z_MANIFEST_IMAGE_ERROR);
        if (cell->entry != image->entry || cell->entry != UINT64_C(0x40000000))
            return fail(error, Z_MANIFEST_ENTRY_ERROR);
        uint16_t stack, heap;
        if (cell->image_budget == 0 || cell->image_budget > Z_MANIFEST_IMAGE_MAX ||
            image->length > cell->image_budget ||
            !z_manifest_memory_pages(cell->stack_budget, cell->writable_budget, &stack, &heap))
            return fail(error, Z_MANIFEST_BUDGET_ERROR);
        total_pages += stack + heap;
        if (total_pages > Z_MANIFEST_ROOT_POOL_PAGES)
            return fail(error, Z_MANIFEST_BUDGET_ERROR);
        if (cell->boot_config > Z_MANIFEST_CONFIG_MAX)
            return fail(error, Z_MANIFEST_CONFIG_ERROR);
        console_configuration |= cell->boot_config == 26 || cell->boot_config == 27;
        if (cell->restart_limit != Z_MANIFEST_RESTART_LIMIT ||
            cell->restart_delay != Z_MANIFEST_RESTART_DELAY)
            return fail(error, Z_MANIFEST_LIFECYCLE_ERROR);
    }
    if (active == 0)
        return fail(error, Z_MANIFEST_CONFIG_ERROR);
    if (console_configuration && (consoles != 1 || template_count || domain_count))
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
    size_t templates_at = sizeof(struct z_manifest_header) +
        cell_count * sizeof(struct z_manifest_cell) + grant_count * sizeof(struct z_manifest_grant);
    uint32_t template_mask = 0;
    for (unsigned i = 0; i < template_count; ++i) {
        const uint8_t *record = bytes + templates_at + i * sizeof(struct z_manifest_template);
        struct z_manifest_template *config = &parsed.templates[i];
        config->identity = read32(record);
        config->image = read32(record + 4);
        config->abi = read32(record + 8);
        config->flags = read32(record + 12);
        config->entry = read64(record + 16);
        config->image_budget = read32(record + 24);
        config->stack_budget = read32(record + 28);
        config->writable_budget = read32(record + 32);
        config->boot_config = read32(record + 36);
        config->restart_limit = read32(record + 40);
        config->restart_delay = read32(record + 44);
        config->max_descendant_depth = read32(record + 48);
        config->child_template_mask = read32(record + 52);
        config->bootstrap_recipe = read32(record + 56);
        config->reserved = read32(record + 60);
        if (config->identity == 0 || config->identity > Z_MANIFEST_TEMPLATE_MAX ||
            (template_mask & (UINT32_C(1) << (config->identity - 1))))
            return fail(error, Z_MANIFEST_TEMPLATE_ERROR);
        template_mask |= UINT32_C(1) << (config->identity - 1);
        if (config->flags || config->reserved)
            return fail(error, Z_MANIFEST_RESERVED_ERROR);
        if (config->abi != Z_MANIFEST_ABI)
            return fail(error, Z_MANIFEST_ABI_ERROR);
        const struct z_image_catalog *image = NULL;
        for (unsigned j = 0; j < catalog_count; ++j)
            if (catalog[j].identity == config->image)
                image = &catalog[j];
        /* Root services retain fixed routing and are never dynamic templates. */
        if (image == NULL || config->image <= Z_MANIFEST_CELL_MAX ||
            (image->role != Z_SUPERVISOR && image->role != Z_WORKER))
            return fail(error, Z_MANIFEST_IMAGE_ERROR);
        if (config->entry != image->entry || config->entry != Z_IMAGE_BASE)
            return fail(error, Z_MANIFEST_ENTRY_ERROR);
        uint16_t stack, heap;
        if (config->image_budget == 0 || config->image_budget > Z_MANIFEST_IMAGE_MAX ||
            image->length > config->image_budget ||
            !z_manifest_memory_pages(config->stack_budget, config->writable_budget, &stack, &heap))
            return fail(error, Z_MANIFEST_BUDGET_ERROR);
        if (config->boot_config > 25)
            return fail(error, Z_MANIFEST_CONFIG_ERROR);
        if (config->restart_limit != Z_MANIFEST_RESTART_LIMIT ||
            config->restart_delay != Z_MANIFEST_RESTART_DELAY)
            return fail(error, Z_MANIFEST_LIFECYCLE_ERROR);
        if (config->max_descendant_depth >= Z_MANIFEST_DEPTH_MAX ||
            (config->bootstrap_recipe != Z_MANIFEST_BOOTSTRAP_RPC &&
                config->bootstrap_recipe != Z_MANIFEST_BOOTSTRAP_SNAPSHOT) ||
            ((config->max_descendant_depth == 0) != (config->child_template_mask == 0)))
            return fail(error, Z_MANIFEST_TEMPLATE_ERROR);
        if (config->bootstrap_recipe == Z_MANIFEST_BOOTSTRAP_RPC && config->boot_config == 25)
            return fail(error, Z_MANIFEST_TEMPLATE_ERROR);
        if (config->bootstrap_recipe == Z_MANIFEST_BOOTSTRAP_SNAPSHOT &&
            (config->boot_config != 25 ||
                !((config->identity == 5 && config->image == 5 &&
                    config->max_descendant_depth == 1 && config->child_template_mask == 32) ||
                  (config->identity == 6 && config->image == 6 &&
                    config->max_descendant_depth == 0 && config->child_template_mask == 0))))
            return fail(error, Z_MANIFEST_TEMPLATE_ERROR);
    }
    for (unsigned i = 0; i < template_count; ++i)
        if (parsed.templates[i].child_template_mask & ~template_mask)
            return fail(error, Z_MANIFEST_REFERENCE_ERROR);
    size_t domains_at = templates_at + template_count * sizeof(struct z_manifest_template);
    unsigned reserved_pages = 0, reserved_slots = 0;
    for (unsigned i = 0; i < domain_count; ++i) {
        const uint8_t *record = bytes + domains_at + i * sizeof(struct z_manifest_domain);
        struct z_manifest_domain *domain = &parsed.domains[i];
        domain->owner_identity = read32(record);
        domain->template_mask = read32(record + 4);
        domain->slot_limit = read32(record + 8);
        domain->page_limit = read32(record + 12);
        domain->max_depth = read32(record + 16);
        domain->bootstrap_recipe = read32(record + 20);
        domain->reserved0 = read32(record + 24);
        domain->reserved1 = read32(record + 28);
        if (domain->reserved0 || domain->reserved1)
            return fail(error, Z_MANIFEST_RESERVED_ERROR);
        int owner = z_manifest_slot(&parsed, domain->owner_identity);
        if (owner < 0 || domain->template_mask == 0 || (domain->template_mask & ~template_mask))
            return fail(error, Z_MANIFEST_REFERENCE_ERROR);
        const struct z_manifest_cell *creator = &parsed.cells[owner];
        /* Only the explicitly selected hosting branch of the original probe is a creator. */
        if (domain->owner_identity != 400 || creator->image != 4 ||
            !(creator->flags & Z_MANIFEST_ACTIVE) || cell_count != Z_MANIFEST_CELL_MAX ||
            active != Z_MANIFEST_CELL_MAX || creator->boot_config < 21 ||
            creator->boot_config > 25 ||
            domain->slot_limit == 0 || domain->slot_limit > Z_MANIFEST_DYNAMIC_SLOTS ||
            domain->page_limit == 0 || domain->page_limit > Z_MANIFEST_DYNAMIC_PAGES ||
            domain->max_depth == 0 || domain->max_depth > Z_MANIFEST_DEPTH_MAX ||
            (domain->bootstrap_recipe != Z_MANIFEST_BOOTSTRAP_RPC &&
                domain->bootstrap_recipe != Z_MANIFEST_BOOTSTRAP_SNAPSHOT) ||
            (domain->bootstrap_recipe == Z_MANIFEST_BOOTSTRAP_RPC && creator->boot_config == 25) ||
            (domain->bootstrap_recipe == Z_MANIFEST_BOOTSTRAP_SNAPSHOT &&
                (creator->boot_config != 25 || domain->template_mask != 48)))
            return fail(error, Z_MANIFEST_DOMAIN_ERROR);
        for (unsigned j = 0; j < i; ++j)
            if (parsed.domains[j].owner_identity == domain->owner_identity)
                return fail(error, Z_MANIFEST_DOMAIN_ERROR);
        for (unsigned j = 0; j < template_count; ++j)
            if ((domain->template_mask & (UINT32_C(1) << (parsed.templates[j].identity - 1))) &&
                parsed.templates[j].bootstrap_recipe != domain->bootstrap_recipe)
                return fail(error, Z_MANIFEST_DOMAIN_ERROR);
        reserved_pages += domain->page_limit;
        reserved_slots += domain->slot_limit;
        if (reserved_pages > Z_MANIFEST_DYNAMIC_PAGES || reserved_slots > Z_MANIFEST_DYNAMIC_SLOTS ||
            total_pages + reserved_pages > Z_MANIFEST_POOL_PAGES)
            return fail(error, Z_MANIFEST_BUDGET_ERROR);
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
        "malformed operation rights", "duplicate initial grant",
        "invalid sealed template", "invalid root creation domain"
    };
    return (unsigned)error < sizeof(names) / sizeof(*names) ? names[error] : "unknown manifest error";
}
