#include <zeal/abi.h>
#include <zeal/arch.h>
#include <zeal/memory.h>

#define PAGE_SIZE 4096u
#define PTE_PRESENT UINT64_C(1)
#define PTE_WRITE UINT64_C(2)
#define PTE_USER UINT64_C(4)
#define PTE_LARGE UINT64_C(128)
#define PTE_NX (UINT64_C(1) << 63)

struct descriptor_pointer {
    uint16_t limit;
    uint64_t base;
} __attribute__((packed));

struct task_state {
    uint32_t reserved0;
    uint64_t rsp[3];
    uint64_t reserved1;
    uint64_t ist[7];
    uint64_t reserved2;
    uint16_t reserved3;
    uint16_t io_map;
} __attribute__((packed));

struct interrupt_gate {
    uint16_t offset0;
    uint16_t selector;
    uint8_t ist;
    uint8_t attributes;
    uint16_t offset1;
    uint32_t offset2;
    uint32_t reserved;
} __attribute__((packed));

struct cell_space {
    _Alignas(PAGE_SIZE) uint64_t pml4[512];
    _Alignas(PAGE_SIZE) uint64_t pdpt[512];
    _Alignas(PAGE_SIZE) uint64_t directory[512];
    _Alignas(PAGE_SIZE) uint64_t pages[512];
    _Alignas(PAGE_SIZE) uint8_t image[Z_IMAGE_SIZE];
    struct z_memory_layout layout;
    uint64_t entry;
    uint32_t image_budget;
    uint32_t stack_budget;
    uint32_t writable_budget;
    bool ready;
};

_Static_assert(sizeof(struct task_state) == 104, "x86 task-state layout");
_Static_assert(sizeof(struct interrupt_gate) == 16, "x86 interrupt-gate layout");
_Static_assert(sizeof(struct z_frame) == 176, "assembly trap-frame layout");
_Static_assert(offsetof(struct z_frame, vector) == 120, "trap vector offset");
_Static_assert(offsetof(struct z_frame, rip) == 136, "trap instruction offset");
_Static_assert(offsetof(struct z_frame, cs) == 144, "trap privilege offset");
_Static_assert(offsetof(struct z_frame, flags) == 152, "trap flags offset");
_Static_assert(offsetof(struct z_frame, rsp) == 160, "trap stack offset");
_Static_assert(offsetof(struct z_frame, ss) == 168, "trap stack selector offset");

extern void *arch_exception_entries[32];
extern void isr_32(void);
extern void isr_128(void);
extern void isr_255(void);
extern void arch_load_gdt(const struct descriptor_pointer *pointer);
extern uint8_t kernel_stack_top[];

static uint64_t gdt[7] __attribute__((aligned(16)));
static struct task_state tss;
static struct interrupt_gate idt[256] __attribute__((aligned(16)));
static uint8_t double_fault_stack[16384] __attribute__((aligned(16)));
static uint64_t low_directory[512] __attribute__((aligned(PAGE_SIZE)));
static struct cell_space spaces[Z_CELL_COUNT];
static struct z_memory_pool memory_pool;
static unsigned active_cell = Z_CELL_COUNT;

static inline void out8(uint16_t port, uint8_t value)
{
    __asm__ volatile("outb %0, %1" : : "a"(value), "Nd"(port));
}

static inline uint8_t in8(uint16_t port)
{
    uint8_t value;
    __asm__ volatile("inb %1, %0" : "=a"(value) : "Nd"(port));
    return value;
}

static void io_wait(void)
{
    out8(0x80, 0);
}

static void clear(void *destination, size_t length)
{
    uint8_t *bytes = destination;
    for (size_t i = 0; i < length; ++i)
        bytes[i] = 0;
}

static void copy(void *destination, const void *source, size_t length)
{
    uint8_t *output = destination;
    const uint8_t *input = source;
    for (size_t i = 0; i < length; ++i)
        output[i] = input[i];
}

static void set_gate(unsigned vector, void *handler, unsigned privilege,
                     unsigned interrupt_stack)
{
    uint64_t address = (uint64_t)(uintptr_t)handler;
    struct interrupt_gate *gate = &idt[vector];
    gate->offset0 = (uint16_t)address;
    gate->selector = 0x08;
    gate->ist = (uint8_t)interrupt_stack;
    gate->attributes = (uint8_t)(0x8e | (privilege << 5));
    gate->offset1 = (uint16_t)(address >> 16);
    gate->offset2 = (uint32_t)(address >> 32);
    gate->reserved = 0;
}

void arch_init(void)
{
    __asm__ volatile("cli" : : : "memory");
    if (!z_memory_init(&memory_pool, Z_MANIFEST_POOL_PAGES))
        arch_finish(0x7d);
    gdt[0] = 0;
    gdt[1] = UINT64_C(0x00af9a000000ffff);
    gdt[2] = UINT64_C(0x00cf92000000ffff);
    gdt[3] = UINT64_C(0x00affa000000ffff);
    gdt[4] = UINT64_C(0x00cff2000000ffff);
    clear(&tss, sizeof(tss));
    tss.rsp[0] = (uint64_t)(uintptr_t)kernel_stack_top;
    tss.ist[0] = (uint64_t)(uintptr_t)(double_fault_stack + sizeof(double_fault_stack));
    tss.io_map = sizeof(tss);
    uint64_t address = (uint64_t)(uintptr_t)&tss;
    uint64_t limit = sizeof(tss) - 1;
    gdt[5] = limit | ((address & UINT64_C(0xffffff)) << 16)
        | (UINT64_C(0x89) << 40) | ((address & UINT64_C(0xff000000)) << 32);
    gdt[6] = address >> 32;
    struct descriptor_pointer gdt_pointer = { sizeof(gdt) - 1, (uintptr_t)gdt };
    arch_load_gdt(&gdt_pointer);

    for (unsigned vector = 0; vector < 256; ++vector)
        set_gate(vector, isr_255, 0, 0);
    for (unsigned vector = 0; vector < 32; ++vector)
        set_gate(vector, arch_exception_entries[vector], 0, vector == 8 ? 1 : 0);
    set_gate(32, isr_32, 0, 0);
    set_gate(128, isr_128, 3, 0);
    struct descriptor_pointer idt_pointer = { sizeof(idt) - 1, (uintptr_t)idt };
    __asm__ volatile("lidt %0" : : "m"(idt_pointer) : "memory");

    for (unsigned page = 0; page < 512; ++page)
        low_directory[page] = ((uint64_t)page << 21)
            | PTE_PRESENT | PTE_WRITE | PTE_LARGE;

    out8(0x20, 0x11);
    io_wait();
    out8(0xa0, 0x11);
    io_wait();
    out8(0x21, 32);
    io_wait();
    out8(0xa1, 40);
    io_wait();
    out8(0x21, 4);
    io_wait();
    out8(0xa1, 2);
    io_wait();
    out8(0x21, 1);
    io_wait();
    out8(0xa1, 1);
    io_wait();
    out8(0x21, 0xfe);
    out8(0xa1, 0xff);
    out8(0x43, 0x36);
    out8(0x40, (uint8_t)(1193182 / 100));
    out8(0x40, (uint8_t)((1193182 / 100) >> 8));
}

bool arch_space_init(unsigned cell, const void *image, size_t length,
                     const struct z_manifest_cell *config)
{
    if (cell >= Z_CELL_COUNT || spaces[cell].ready || image == NULL || config == NULL ||
        length == 0 || config->image_budget == 0 || config->image_budget > Z_IMAGE_SIZE ||
        length > config->image_budget || config->entry != Z_IMAGE_BASE ||
        !z_memory_allocate(&memory_pool, cell, config->stack_budget, config->writable_budget))
        return false;
    struct cell_space *space = &spaces[cell];
    clear(space, sizeof(*space));
    uint64_t user_table = PTE_PRESENT | PTE_WRITE | PTE_USER;
    space->pml4[0] = (uintptr_t)space->pdpt | user_table;
    space->pdpt[0] = (uintptr_t)low_directory | PTE_PRESENT | PTE_WRITE;
    space->pdpt[1] = (uintptr_t)space->directory | user_table;
    space->directory[0] = (uintptr_t)space->pages | user_table;
    unsigned image_pages = (config->image_budget + PAGE_SIZE - 1) / PAGE_SIZE;
    for (unsigned page = 0; page < image_pages; ++page)
        space->pages[page] = (uintptr_t)(space->image + page * PAGE_SIZE)
            | PTE_PRESENT | PTE_USER;
    unsigned stack_page = (Z_STACK_BASE - Z_IMAGE_BASE) / PAGE_SIZE;
    const struct z_memory_allocation *allocation = &memory_pool.cells[cell];
    for (unsigned page = 0; page < allocation->stack_pages; ++page)
        space->pages[stack_page + page] = (uintptr_t)z_memory_page(&memory_pool, cell, page)
            | PTE_PRESENT | PTE_WRITE | PTE_USER | PTE_NX;
    unsigned heap_page = (Z_HEAP_BASE - Z_IMAGE_BASE) / PAGE_SIZE;
    for (unsigned page = 0; page < allocation->heap_pages; ++page)
        space->pages[heap_page + page] = (uintptr_t)z_memory_page(
            &memory_pool, cell, allocation->stack_pages + page)
            | PTE_PRESENT | PTE_WRITE | PTE_USER | PTE_NX;
    copy(space->image, image, length);
    space->layout = (struct z_memory_layout) {
        space->image, image_pages * PAGE_SIZE,
        allocation->stack_pages * PAGE_SIZE, allocation->heap_pages * PAGE_SIZE
    };
    space->entry = config->entry;
    space->image_budget = config->image_budget;
    space->stack_budget = config->stack_budget;
    space->writable_budget = config->writable_budget;
    space->ready = true;
    return true;
}

bool arch_space_reset(unsigned cell, const void *image, size_t length,
                      const struct z_manifest_cell *config)
{
    if (cell >= Z_CELL_COUNT || image == NULL || config == NULL)
        return false;
    if (!spaces[cell].ready)
        return arch_space_init(cell, image, length, config);
    if (length == 0 || length > spaces[cell].image_budget ||
        spaces[cell].image_budget != config->image_budget ||
        spaces[cell].stack_budget != config->stack_budget ||
        spaces[cell].writable_budget != config->writable_budget ||
        spaces[cell].entry != config->entry || !z_memory_reset(&memory_pool, cell))
        return false;
    clear(spaces[cell].image, sizeof(spaces[cell].image));
    copy(spaces[cell].image, image, length);
    return true;
}

void arch_space_release(unsigned cell)
{
    if (cell >= Z_CELL_COUNT || !spaces[cell].ready)
        return;
    if (!z_memory_release(&memory_pool, cell))
        arch_finish(0x7d);
    clear(spaces[cell].pages, sizeof(spaces[cell].pages));
    spaces[cell].ready = false;
}

void arch_activate(unsigned cell)
{
    if (cell >= Z_CELL_COUNT || !spaces[cell].ready)
        arch_finish(0x7d);
    uintptr_t root = (uintptr_t)spaces[cell].pml4;
    active_cell = cell;
    __asm__ volatile("mov %0, %%cr3" : : "r"(root) : "memory");
}

bool arch_user_range(uint64_t address, size_t length, bool write)
{
    return active_cell < Z_CELL_COUNT && spaces[active_cell].ready &&
        z_memory_user_range(&spaces[active_cell].layout, address, length, write);
}

void arch_user_copy_in(void *destination, uint64_t source, size_t length)
{
    if (active_cell >= Z_CELL_COUNT || !spaces[active_cell].ready ||
        !z_memory_copy_in(&memory_pool, active_cell, &spaces[active_cell].layout,
                           destination, source, length))
        arch_finish(0x7d);
}

void arch_user_copy_out(uint64_t destination, const void *source, size_t length)
{
    if (active_cell >= Z_CELL_COUNT || !spaces[active_cell].ready ||
        !z_memory_copy_out(&memory_pool, active_cell, &spaces[active_cell].layout,
                            destination, source, length))
        arch_finish(0x7d);
}

/* Deferred completion addresses the owner's backing directly; it must not
 * depend on whichever cell's CR3 is currently active. */
bool arch_cell_copy_valid(unsigned cell, uint64_t destination, size_t length)
{
    return cell < Z_CELL_COUNT && spaces[cell].ready &&
        z_memory_copy_valid(&memory_pool, cell, &spaces[cell].layout,
                             destination, length, true);
}

bool arch_cell_copy_out(unsigned cell, uint64_t destination,
                        const void *source, size_t length)
{
    return cell < Z_CELL_COUNT && spaces[cell].ready &&
        z_memory_copy_out(&memory_pool, cell, &spaces[cell].layout,
                           destination, source, length);
}

bool arch_cell_range(unsigned cell, uint64_t address, size_t length, bool write)
{
    return cell < Z_CELL_COUNT && spaces[cell].ready &&
        z_memory_copy_valid(&memory_pool, cell, &spaces[cell].layout, address, length, write);
}

bool arch_cell_copy_in(unsigned cell, void *destination, uint64_t source, size_t length)
{
    return cell < Z_CELL_COUNT && spaces[cell].ready &&
        z_memory_copy_in(&memory_pool, cell, &spaces[cell].layout, destination, source, length);
}

unsigned arch_space_pages(unsigned cell)
{
    return cell < Z_CELL_COUNT ? memory_pool.cells[cell].count : 0;
}

bool arch_memory_check(void)
{
    return z_memory_check(&memory_pool);
}

uint32_t arch_space_page_id(unsigned cell, unsigned page)
{
    return cell < Z_CELL_COUNT && page < memory_pool.cells[cell].count ?
        memory_pool.cells[cell].pages[page] : UINT32_MAX;
}

bool arch_space_zero(unsigned cell)
{
    if (cell >= Z_CELL_COUNT || !spaces[cell].ready) return false;
    for (unsigned page = 0; page < memory_pool.cells[cell].count; ++page) {
        const uint8_t *bytes = z_memory_page(&memory_pool, cell, page);
        if (bytes == NULL) return false;
        for (unsigned i = 0; i < Z_MANIFEST_PAGE_SIZE; ++i)
            if (bytes[i] != 0) return false;
    }
    return true;
}

void arch_frame_init(struct z_frame *frame, unsigned cell)
{
    if (cell >= Z_CELL_COUNT || !spaces[cell].ready)
        arch_finish(0x7d);
    clear(frame, sizeof(*frame));
    frame->rip = spaces[cell].entry;
    frame->cs = 0x1b;
    frame->flags = 0x202;
    frame->rsp = Z_STACK_BASE + spaces[cell].layout.stack_size - sizeof(uint64_t);
    frame->ss = 0x23;
}

void arch_eoi(void)
{
    out8(0x20, 0x20);
}

uint64_t arch_fault_address(void)
{
    uint64_t address;
    __asm__ volatile("mov %%cr2, %0" : "=r"(address));
    return address;
}

void serial_init(void)
{
    out8(0x3f9, 0);
    out8(0x3fb, 0x80);
    out8(0x3f8, 1);
    out8(0x3f9, 0);
    out8(0x3fb, 3);
    out8(0x3fa, 0xc7);
    out8(0x3fc, 0x0b);
}

static void serial_putc(char character)
{
    for (unsigned attempt = 0; attempt < 1000000; ++attempt) {
        if (in8(0x3fd) & 0x20) {
            out8(0x3f8, (uint8_t)character);
            return;
        }
    }
}

void serial_puts(const char *text)
{
    while (*text) {
        if (*text == '\n')
            serial_putc('\r');
        serial_putc(*text++);
    }
}

void serial_hex(uint64_t value)
{
    static const char digits[] = "0123456789abcdef";
    serial_puts("0x");
    for (int shift = 60; shift >= 0; shift -= 4)
        serial_putc(digits[(value >> shift) & 15]);
}

void arch_finish(unsigned code)
{
    __asm__ volatile("cli; outl %0, %1" : : "a"(code), "Nd"((uint16_t)0xf4) : "memory");
    for (;;)
        __asm__ volatile("hlt");
}
