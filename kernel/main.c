#include <zeal/abi.h>
#include <zeal/arch.h>
#include <zeal/ipc.h>
#include <zeal/memory.h>

#ifndef Z_SCENARIO
#define Z_SCENARIO 0
#endif
#ifndef Z_TEST
#define Z_TEST 0
#endif
#ifndef Z_SOLO
#define Z_SOLO -1
#endif

extern const unsigned char _binary_block_bin_start[], _binary_block_bin_end[];
extern const unsigned char _binary_filesystem_bin_start[], _binary_filesystem_bin_end[];
extern const unsigned char _binary_client_bin_start[], _binary_client_bin_end[];
extern const unsigned char _binary_probe_bin_start[], _binary_probe_bin_end[];

static struct z_broker broker;
static struct z_frame frames[Z_CELL_COUNT];
static const unsigned char *images[Z_CELL_COUNT];
static size_t image_lengths[Z_CELL_COUNT];
static unsigned current;
static uint64_t ticks;
static uint64_t reads;
static uint64_t sends[Z_CELL_COUNT];
static uint64_t fault_sends[2];
static uint64_t fault_reads[2];
static unsigned run_ticks[Z_CELL_COUNT];
static unsigned boots[Z_CELL_COUNT];
static unsigned reset_reports;
static unsigned recovered;
static bool contract_ok;
static bool finished;

static void field(const char *name, uint64_t value)
{
    serial_puts(" ");
    serial_puts(name);
    serial_puts("=");
    serial_hex(value);
}

static void event(const char *name, unsigned cell)
{
    serial_puts("EVENT ");
    serial_puts(name);
    field("cell", cell);
    field("generation", broker.policies[cell].generation);
    field("tick", ticks);
}

static void panic(const char *reason) __attribute__((noreturn));
static void panic(const char *reason)
{
    serial_puts("PANIC ");
    serial_puts(reason);
    serial_puts("\n");
    arch_finish(2);
}

static void cold_boot(unsigned cell)
{
    arch_space_reset(cell, images[cell], image_lengths[cell]);
    arch_frame_init(&frames[cell]);
    run_ticks[cell] = 0;
    ++boots[cell];
    event("boot", cell);
    serial_puts("\n");
}

static void fail_cell(unsigned cell, uint64_t reason, uint64_t error, uint64_t address)
{
    event("fault", cell);
    field("reason", reason);
    field("error", error);
    field("address", address);
    serial_puts("\n");
    if (cell < 2) {
        fault_sends[cell] = sends[cell];
        fault_reads[cell] = reads;
    }
    z_broker_revoke(&broker, cell);
    z_policy_fault(&broker.policies[cell], ticks);
    run_ticks[cell] = 0;
    if (broker.policies[cell].phase == Z_POLICY_QUARANTINED) {
        event("quarantine", cell);
        serial_puts("\n");
    }
}

static void supervisor_tick(void)
{
    if (Z_SCENARIO == 12 && ticks == 10)
        __asm__ volatile("ud2");
    if (Z_SOLO < 0 && ticks == 20)
        fail_cell(Z_BLOCK, 64, 0, 0);
    if (Z_SOLO < 0 && ticks == 40)
        fail_cell(Z_FS, 64, 0, 0);
    for (unsigned i = 0; i < Z_CELL_COUNT; ++i) {
        if (!z_policy_check(&broker.policies[i]))
            panic("policy invariant");
        if (z_policy_poll(&broker.policies[i], ticks))
            cold_boot(i);
    }
}

static void observe_read(void)
{
    ++reads;
    if (reads == 1) {
        event("read", current);
        serial_puts("\n");
    }
    for (unsigned i = 0; i < 2; ++i) {
        if (!(recovered & (1u << i)) && broker.policies[i].generation == 2 &&
            sends[i] > fault_sends[i] && reads > fault_reads[i]) {
            recovered |= 1u << i;
            event("recovered", i);
            field("reads", reads);
            serial_puts("\n");
        }
    }
}

static int64_t syscall(struct z_frame *frame)
{
    struct z_message message;
    uint64_t pointer = frame->rdi;
    switch (frame->rax) {
    case Z_YIELD:
        return Z_OK;
    case Z_SEND:
        if (!arch_user_range(frame->rsi, sizeof(message), false))
            return Z_BAD_ADDRESS;
        arch_user_copy_in(&message, frame->rsi, sizeof(message));
        {
            int result = z_broker_send(&broker, current, pointer, &message);
            if (result == Z_OK)
                ++sends[current];
            return result;
        }
    case Z_RECV:
        if (!arch_user_range(pointer, sizeof(message), true))
            return Z_BAD_ADDRESS;
        {
            int result = z_broker_receive(&broker, current, &message);
            if (result == Z_OK)
                arch_user_copy_out(pointer, &message, sizeof(message));
            return result;
        }
    case Z_LOOKUP:
        if (pointer >= Z_CELL_COUNT)
            return Z_INVALID;
        return z_broker_lookup(&broker, current, (unsigned)pointer);
    case Z_BOOT:
        if (!arch_user_range(pointer, sizeof(struct z_boot_info), true))
            return Z_BAD_ADDRESS;
        {
            struct z_boot_info info = {
                Z_ABI_VERSION, current, broker.policies[current].generation, Z_SCENARIO
            };
            arch_user_copy_out(pointer, &info, sizeof(info));
            return Z_OK;
        }
    case Z_REPORT:
        if (pointer == 7 && current == Z_PROBE) {
            ++reset_reports;
            event("reset-memory", current);
            serial_puts("\n");
            return Z_OK;
        }
        if (pointer == 1 && current == Z_CLIENT) {
            observe_read();
            return Z_OK;
        }
        if (pointer == 2 && current == Z_PROBE &&
            (Z_SCENARIO == 7 || Z_SCENARIO == 8 || Z_SCENARIO == 15)) {
            contract_ok = true;
            event("contract", current);
            serial_puts("\n");
            return Z_OK;
        }
        if (pointer == (uint64_t)current + 3) {
            event("entry", current);
            serial_puts("\n");
            return Z_OK;
        }
        event("bad-report", current);
        field("code", pointer);
        serial_puts("\n");
        fail_cell(current, 66, 0, 0);
        return Z_INVALID;
    case Z_EXIT:
        z_broker_revoke(&broker, current);
        z_policy_stop(&broker.policies[current]);
        event("exit", current);
        serial_puts("\n");
        return Z_OK;
    default:
        return Z_INVALID;
    }
}

static void research_check(void)
{
    if (finished || ticks < 120 || Z_SOLO >= 0)
        return;
    bool probe_ok = broker.policies[Z_PROBE].phase == Z_POLICY_QUARANTINED;
    if (Z_SCENARIO == 7 || Z_SCENARIO == 8 || Z_SCENARIO == 15)
        probe_ok = broker.policies[Z_PROBE].phase == Z_POLICY_STOPPED && contract_ok;
    else
        probe_ok = probe_ok && broker.policies[Z_PROBE].faults == 4 && boots[Z_PROBE] == 4;
    bool pass = recovered == 3 && reads > 2 && probe_ok && reset_reports == boots[Z_PROBE] &&
                broker.policies[Z_BLOCK].phase == Z_POLICY_READY &&
                broker.policies[Z_FS].phase == Z_POLICY_READY &&
                broker.policies[Z_CLIENT].faults == 0 && boots[Z_CLIENT] == 1;
    serial_puts(pass ? "RESEARCH_PASS" : "RESEARCH_FAIL");
    field("scenario", Z_SCENARIO);
    field("reads", reads);
    field("tick", ticks);
    serial_puts("\n");
    finished = true;
    if (!pass || Z_TEST)
        arch_finish(pass ? 0 : 1);
}

static struct z_frame *schedule(void)
{
    for (;;) {
        for (unsigned offset = 1; offset <= Z_CELL_COUNT; ++offset) {
            unsigned next = (current + offset) % Z_CELL_COUNT;
            if (broker.policies[next].phase == Z_POLICY_READY) {
                current = next;
                arch_activate(current);
                return &frames[current];
            }
        }
        /* No runnable cell: the supervisor remains available during backoff. */
        __asm__ volatile("sti; hlt; cli" ::: "memory");
        supervisor_tick();
    }
}

struct z_frame *kernel_trap(struct z_frame *frame)
{
    if ((frame->cs & 3) != 3) {
        if (frame->vector == 32) {
            ++ticks;
            arch_eoi();
            return frame;
        }
        serial_puts("KERNEL_FAULT");
        field("vector", frame->vector);
        field("rip", frame->rip);
        serial_puts("\n");
        panic("trusted kernel fault");
    }
    frames[current] = *frame;
    if (frame->cs != 0x1b || frame->ss != 0x23 ||
        !z_canonical_address(frame->rip) || !z_canonical_address(frame->rsp)) {
        if (frame->vector == 32) {
            ++ticks;
            arch_eoi();
            supervisor_tick();
        }
        fail_cell(current, 69, 0, frame->rsp);
        return schedule();
    }
    frames[current].flags = (frame->flags | UINT64_C(0x202)) & ~UINT64_C(0x27000);
    if (frame->vector == 32) {
        ++ticks;
        arch_eoi();
        if (++run_ticks[current] >= 5)
            fail_cell(current, 65, 0, 0);
        supervisor_tick();
        research_check();
    } else if (frame->vector == 128) {
        run_ticks[current] = 0;
        frames[current].rax = (uint64_t)syscall(frame);
    } else if (frame->vector < 32) {
        fail_cell(current, frame->vector, frame->error,
                  frame->vector == 14 ? arch_fault_address() : 0);
    } else {
        panic("unexpected interrupt");
    }
    return schedule();
}

void kernel_main(void)
{
    serial_init();
    serial_puts("ZEAL boot abi=1 x86_64\n");
    arch_init();
    z_broker_init(&broker);
    images[0] = _binary_block_bin_start;
    images[1] = _binary_filesystem_bin_start;
    images[2] = _binary_client_bin_start;
    images[3] = _binary_probe_bin_start;
    image_lengths[0] = (size_t)(_binary_block_bin_end - _binary_block_bin_start);
    image_lengths[1] = (size_t)(_binary_filesystem_bin_end - _binary_filesystem_bin_start);
    image_lengths[2] = (size_t)(_binary_client_bin_end - _binary_client_bin_start);
    image_lengths[3] = (size_t)(_binary_probe_bin_end - _binary_probe_bin_start);
    for (unsigned i = 0; i < Z_CELL_COUNT; ++i) {
        if (Z_SOLO >= 0 && i != (unsigned)Z_SOLO) {
            broker.policies[i].phase = Z_POLICY_DORMANT;
            continue;
        }
        if (!arch_space_init(i, images[i], image_lengths[i]))
            panic("invalid sealed image");
        cold_boot(i);
    }
    current = Z_SOLO >= 0 ? (unsigned)Z_SOLO : Z_BLOCK;
    arch_activate(current);
    arch_enter(&frames[current]);
}
