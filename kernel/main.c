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
extern const unsigned char _binary_manifest_bin_start[], _binary_manifest_bin_end[];

static struct z_broker broker;
static struct z_manifest manifest;
static struct z_frame frames[Z_CELL_COUNT];
static const unsigned char *images[Z_CELL_COUNT];
static size_t image_lengths[Z_CELL_COUNT];
static unsigned current;
static uint64_t ticks, reads;
static uint64_t sends[Z_CELL_COUNT], fault_sends[2], fault_reads[2];
static unsigned run_ticks[Z_CELL_COUNT], boots[Z_CELL_COUNT], reset_reports, recovered;
static bool contract_ok, finished;

static void field(const char *name, uint64_t value)
{
    serial_puts(" "); serial_puts(name); serial_puts("="); serial_hex(value);
}

static void event(const char *name, unsigned cell)
{
    serial_puts("EVENT "); serial_puts(name);
    field("cell", cell); field("identity", manifest.cells[cell].identity);
    field("generation", broker.policies[cell].generation); field("tick", ticks);
}

static void panic(const char *reason) __attribute__((noreturn));
static void panic(const char *reason)
{
    serial_puts("PANIC "); serial_puts(reason); serial_puts("\n"); arch_finish(2);
}

static void load_manifest(void)
{
    images[0] = _binary_block_bin_start;
    images[1] = _binary_filesystem_bin_start;
    images[2] = _binary_client_bin_start;
    images[3] = _binary_probe_bin_start;
    image_lengths[0] = (size_t)(_binary_block_bin_end - _binary_block_bin_start);
    image_lengths[1] = (size_t)(_binary_filesystem_bin_end - _binary_filesystem_bin_start);
    image_lengths[2] = (size_t)(_binary_client_bin_end - _binary_client_bin_start);
    image_lengths[3] = (size_t)(_binary_probe_bin_end - _binary_probe_bin_start);
    const struct z_image_catalog catalog[] = {
        { 1, images[0], image_lengths[0], Z_IMAGE_BASE },
        { 2, images[1], image_lengths[1], Z_IMAGE_BASE },
        { 3, images[2], image_lengths[2], Z_IMAGE_BASE },
        { 4, images[3], image_lengths[3], Z_IMAGE_BASE },
    };
    size_t length = (size_t)(_binary_manifest_bin_end - _binary_manifest_bin_start);
    enum z_manifest_error error;
    if (!z_manifest_validate(_binary_manifest_bin_start, length, catalog,
                             sizeof(catalog) / sizeof(catalog[0]), &manifest, &error)) {
        serial_puts("MANIFEST_REJECT reason="); serial_puts(z_manifest_diagnostic(error));
        serial_puts("\n"); arch_finish(3);
    }
    serial_puts("MANIFEST_ACCEPT version=1 cells="); serial_hex(manifest.cell_count);
    serial_puts(" grants="); serial_hex(manifest.grant_count); serial_puts("\n");
}

static unsigned role_slot(unsigned role)
{
    uint32_t image = role + 1;
    for (unsigned i = 0; i < manifest.cell_count; ++i)
        if (manifest.cells[i].image == image) return i;
    return Z_CELL_COUNT;
}

static void cold_boot(unsigned cell)
{
    const struct z_manifest_cell *config = &manifest.cells[cell];
    unsigned image = config->image - 1;
    if (!arch_space_reset(cell, images[image], image_lengths[image], config))
        panic("manifest cell memory reset failed");
    arch_frame_init(&frames[cell], cell);
    run_ticks[cell] = 0;
    ++boots[cell];
    event("boot", cell);
    field("image", config->image); field("abi", config->abi);
    field("entry", config->entry); field("image_budget", config->image_budget);
    field("writable_budget", config->writable_budget); field("config", config->boot_config);
    serial_puts("\n");
}

static void fail_cell(unsigned cell, uint64_t reason, uint64_t error, uint64_t address)
{
    event("fault", cell); field("reason", reason); field("error", error);
    field("address", address); serial_puts("\n");
    if (cell < 2) { fault_sends[cell] = sends[cell]; fault_reads[cell] = reads; }
    z_broker_revoke(&broker, cell);
    z_policy_fault(&broker.policies[cell], ticks);
    run_ticks[cell] = 0;
    if (broker.policies[cell].phase == Z_POLICY_QUARANTINED) {
        arch_space_release(cell);
        event("quarantine", cell); serial_puts("\n");
    }
}

static void supervisor_tick(void)
{
    if (Z_SCENARIO == 12 && ticks == 10) __asm__ volatile("ud2");
    if (Z_SOLO < 0 && ticks == 20) {
        unsigned block = role_slot(Z_BLOCK);
        if (block < manifest.cell_count) fail_cell(block, 64, 0, 0);
    }
    if (Z_SOLO < 0 && ticks == 40) {
        unsigned fs = role_slot(Z_FS);
        if (fs < manifest.cell_count) fail_cell(fs, 64, 0, 0);
    }
    for (unsigned i = 0; i < manifest.cell_count; ++i) {
        if (!z_policy_check(&broker.policies[i])) panic("policy invariant");
        if (z_policy_poll(&broker.policies[i], ticks)) {
            cold_boot(i);
            if (z_broker_refresh(&broker) != Z_OK) panic("capability refresh exhausted");
        }
    }
}

static void observe_read(void)
{
    ++reads;
    unsigned client = role_slot(Z_CLIENT);
    if (client < manifest.cell_count) {
        event("read-verified", client); field("reads", reads); serial_puts("\n");
    }
    if (reads == 1 && client < manifest.cell_count) {
        event("read", client); field("reads", reads); serial_puts("\n");
    }
    for (unsigned i = 0; i < 2; ++i) {
        unsigned service = role_slot(i);
        if (service < manifest.cell_count && !(recovered & (1u << i)) &&
            broker.policies[service].generation == 2 && sends[service] > fault_sends[i] &&
            reads > fault_reads[i]) {
            recovered |= 1u << i;
            event("recovered", service); field("reads", reads); serial_puts("\n");
        }
    }
}

static int64_t syscall(struct z_frame *frame)
{
    struct z_message message;
    uint64_t argument = frame->rdi;
    switch (frame->rax) {
    case Z_YIELD: return Z_OK;
    case Z_SEND:
        if (!arch_user_range(frame->rsi, sizeof(message), false)) return Z_BAD_ADDRESS;
        arch_user_copy_in(&message, frame->rsi, sizeof(message));
        {
            int result = z_broker_send(&broker, current, argument, frame->rdx, &message);
            if (result == Z_OK) ++sends[current];
            return result;
        }
    case Z_RECV:
        if (!arch_user_range(argument, sizeof(message), true)) return Z_BAD_ADDRESS;
        { int result = z_broker_receive(&broker, current, &message);
          if (result == Z_OK) arch_user_copy_out(argument, &message, sizeof(message));
          return result; }
    case Z_LOOKUP: {
        int target = z_manifest_slot(&manifest, (uint32_t)argument);
        if (target < 0 || manifest.cells[target].identity != argument) return Z_INVALID;
        return z_broker_lookup(&broker, current, (unsigned)target);
    }
    case Z_BOOT:
        if (!arch_user_range(argument, sizeof(struct z_boot_info), true)) return Z_BAD_ADDRESS;
        { struct z_boot_info info = { Z_ABI_VERSION, manifest.cells[current].image - 1,
              broker.policies[current].generation, manifest.cells[current].boot_config };
          arch_user_copy_out(argument, &info, sizeof(info)); return Z_OK; }
    case Z_CAP_FIND:
        if (frame->rsi > UINT32_MAX) return Z_INVALID;
        return z_broker_find(&broker, current, argument, (uint32_t)frame->rsi);
    case Z_CAP_DELEGATE:
        if (!arch_user_range(argument, sizeof(struct z_cap_request), false)) return Z_BAD_ADDRESS;
        { struct z_cap_request request;
          arch_user_copy_in(&request, argument, sizeof(request));
          if (request.reserved) return Z_INVALID;
          struct z_cap_info parent_info;
          if (z_broker_query(&broker, current, request.parent, &parent_info) != Z_OK)
              return Z_DENIED;
          int64_t grant = z_broker_delegate(&broker, current, request.parent,
                                             request.holder, request.rights);
          if (grant > 0) {
              event("cap-delegate", current); field("holder", request.holder);
              field("target", parent_info.target); field("rights", request.rights);
              field("cap", (uint64_t)grant); field("parent", request.parent); serial_puts("\n");
          }
          return grant; }
    case Z_CAP_QUERY:
        if (!arch_user_range(frame->rsi, sizeof(struct z_cap_info), true)) return Z_BAD_ADDRESS;
        { struct z_cap_info info;
          int result = z_broker_query(&broker, current, argument, &info);
          if (result == Z_OK) arch_user_copy_out(frame->rsi, &info, sizeof(info));
          return result; }
    case Z_CAP_REVOKE: {
        int result = z_broker_revoke_cap(&broker, current, argument);
        if (result == Z_OK) {
            event("cap-revoke", current); field("cap", argument); serial_puts("\n");
        }
        return result;
    }
    case Z_REPORT:
        if (argument == 7 && manifest.cells[current].image == 4) {
            ++reset_reports; event("reset-memory", current); serial_puts("\n"); return Z_OK;
        }
        if (argument == 1 && manifest.cells[current].image == 3) {
            observe_read(); return Z_OK;
        }
        if (argument == 2 && manifest.cells[current].image == 4 &&
            (Z_SCENARIO == 7 || Z_SCENARIO == 8 || Z_SCENARIO == 15)) {
            contract_ok = true; event("contract", current); serial_puts("\n"); return Z_OK;
        }
        if (argument == 8 && manifest.cells[current].image == 3) {
            event("healthy-memory", current); field("stack", frame->rsi);
            field("writable", frame->rdx); serial_puts("\n"); return Z_OK;
        }
        if (argument == 9 && manifest.cells[current].image == 3) {
            event("demo-allowed", current); field("cap", frame->rsi);
            field("parent", frame->rdx); serial_puts("\n"); return Z_OK;
        }
        if (argument == 10 && manifest.cells[current].image == 3) {
            event("demo-revoked", current); field("cap", frame->rsi);
            field("endpoint", frame->rdx); serial_puts("\n"); return Z_OK;
        }
        if (argument == 11 && manifest.cells[current].image == 3) {
            event("demo-rebind", current); field("old", frame->rsi);
            field("endpoint", frame->rdx); serial_puts("\n"); return Z_OK;
        }
        if (argument == 12 && manifest.cells[current].image == 3) {
            event("demo-forbidden", current); field("rights", frame->rsi);
            field("result", frame->rdx); serial_puts("\n"); return Z_OK;
        }
        if (argument == 13 && manifest.cells[current].image == 3) {
            event("demo-resumed", current); field("reads", reads); serial_puts("\n"); return Z_OK;
        }
        if (argument == (uint64_t)manifest.cells[current].image + 2) {
            event("entry", current); serial_puts("\n"); return Z_OK;
        }
        event("bad-report", current); field("code", argument); serial_puts("\n");
        fail_cell(current, 66, 0, 0); return Z_INVALID;
    case Z_EXIT:
        z_broker_revoke(&broker, current); z_policy_stop(&broker.policies[current]);
        arch_space_release(current);
        event("exit", current); serial_puts("\n"); return Z_OK;
    default: return Z_INVALID;
    }
}

static void research_check(void)
{
    if (finished || ticks < 120 || Z_SOLO >= 0) return;
    unsigned block = role_slot(Z_BLOCK), fs = role_slot(Z_FS), client = role_slot(Z_CLIENT);
    unsigned probe = role_slot(Z_PROBE);
    bool probe_ok = probe < manifest.cell_count &&
        broker.policies[probe].phase == Z_POLICY_QUARANTINED;
    if (probe < manifest.cell_count && (Z_SCENARIO == 7 || Z_SCENARIO == 8 || Z_SCENARIO == 15))
        probe_ok = broker.policies[probe].phase == Z_POLICY_STOPPED && contract_ok;
    else if (probe < manifest.cell_count)
        probe_ok = probe_ok && broker.policies[probe].faults == 4 && boots[probe] == 4;
    bool pass = block < manifest.cell_count && fs < manifest.cell_count && client < manifest.cell_count &&
        probe < manifest.cell_count && recovered == 3 && reads > 2 && probe_ok &&
        reset_reports == boots[probe] && broker.policies[block].phase == Z_POLICY_READY &&
        broker.policies[fs].phase == Z_POLICY_READY && broker.policies[client].faults == 0 &&
        boots[client] == 1;
    serial_puts(pass ? "RESEARCH_PASS" : "RESEARCH_FAIL");
    field("scenario", Z_SCENARIO); field("reads", reads); field("tick", ticks); serial_puts("\n");
    finished = true;
    if (!pass || Z_TEST) arch_finish(pass ? 0 : 1);
}

static struct z_frame *schedule(void)
{
    for (;;) {
        for (unsigned offset = 1; offset <= manifest.cell_count; ++offset) {
            unsigned next = (current + offset) % manifest.cell_count;
            if (broker.policies[next].phase == Z_POLICY_READY) {
                current = next; arch_activate(current); return &frames[current];
            }
        }
        __asm__ volatile("sti; hlt; cli" ::: "memory"); supervisor_tick(); research_check();
    }
}

struct z_frame *kernel_trap(struct z_frame *frame)
{
    if ((frame->cs & 3) != 3) {
        if (frame->vector == 32) { ++ticks; arch_eoi(); return frame; }
        serial_puts("KERNEL_FAULT"); field("vector", frame->vector);
        field("rip", frame->rip); serial_puts("\n"); panic("trusted kernel fault");
    }
    frames[current] = *frame;
    if (frame->cs != 0x1b || frame->ss != 0x23 ||
        !z_canonical_address(frame->rip) || !z_canonical_address(frame->rsp)) {
        if (frame->vector == 32) { ++ticks; arch_eoi(); supervisor_tick(); }
        fail_cell(current, 69, 0, frame->rsp); return schedule();
    }
    frames[current].flags = (frame->flags | UINT64_C(0x202)) & ~UINT64_C(0x27000);
    if (frame->vector == 32) {
        ++ticks; arch_eoi(); if (++run_ticks[current] >= 5) fail_cell(current, 65, 0, 0);
        supervisor_tick(); research_check();
    } else if (frame->vector == 128) {
        run_ticks[current] = 0; frames[current].rax = (uint64_t)syscall(frame);
    } else if (frame->vector < 32) {
        fail_cell(current, frame->vector, frame->error,
                  frame->vector == 14 ? arch_fault_address() : 0);
    } else panic("unexpected interrupt");
    return schedule();
}

void kernel_main(void)
{
    serial_init(); serial_puts("ZEAL boot abi=2 x86_64\n");
    arch_init(); load_manifest(); z_broker_init(&broker);
    struct z_boot_grant grants[Z_MANIFEST_GRANT_MAX];
    for (unsigned i = 0; i < manifest.grant_count; ++i) {
        int holder = z_manifest_slot(&manifest, manifest.grants[i].holder);
        int target = z_manifest_slot(&manifest, manifest.grants[i].target);
        if (holder < 0 || target < 0) panic("manifest grant slot resolution failed");
        grants[i] = (struct z_boot_grant) { (uint32_t)holder, (uint32_t)target,
                                             manifest.grants[i].rights, 0 };
    }
    if (z_broker_configure(&broker, grants, manifest.grant_count) != Z_OK)
        panic("manifest initial grants rejected");
    unsigned active_count = 0;
    for (unsigned i = 0; i < manifest.cell_count; ++i) {
        if (!(manifest.cells[i].flags & Z_MANIFEST_ACTIVE)) {
            broker.policies[i] = (struct z_policy_state){ .phase = Z_POLICY_DORMANT };
            continue;
        }
        if (Z_SOLO >= 0 && i != (unsigned)Z_SOLO) {
            broker.policies[i] = (struct z_policy_state){ .phase = Z_POLICY_DORMANT };
            continue;
        }
        if (!arch_space_init(i, images[manifest.cells[i].image - 1],
                             image_lengths[manifest.cells[i].image - 1], &manifest.cells[i])) {
            serial_puts("MANIFEST_REJECT reason=cell memory allocation cell="); serial_hex(i);
            serial_puts("\n"); arch_finish(3);
        }
        cold_boot(i); ++active_count;
    }
    if (!active_count || z_broker_refresh(&broker) != Z_OK) panic("empty boot or initial authority failure");
    current = role_slot(Z_SOLO >= 0 ? (unsigned)Z_SOLO : Z_BLOCK);
    if (current >= manifest.cell_count || broker.policies[current].phase != Z_POLICY_READY)
        panic("standalone selection is not active");
    arch_activate(current); arch_enter(&frames[current]);
}
