#include <stddef.h>
#include <zeal/wait.h>

void z_wait_init(struct z_wait_table *table)
{
    if (table != NULL)
        *table = (struct z_wait_table){0};
}

void z_wait_cancel(struct z_wait_table *table, unsigned cell)
{
    if (table != NULL && cell < Z_CELL_COUNT)
        table->entries[cell] = (struct z_wait_entry){0};
}

int z_wait_deadline(uint64_t now, uint64_t duration, uint64_t *deadline)
{
    if (deadline == NULL || duration > Z_WAIT_MAX_TICKS ||
        duration > UINT64_MAX - now)
        return Z_INVALID;
    *deadline = now + duration;
    return Z_OK;
}

static int available(const struct z_wait_table *table,
                      const struct z_broker *broker, unsigned cell)
{
    if (table == NULL || broker == NULL || cell >= Z_CELL_COUNT)
        return Z_INVALID;
    if (broker->policies[cell].phase != Z_POLICY_READY)
        return Z_AGAIN;
    return table->entries[cell].kind == Z_WAIT_NONE ? Z_OK : Z_INVALID;
}

static void arm(struct z_wait_table *table, const struct z_broker *broker,
                 unsigned cell, uint64_t deadline, uint64_t destination,
                 enum z_wait_kind kind)
{
    table->entries[cell] = (struct z_wait_entry){
        .generation = broker->policies[cell].generation,
        .deadline = deadline,
        .destination = destination,
        .kind = kind,
    };
}

int z_wait_sleep(struct z_wait_table *table, const struct z_broker *broker,
                 unsigned cell, uint64_t now, uint64_t duration)
{
    uint64_t deadline;
    int result = available(table, broker, cell);
    if (result != Z_OK)
        return result;
    result = z_wait_deadline(now, duration, &deadline);
    if (result != Z_OK)
        return result;
    if (duration)
        arm(table, broker, cell, deadline, 0, Z_WAIT_SLEEP);
    return Z_OK;
}

int z_wait_receive(struct z_wait_table *table, struct z_broker *broker,
                   unsigned cell, uint64_t now, uint64_t duration,
                   uint64_t destination, z_receive_copy_fn copy, void *context,
                   bool *blocked)
{
    if (blocked == NULL)
        return Z_INVALID;
    *blocked = false;
    uint64_t deadline;
    int result = available(table, broker, cell);
    if (result != Z_OK)
        return result;
    result = z_wait_deadline(now, duration, &deadline);
    if (result != Z_OK)
        return result;
    result = z_broker_receive_checked(broker, cell, destination, copy, context);
    if (result != Z_AGAIN || !duration)
        return result;
    /* The queue check and this publication share an interrupt-masked kernel
     * entry. A send cannot interleave; every scheduler pass polls after sends. */
    arm(table, broker, cell, deadline, destination, Z_WAIT_RECEIVE);
    *blocked = true;
    return Z_OK;
}

enum z_wait_status z_wait_poll(struct z_wait_table *table,
                               struct z_broker *broker, unsigned cell,
                               uint64_t now, z_receive_copy_fn copy,
                               void *context, int *result,
                               enum z_wake_reason *reason)
{
    if (table == NULL || broker == NULL || cell >= Z_CELL_COUNT ||
        result == NULL || reason == NULL)
        return Z_WAIT_PENDING;
    *reason = Z_WAKE_NONE;
    struct z_wait_entry *entry = &table->entries[cell];
    if (entry->kind == Z_WAIT_NONE)
        return Z_WAIT_PENDING;
    if (entry->generation != broker->policies[cell].generation ||
        broker->policies[cell].phase != Z_POLICY_READY) {
        z_wait_cancel(table, cell);
        *result = Z_STALE;
        *reason = Z_WAKE_CANCELLED;
        return Z_WAIT_CANCELLED;
    }
    /* Expiry wins at the exact deadline, even if a message is now queued. */
    if (now >= entry->deadline) {
        *result = entry->kind == Z_WAIT_SLEEP ? Z_OK : Z_TIMEOUT;
        *reason = entry->kind == Z_WAIT_SLEEP ? Z_WAKE_SLEEP : Z_WAKE_TIMEOUT;
    } else if (entry->kind == Z_WAIT_RECEIVE) {
        *result = z_broker_receive_checked(broker, cell, entry->destination,
                                           copy, context);
        if (*result == Z_AGAIN)
            return Z_WAIT_PENDING;
        *reason = *result == Z_OK ? Z_WAKE_MESSAGE : Z_WAKE_BAD_ADDRESS;
    } else {
        return Z_WAIT_PENDING;
    }
    z_wait_cancel(table, cell);
    return Z_WAIT_DONE;
}

bool z_wait_runnable(const struct z_wait_table *table,
                      const struct z_broker *broker, unsigned cell)
{
    return table != NULL && broker != NULL && cell < Z_CELL_COUNT &&
           broker->policies[cell].phase == Z_POLICY_READY &&
           table->entries[cell].kind == Z_WAIT_NONE;
}

int z_wait_next(const struct z_wait_table *table,
                 const struct z_broker *broker, unsigned after)
{
    if (after >= Z_CELL_COUNT)
        return Z_INVALID;
    for (unsigned offset = 1; offset <= Z_CELL_COUNT; ++offset) {
        unsigned cell = (after + offset) % Z_CELL_COUNT;
        if (z_wait_runnable(table, broker, cell))
            return (int)cell;
    }
    return -1;
}
