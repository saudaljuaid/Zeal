#ifndef ZEAL_WAIT_H
#define ZEAL_WAIT_H

#include <stdbool.h>
#include <zeal/ipc.h>

enum z_wait_kind { Z_WAIT_NONE, Z_WAIT_SLEEP, Z_WAIT_RECEIVE };
enum z_wake_reason {
    Z_WAKE_NONE, Z_WAKE_SLEEP, Z_WAKE_MESSAGE, Z_WAKE_TIMEOUT,
    Z_WAKE_BAD_ADDRESS, Z_WAKE_CANCELLED
};
enum z_wait_status { Z_WAIT_PENDING, Z_WAIT_DONE, Z_WAIT_CANCELLED };

struct z_wait_entry {
    uint64_t generation;
    uint64_t deadline;
    uint64_t destination;
    uint32_t kind;
    uint32_t reserved;
};
struct z_wait_table { struct z_wait_entry entries[Z_CELL_COUNT]; };

_Static_assert(sizeof(struct z_wait_entry) == 32, "bounded wait entry");

/* All operations run on the single CPU with interrupts masked. The callback
 * validates destination and cell backing when message is NULL, and performs
 * a checked copy when non-NULL. No message is consumed if either step fails. */
void z_wait_init(struct z_wait_table *table);
void z_wait_cancel(struct z_wait_table *table, unsigned cell);
int z_wait_deadline(uint64_t now, uint64_t duration, uint64_t *deadline);
int z_wait_sleep(struct z_wait_table *table, const struct z_broker *broker,
                 unsigned cell, uint64_t now, uint64_t duration);
int z_wait_receive(struct z_wait_table *table, struct z_broker *broker,
                   unsigned cell, uint64_t now, uint64_t duration,
                   uint64_t destination, z_receive_copy_fn copy, void *context,
                   bool *blocked);
enum z_wait_status z_wait_poll(struct z_wait_table *table,
                               struct z_broker *broker, unsigned cell,
                               uint64_t now, z_receive_copy_fn copy,
                               void *context, int *result,
                               enum z_wake_reason *reason);
bool z_wait_runnable(const struct z_wait_table *table,
                      const struct z_broker *broker, unsigned cell);
/* Round-robin search starts after the supplied cell, returning -1 for idle. */
int z_wait_next(const struct z_wait_table *table,
                 const struct z_broker *broker, unsigned after);

#endif
