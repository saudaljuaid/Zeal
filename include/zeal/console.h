#ifndef ZEAL_CONSOLE_H
#define ZEAL_CONSOLE_H

#include <zeal/abi.h>
#include <stdbool.h>

/* Checked copies and single-attempt device operations form the complete seam.
 * Caller authority is supplied only by the supervisor's current live record. */
struct z_console_callbacks {
    bool (*range)(void *context, uint64_t address, size_t length, bool write);
    bool (*copy_in)(void *context, void *destination, uint64_t source, size_t length);
    bool (*copy_out)(void *context, uint64_t destination, const void *source, size_t length);
    bool (*try_read)(void *context, uint8_t *byte);
    bool (*try_write)(void *context, uint8_t byte);
};

int64_t z_console_read(const struct z_console_callbacks *callbacks, void *context,
                       bool entitled, uint64_t destination, uint64_t count, uint64_t reserved);
int64_t z_console_write(const struct z_console_callbacks *callbacks, void *context,
                        bool entitled, uint64_t source, uint64_t count, uint64_t reserved);
int64_t z_console_system_info(const struct z_console_callbacks *callbacks, void *context,
                              const struct z_system_info *info, uint64_t destination,
                              uint64_t size, uint64_t reserved);

#endif
