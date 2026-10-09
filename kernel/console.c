#include <zeal/console.h>

static bool checked_callbacks(const struct z_console_callbacks *callbacks)
{
    return callbacks != NULL && callbacks->range != NULL &&
        callbacks->copy_in != NULL && callbacks->copy_out != NULL;
}

int64_t z_console_read(const struct z_console_callbacks *callbacks, void *context,
                       bool entitled, uint64_t destination, uint64_t count, uint64_t reserved)
{
    if (!entitled) return Z_DENIED;
    if (reserved || !checked_callbacks(callbacks) || callbacks->try_read == NULL) return Z_INVALID;
    if (count > Z_CONSOLE_LIMIT) return Z_TOO_LARGE;
    if (count == 0) return 0;
    if (!callbacks->range(context, destination, (size_t)count, true)) return Z_BAD_ADDRESS;
    uint8_t bytes[Z_CONSOLE_LIMIT];
    size_t received = 0;
    while (received < (size_t)count && callbacks->try_read(context, &bytes[received])) ++received;
    if (received && !callbacks->copy_out(context, destination, bytes, received)) return Z_BAD_ADDRESS;
    return (int64_t)received;
}

int64_t z_console_write(const struct z_console_callbacks *callbacks, void *context,
                        bool entitled, uint64_t source, uint64_t count, uint64_t reserved)
{
    if (!entitled) return Z_DENIED;
    if (reserved || !checked_callbacks(callbacks) || callbacks->try_write == NULL) return Z_INVALID;
    if (count > Z_CONSOLE_LIMIT) return Z_TOO_LARGE;
    if (count == 0) return 0;
    if (!callbacks->range(context, source, (size_t)count, false)) return Z_BAD_ADDRESS;
    uint8_t bytes[Z_CONSOLE_LIMIT];
    if (!callbacks->copy_in(context, bytes, source, (size_t)count)) return Z_BAD_ADDRESS;
    size_t written = 0;
    while (written < (size_t)count && callbacks->try_write(context, bytes[written])) ++written;
    return (int64_t)written;
}

int64_t z_console_system_info(const struct z_console_callbacks *callbacks, void *context,
                              const struct z_system_info *info, uint64_t destination,
                              uint64_t size, uint64_t reserved)
{
    if (reserved || size != sizeof(*info) || info == NULL || !checked_callbacks(callbacks)) return Z_INVALID;
    if (!callbacks->range(context, destination, sizeof(*info), true) ||
        !callbacks->copy_out(context, destination, info, sizeof(*info))) return Z_BAD_ADDRESS;
    return Z_OK;
}
