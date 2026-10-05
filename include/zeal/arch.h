#ifndef ZEAL_ARCH_H
#define ZEAL_ARCH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct z_frame {
    uint64_t r15, r14, r13, r12, r11, r10, r9, r8;
    uint64_t rdi, rsi, rbp, rdx, rcx, rbx, rax;
    uint64_t vector, error, rip, cs, flags, rsp, ss;
};

void arch_init(void);
bool arch_space_init(unsigned cell, const void *image, size_t length);
void arch_space_reset(unsigned cell, const void *image, size_t length);
void arch_activate(unsigned cell);
bool arch_user_range(uint64_t address, size_t length, bool write);
void arch_user_copy_in(void *destination, uint64_t source, size_t length);
void arch_user_copy_out(uint64_t destination, const void *source, size_t length);
void arch_frame_init(struct z_frame *frame);
void arch_enter(struct z_frame *frame) __attribute__((noreturn));
struct z_frame *kernel_trap(struct z_frame *frame);
void arch_eoi(void);
uint64_t arch_fault_address(void);
void serial_init(void);
void serial_puts(const char *s);
void serial_hex(uint64_t value);
void arch_finish(unsigned code) __attribute__((noreturn));
void kernel_main(void) __attribute__((noreturn));

#endif
