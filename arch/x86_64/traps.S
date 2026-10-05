.section .text
.code64

.macro ISR number error=0
.global isr_\number
isr_\number:
.if !\error
    pushq $0
.endif
    pushq $\number
    jmp trap_common
.endm

ISR 0
ISR 1
ISR 2
ISR 3
ISR 4
ISR 5
ISR 6
ISR 7
ISR 8, 1
ISR 9
ISR 10, 1
ISR 11, 1
ISR 12, 1
ISR 13, 1
ISR 14, 1
ISR 15
ISR 16
ISR 17, 1
ISR 18
ISR 19
ISR 20
ISR 21, 1
ISR 22
ISR 23
ISR 24
ISR 25
ISR 26
ISR 27
ISR 28
ISR 29, 1
ISR 30, 1
ISR 31
ISR 32
ISR 128
ISR 255

trap_common:
    cld
    push %rax
    push %rbx
    push %rcx
    push %rdx
    push %rbp
    push %rsi
    push %rdi
    push %r8
    push %r9
    push %r10
    push %r11
    push %r12
    push %r13
    push %r14
    push %r15
    xor %eax, %eax
    mov %ax, %fs
    mov %ax, %gs
    mov $0x10, %ax
    mov %ax, %ds
    mov %ax, %es
    mov %rsp, %rdi
    and $-16, %rsp
    call kernel_trap
    mov %rax, %rsp
restore_frame:
    xor %eax, %eax
    mov %ax, %fs
    mov %ax, %gs
    mov $0x10, %ax
    testb $3, 144(%rsp)
    jz restore_segments
    mov $0x23, %ax
restore_segments:
    mov %ax, %ds
    mov %ax, %es
    pop %r15
    pop %r14
    pop %r13
    pop %r12
    pop %r11
    pop %r10
    pop %r9
    pop %r8
    pop %rdi
    pop %rsi
    pop %rbp
    pop %rdx
    pop %rcx
    pop %rbx
    pop %rax
    add $16, %rsp
    iretq

.global arch_enter
.type arch_enter, @function
arch_enter:
    mov %rdi, %rsp
    jmp restore_frame
.size arch_enter, .-arch_enter

.global arch_load_gdt
.type arch_load_gdt, @function
arch_load_gdt:
    lgdt (%rdi)
    pushq $0x08
    lea gdt_loaded(%rip), %rax
    push %rax
    lretq
gdt_loaded:
    mov $0x10, %ax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %ss
    mov $0x28, %ax
    ltr %ax
    ret
.size arch_load_gdt, .-arch_load_gdt

.section .rodata
.global arch_exception_entries
arch_exception_entries:
.irp number,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31
    .quad isr_\number
.endr
.section .note.GNU-stack,"",@progbits
