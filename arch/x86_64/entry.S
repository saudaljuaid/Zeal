.section .boot.text,"ax",@progbits
.code32
.global kernel_entry
kernel_entry:
    cli
    cld
    mov $0x10, %ax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %ss
    mov $0x90000, %esp

    pushfl
    pop %eax
    mov %eax, %ecx
    xor $0x200000, %eax
    push %eax
    popfl
    pushfl
    pop %eax
    xor %ecx, %eax
    test $0x200000, %eax
    jz unsupported
    push %ecx
    popfl
    mov $0x80000000, %eax
    cpuid
    cmp $0x80000001, %eax
    jb unsupported
    mov $0x80000001, %eax
    cpuid
    and $0x20100000, %edx
    cmp $0x20100000, %edx
    jne unsupported
    mov $1, %eax
    cpuid
    test $0x40, %edx
    jz unsupported
    test $0x800, %edx
    jz disable_syscall_done
    xor %eax, %eax
    xor %edx, %edx
    mov $0x174, %ecx
    wrmsr
disable_syscall_done:

    mov $bootstrap_pml4, %edi
    xor %eax, %eax
    mov $(3 * 4096 / 4), %ecx
    rep stosl
    mov $(bootstrap_pdpt + 3), %eax
    mov %eax, bootstrap_pml4
    mov $(bootstrap_pd + 3), %eax
    mov %eax, bootstrap_pdpt
    mov $bootstrap_pd, %edi
    mov $0x83, %eax
    mov $512, %ecx
map_low:
    mov %eax, (%edi)
    add $0x200000, %eax
    add $8, %edi
    loop map_low
    mov $0x20, %eax
    mov %eax, %cr4
    mov $bootstrap_pml4, %eax
    mov %eax, %cr3
    mov $0xc0000080, %ecx
    rdmsr
    and $0xfffffffe, %eax
    or $0x900, %eax
    wrmsr
    mov %cr0, %eax
    or $0x8001000e, %eax
    mov %eax, %cr0
    lgdt long_gdt_pointer
    ljmp $0x08, $long_entry
unsupported:
    mov $0xf4, %dx
    mov $0x7e, %eax
    out %eax, %dx
halt32:
    cli
    hlt
    jmp halt32

.code64
long_entry:
    mov $0x10, %ax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %ss
    xor %eax, %eax
    mov %ax, %fs
    mov %ax, %gs
    xor %edx, %edx
    mov $0xc0000100, %ecx
    wrmsr
    inc %ecx
    wrmsr
    inc %ecx
    wrmsr
    mov $__bss_start, %edi
    mov $__bss_end, %ecx
    sub %edi, %ecx
    rep stosb
    mov $kernel_stack_top, %rsp
    xor %ebp, %ebp
    call kernel_main
halt64:
    cli
    hlt
    jmp halt64

.balign 8
long_gdt:
    .quad 0
    .quad 0x00af9a000000ffff
    .quad 0x00cf92000000ffff
long_gdt_pointer:
    .word long_gdt_pointer - long_gdt - 1
    .long long_gdt

.section .boot.data,"aw",@progbits
.balign 4096
bootstrap_pml4:
    .zero 4096
bootstrap_pdpt:
    .zero 4096
bootstrap_pd:
    .zero 4096

.section .bss,"aw",@nobits
.balign 16
kernel_stack:
    .skip 32768
.global kernel_stack_top
kernel_stack_top:
.section .note.GNU-stack,"",@progbits
