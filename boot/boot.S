.code16
.section .text
.global _start

.if KERNEL_SECTORS < 1
.error "empty kernel payload"
.endif
.if KERNEL_SECTORS > 1024
.error "kernel payload overlaps bootstrap stack"
.endif

_start:
    ljmp $0, $normalized
normalized:
    cli
    xor %ax, %ax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %ss
    mov $0x7c00, %sp
    sti
    cld
    mov %dl, drive
    mov $0x55aa, %bx
    mov $0x41, %ah
    int $0x13
    jc failed
    cmp $0xaa55, %bx
    jne failed
    test $1, %cx
    jz failed
next_chunk:
    mov remaining, %ax
    test %ax, %ax
    jz loaded
    cmp $16, %ax
    jbe selected
    mov $16, %ax
selected:
    mov %ax, chunk
    movb $3, attempts
retry:
    mov chunk, %ax
    mov %ax, packet_count
    mov $packet, %si
    mov drive, %dl
    mov $0x42, %ah
    push %ds
    int $0x13
    pop %ds
    jnc advance
    xor %ax, %ax
    mov drive, %dl
    push %ds
    int $0x13
    pop %ds
    decb attempts
    jnz retry
    jmp failed
advance:
    mov chunk, %ax
    sub %ax, remaining
    movzwl %ax, %eax
    addl %eax, packet_lba
    shl $5, %ax
    add %ax, packet_segment
    jmp next_chunk
loaded:
    cli
    in $0x92, %al
    or $2, %al
    and $0xfe, %al
    out %al, $0x92
    lgdt gdt_pointer
    mov %cr0, %eax
    or $1, %eax
    mov %eax, %cr0
    ljmpl $0x08, $0x10000
failed:
    mov $failure_text, %si
print:
    lodsb
    test %al, %al
    jz stopped
    mov $0x0e, %ah
    mov $7, %bx
    int $0x10
    jmp print
stopped:
    cli
    hlt
    jmp stopped

.balign 8
gdt:
    .quad 0
    .quad 0x00cf9a000000ffff
    .quad 0x00cf92000000ffff
gdt_pointer:
    .word gdt_pointer - gdt - 1
    .long gdt
.balign 16
packet:
    .byte 16, 0
packet_count:
    .word 0
    .word 0
packet_segment:
    .word 0x1000
packet_lba:
    .quad 1
remaining:
    .word KERNEL_SECTORS
chunk:
    .word 0
drive:
    .byte 0
attempts:
    .byte 0
failure_text:
    .asciz "Zeal: BIOS disk read failed"

.org 510
    .word 0xaa55
.section .note.GNU-stack,"",@progbits
