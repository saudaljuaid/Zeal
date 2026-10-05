OUTPUT_FORMAT(elf64-x86-64)
OUTPUT_ARCH(i386:x86-64)
ENTRY(kernel_entry)
SECTIONS
{
    . = 0x10000;
    __kernel_start = .;
    .text : ALIGN(16) { KEEP(*(.boot.text)) *(.text .text.*) }
    .rodata : ALIGN(16) { *(.rodata .rodata.*) }
    .data : ALIGN(4096) { *(.boot.data) *(.data .data.*) }
    __kernel_load_end = .;
    . = 0x200000;
    .bss (NOLOAD) : ALIGN(4096) {
        __bss_start = .;
        *(.bss .bss.*) *(COMMON)
        . = ALIGN(16);
        __bss_end = .;
    }
    __kernel_end = .;
    /DISCARD/ : { *(.eh_frame*) *(.note*) *(.comment*) }
}
ASSERT(__kernel_load_end <= 0x90000, "BIOS payload exceeds conventional-memory window")
ASSERT(__kernel_end < 0x40000000, "kernel exceeds identity mapping")
