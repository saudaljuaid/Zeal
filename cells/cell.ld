ENTRY(_start)

SECTIONS {
    . = 0x40000000;
    .text : { KEEP(*(.text.entry)) *(.text .text.*) }
    .rodata : { *(.rodata .rodata.*) }
    .forbidden : { *(.data .data.* .bss .bss.* COMMON) }
    /DISCARD/ : { *(.comment .note.* .eh_frame .eh_frame_hdr) }
    ASSERT(SIZEOF(.forbidden) == 0, "cell contains mutable global storage")
    ASSERT(. <= 0x40010000, "cell exceeds its 64 KiB image")
    ASSERT(_start == 0x40000000, "cell entry is not at the sealed image base")
}
