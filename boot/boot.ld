OUTPUT_FORMAT(binary)
ENTRY(_start)
SECTIONS
{
    . = 0x7c00;
    .text : { *(.text) }
    /DISCARD/ : { *(.note*) *(.comment*) }
}
ASSERT(SIZEOF(.text) == 512, "BIOS boot sector must be 512 bytes")
