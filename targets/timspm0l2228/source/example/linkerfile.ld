ENTRY(_start)

MEMORY
{
    FLASH (RX)  : ORIGIN = 0x1000000, LENGTH = 0x10000      /* 64 KiB */
    RAM (RWX)   : ORIGIN = 0x2000000, LENGTH = 0x10000      /* 64 KiB */
}

SECTIONS
{
    .text   : {
        *(.startup)        /* _start goes first */
        *(.text)           /* then everything else */
    } > FLASH
    .rodata : { *(.rodata) } > FLASH

    .data   : { *(.data) } > RAM AT > FLASH
    .bss    : { *(.bss)  } > RAM
}
