ENTRY(_start)

SECTIONS
{
    .text : {
        *(.startup*)    /* _start goes first */
        *(.text*)           /* then everything else */
    }

    .data : { *(.data*) }
    .bss  : { *(.bss*)  }
}
