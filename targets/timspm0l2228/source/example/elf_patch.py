#!/usr/bin/env python3
"""
elf_patch.py — Replace a function's instructions in an ELF binary.

Usage:
    python3 elf_patch.py <elf_file> <function_name> <new_code.bin> [--output <out_file>]

Arguments:
    elf_file        Path to the input ELF binary (modified in-place unless --output given)
    function_name   Name of the function to replace (must exist in the symbol table)
    new_code.bin    Raw binary file containing replacement machine code
    --output / -o   Write patched binary here instead of modifying the input

Requires:
    pip install pyelftools

Behaviour:
    1. Locates the function via the ELF symbol table (.symtab or .dynsym).
    2. Checks that the replacement code fits inside the original function's extent.
       If the replacement is SMALLER, the remainder is padded with NOPs (0x90 on x86/x86-64,
       or 0x00 for other architectures which is typically a safe filler — see ARCH_NOP below).
    3. Writes the patched binary to the output path.

Limitations / caveats:
    • The replacement must not be LARGER than the original function (patching cannot
      relocate code; that would require a full linker).  If you need more space, consider
      a trampoline approach or recompiling with enough padding.
    • Stripped binaries have no symbol table and will fail gracefully with a clear error.
    • Works on any ELF class (32-bit / 64-bit) and any ISA, though the NOP byte is
      architecture-specific — update ARCH_NOP if needed.
    • ARM Thumb functions are detected automatically via the bit-0 convention in st_value
      and are padded with the correct 2-byte Thumb NOP (0x00 0xBF).
"""

import argparse
import shutil
import sys
from pathlib import Path

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection
except ImportError:
    sys.exit(
        "pyelftools is not installed.\n"
        "Install it with:  pip install pyelftools"
    )

# ---------------------------------------------------------------------------
# Architecture → NOP byte mapping.
# Add entries here for exotic ISAs as needed.
# ---------------------------------------------------------------------------
ARCH_NOP: dict[str, bytes] = {
    "x86":      b"\x90",
    "x64":      b"\x90",
    "x86_64":   b"\x90",
    "EM_386":   b"\x90",
    "EM_X86_64": b"\x90",
    "EM_AARCH64": b"\x1f\x20\x03\xd5",  # AArch64 NOP (4-byte aligned)
    "EM_ARM":   b"\x00\x00\xa0\xe3",    # ARM (32-bit) MOV r0, r0
    # Thumb NOP is handled dynamically in get_nop() — do not add it here.
    "EM_MIPS":  b"\x00\x00\x00\x00",    # MIPS NOP (sll $zero, $zero, 0)
    "EM_RISCV": b"\x13\x00\x00\x00",    # RISC-V NOP (addi x0, x0, 0)
    "EM_PPC64": b"\x60\x00\x00\x00",    # PPC64 NOP
}

DEFAULT_NOP = b"\x00"


def is_thumb_symbol(sym) -> bool:
    """In the ARM ELF ABI, Thumb function symbols have bit 0 set in st_value."""
    return sym["st_value"] & 1 == 1


def get_nop(elf: ELFFile, thumb: bool = False) -> bytes:
    arch = elf.header.e_machine          # e.g. "EM_X86_64"
    if arch == "EM_ARM" and thumb:
        return b"\x00\xbf"              # Thumb NOP (2-byte)
    return ARCH_NOP.get(arch, DEFAULT_NOP)


def find_function(elf: ELFFile, name: str):
    """Return (file_offset, size, is_thumb) for *name*, or raise ValueError."""
    for section in elf.iter_sections():
        if not isinstance(section, SymbolTableSection):
            continue
        for sym in section.iter_symbols():
            if sym.name == name and sym["st_size"] > 0 and sym["st_info"]["type"] == "STT_FUNC":
                thumb = is_thumb_symbol(sym)
                vaddr = sym["st_value"] & ~1  # strip Thumb indicator bit if present
                size  = sym["st_size"]
                return _vaddr_to_offset(elf, vaddr), size, thumb
    raise ValueError(
        f"Function '{name}' not found in the ELF symbol table.\n"
        "  • Make sure the binary is not stripped.\n"
        "  • Use 'nm <elf_file>' or 'readelf -s <elf_file>' to list available symbols."
    )


def _vaddr_to_offset(elf: ELFFile, vaddr: int) -> int:
    """Convert a virtual address to a file offset using program headers."""
    for seg in elf.iter_segments():
        if seg.header.p_type != "PT_LOAD":
            continue
        seg_vaddr = seg.header.p_vaddr
        seg_filesz = seg.header.p_filesz
        seg_offset = seg.header.p_offset
        if seg_vaddr <= vaddr < seg_vaddr + seg_filesz:
            return seg_offset + (vaddr - seg_vaddr)
    raise ValueError(f"Virtual address 0x{vaddr:x} not found in any PT_LOAD segment.")


def patch(elf_path: Path, func_name: str, code_path: Path, out_path: Path) -> None:
    new_code = code_path.read_bytes()

    with elf_path.open("rb") as fh:
        elf = ELFFile(fh)
        offset, func_size, thumb = find_function(elf, func_name)
        nop = get_nop(elf, thumb)
        arch = elf.header.e_machine

    if len(new_code) > func_size:
        raise ValueError(
            f"Replacement code ({len(new_code)} bytes) is LARGER than "
            f"the original function '{func_name}' ({func_size} bytes).\n"
            "The patch cannot extend beyond the original function boundary."
        )

    # Build the padded replacement block.
    pad_needed = func_size - len(new_code)
    if pad_needed % len(nop) != 0:
        # Fall back to single-byte padding when alignment doesn't work out.
        padding = DEFAULT_NOP * pad_needed
    else:
        padding = nop * (pad_needed // len(nop))

    replacement = new_code + padding
    assert len(replacement) == func_size, "Internal error: replacement size mismatch."

    # Copy the input to the output path, then patch in-place.
    if out_path != elf_path:
        shutil.copy2(elf_path, out_path)

    with out_path.open("r+b") as fh:
        fh.seek(offset)
        fh.write(replacement)

    print(f"✓  Patched '{func_name}' in '{out_path}'")
    print(f"   Architecture : {arch}{' (Thumb)' if thumb else ''}")
    print(f"   File offset  : 0x{offset:08x}")
    print(f"   Function size: {func_size} bytes")
    print(f"   New code size: {len(new_code)} bytes")
    print(f"   NOP padding  : {pad_needed} bytes  ({repr(nop)} × {pad_needed // len(nop) if len(nop) and pad_needed % len(nop) == 0 else pad_needed})")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Replace a function's machine code in an ELF binary.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("elf_file",      help="Input ELF binary")
    parser.add_argument("function_name", help="Symbol name of the function to replace")
    parser.add_argument("new_code",      help="Raw binary file with replacement instructions")
    parser.add_argument("-o", "--output", default=None,
                        help="Output path (default: overwrite input file)")

    args = parser.parse_args()

    elf_path  = Path(args.elf_file)
    code_path = Path(args.new_code)
    out_path  = Path(args.output) if args.output else elf_path

    if not elf_path.exists():
        sys.exit(f"Error: ELF file not found: {elf_path}")
    if not code_path.exists():
        sys.exit(f"Error: replacement code file not found: {code_path}")

    try:
        patch(elf_path, args.function_name, code_path, out_path)
    except ValueError as exc:
        sys.exit(f"Error: {exc}")


if __name__ == "__main__":
    main()
