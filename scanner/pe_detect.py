"""
Aegis Node — bounded, read-only Windows PE header validation.

An "MZ" byte pair on its own is not an executable: it appears in country codes,
random identifiers and binary columns. PE evidence requires a DOS header whose
e_lfanew field (offset 0x3C) points, within bounds, at the "PE\\0\\0" signature
followed by a known machine type. Nothing found here is ever loaded or executed.
"""

import struct

DOS_HEADER_SIZE = 0x40          # e_lfanew lives at 0x3C..0x40
MAX_E_LFANEW = 0x10000          # real linkers place the PE header well below 64 KB
MAX_CANDIDATES = 256            # bound the work on files full of "MZ" pairs

# IMAGE_FILE_MACHINE_* values that appear in real PE files
_KNOWN_MACHINES = {
    0x014C,  # i386
    0x8664,  # AMD64
    0x01C0,  # ARM
    0x01C4,  # ARMNT
    0xAA64,  # ARM64
    0x0200,  # IA64
    0x0EBC,  # EFI byte code
}


def pe_header_at(data: bytes, pos: int) -> bool:
    """True if a structurally valid PE header starts at `pos` (bounds-checked)."""
    if pos < 0 or pos + DOS_HEADER_SIZE > len(data) or data[pos:pos + 2] != b"MZ":
        return False
    (e_lfanew,) = struct.unpack_from("<I", data, pos + 0x3C)
    if e_lfanew < DOS_HEADER_SIZE or e_lfanew > MAX_E_LFANEW:
        return False
    sig = pos + e_lfanew
    if sig + 6 > len(data) or data[sig:sig + 4] != b"PE\x00\x00":
        return False
    (machine,) = struct.unpack_from("<H", data, sig + 4)
    return machine in _KNOWN_MACHINES


def find_embedded_pe(data: bytes, start: int = 1) -> int | None:
    """Offset of the first valid PE header at or after `start`, else None."""
    pos = data.find(b"MZ", start)
    checked = 0
    while pos != -1 and checked < MAX_CANDIDATES:
        if pe_header_at(data, pos):
            return pos
        checked += 1
        pos = data.find(b"MZ", pos + 1)
    return None
