"""Neutralise PREFETCHW (0F 0D /1) inside a boot binary.

Pentium 4 (Prescott) and the first-generation Socket 754 Athlon 64 do not
implement PREFETCHW and raise #UD on it.  Both winload.exe and ntoskrnl.exe
execute it, and the earliest occurrences run long before the kernel installs
an exception handler -- the machine just resets, with no bugcheck, no dump and
no bootlog entry.

This is easy to miss when testing in a VM: QEMU decodes 0F 0D as a NOP
regardless of CPUID, so everything looks fine while real hardware reboots.

`0F 0D /1` is rewritten to a length-preserving `0F 1F /0` (a plain NOP).

One trap: a naive byte scan also finds `0F 0D` bytes that belong to the
relative displacement of a CALL/JMP.  Rewriting those turns a valid call into
a jump into nowhere -- in one ntoskrnl build this silently corrupted
`call ObfDereferenceObject` (`E8 0F 0D 8F FF`).  Candidates that sit inside a
rel32 are therefore skipped.
"""

import pefile

IMAGE_SCN_MEM_EXECUTE = 0x20000000


def _inside_rel32(data: bytearray, pe: pefile.PE, rva: int) -> bool:
    """True when `rva` points into the displacement of a CALL/JMP rel32."""
    for back in range(1, 5):
        try:
            off = pe.get_offset_from_rva(rva - back)
        except Exception:
            continue
        if off is None or off >= len(data):
            continue
        if data[off] in (0xE8, 0xE9):
            return True
    return False


def neutralize_prefetchw(data: bytearray) -> list:
    """Rewrite every real PREFETCHW in the image.  Returns the patched RVAs."""
    pe = pefile.PE(data=bytes(data), fast_load=True)
    patched = []
    try:
        for sec in pe.sections:
            if not (sec.Characteristics & IMAGE_SCN_MEM_EXECUTE):
                continue
            start = sec.PointerToRawData
            end = start + sec.SizeOfRawData
            if start >= len(data):
                continue
            end = min(end, len(data))
            rva_base = sec.VirtualAddress
            i = start
            while i + 2 < end:
                if data[i] == 0x0F and data[i + 1] == 0x0D:
                    modrm = data[i + 2]
                    # /1 == PREFETCHW, /0 would be PREFETCHNTA and /2.. are
                    # different (or reserved) hints
                    if ((modrm >> 3) & 7) == 1:
                        rva = rva_base + (i - start)
                        if not _inside_rel32(data, pe, rva):
                            data[i + 1] = 0x1F
                            data[i + 2] = modrm & 0xC7
                            patched.append(rva)
                        i += 3
                        continue
                i += 1
    finally:
        pe.close()
    return patched
