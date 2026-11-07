"""Neutralise PREFETCHW (0F 0D /1) inside a boot binary.

Pentium 4 (Prescott) and the first-generation Socket 754 Athlon 64 do not
implement PREFETCHW and raise #UD on it.  Both winload.exe and ntoskrnl.exe
execute it, and the earliest occurrences run long before the kernel installs
an exception handler -- the machine just resets, with no bugcheck, no dump and
no bootlog entry.

This is easy to miss when testing in a VM: QEMU decodes 0F 0D as a NOP
regardless of CPUID, so everything looks fine while real hardware reboots.

`0F 0D /1` is rewritten to a length-preserving `0F 1F /0` (a plain NOP).
Neither instruction touches flags, so this is semantically free.

Why verification matters
------------------------
The two bytes `0F 0D` also occur inside data, inside padding, and in the
middle of other instructions.  On the Windows 10 1607 (14393) kernel a plain
byte scan finds 616 candidates of which only 309 are real instructions;
rewriting the other 307 makes the machine reboot immediately after the logo.

Candidates are therefore checked against an instruction-boundary map when
`verify` is enabled:

  1. collect trusted decode entry points -- PE entry point, exports and every
     .pdata RUNTIME_FUNCTION start;
  2. decode recursively with capstone, following direct call/jcc/jmp targets;
  3. patch only candidates that were reached as an instruction start.

If verification yields nothing (a stripped image, or one the map does not
cover) the module falls back to the old heuristic so that winload.exe -- which
only has one or two of these instructions and little unwind data -- is still
patched.
"""

import pefile

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    from capstone.x86 import X86_OP_IMM
    HAVE_CAPSTONE = True
except ImportError:                                  # pragma: no cover
    HAVE_CAPSTONE = False

IMAGE_SCN_MEM_EXECUTE = 0x20000000


# --------------------------------------------------------------------- PE
def _sections(pe):
    out = []
    for s in pe.sections:
        out.append({
            "name": s.Name.rstrip(b"\0").decode("latin1"),
            "va": s.VirtualAddress,
            "vsize": s.Misc_VirtualSize,
            "raw": s.PointerToRawData,
            "rawsize": s.SizeOfRawData,
            "chars": s.Characteristics,
        })
    return out


def _rva_to_off(secs, rva):
    for s in secs:
        if s["va"] <= rva < s["va"] + max(s["vsize"], s["rawsize"]):
            return s["raw"] + (rva - s["va"])
    return None


def _pdata_starts(raw, pe, secs):
    try:
        dd = pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
        rva, size = dd.VirtualAddress, dd.Size
    except Exception:
        return []
    if not rva or not size:
        return []
    off = _rva_to_off(secs, rva)
    if off is None:
        return []
    out = []
    for i in range(size // 12):
        b = int.from_bytes(raw[off + i * 12:off + i * 12 + 4], "little")
        if b:
            out.append(b)
    return out


def _export_starts(pe):
    out = []
    try:
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.address:
                out.append(exp.address)
    except Exception:
        pass
    return out


# ------------------------------------------------- instruction boundaries
def _boundary_map(raw, pe, secs, entries):
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    starts = set()
    work = list(entries)
    seen = set()
    guard = 0
    while work and guard < 400000:
        guard += 1
        start = work.pop()
        if start in seen:
            continue
        seen.add(start)
        off = _rva_to_off(secs, start)
        if off is None:
            continue
        for insn in md.disasm(bytes(raw[off:off + 0x2000]), start):
            starts.add(insn.address)
            mn = insn.mnemonic
            if mn in ("ret", "int3", "ud2", "hlt"):
                break
            if mn.startswith("j"):
                if insn.operands and insn.operands[0].type == X86_OP_IMM:
                    work.append(insn.operands[0].imm)
                if mn == "jmp":
                    break
            elif mn == "call" and insn.operands and insn.operands[0].type == X86_OP_IMM:
                work.append(insn.operands[0].imm)
    return starts


# --------------------------------------------------------------- scanning
def _candidates(raw, secs):
    out = []
    for s in secs:
        if not (s["chars"] & IMAGE_SCN_MEM_EXECUTE) or not s["rawsize"]:
            continue
        blob = raw[s["raw"]:s["raw"] + s["rawsize"]]
        i = 0
        while True:
            j = blob.find(b"\x0f\x0d", i)
            if j < 0:
                break
            i = j + 1
            if j + 2 >= len(blob):
                break
            modrm = blob[j + 2]
            # /1 == PREFETCHW, and it must be a memory operand (mod != 11b)
            if ((modrm >> 3) & 7) != 1 or (modrm >> 6) == 3:
                continue
            out.append(s["va"] + j)
    return out


def _verify(raw, pe, secs, candidates):
    """Return the subset of candidates that are genuine instruction starts."""
    entries = set()
    try:
        entries.add(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
    except Exception:
        pass
    entries.update(_export_starts(pe))
    entries.update(_pdata_starts(raw, pe, secs))
    if not entries:
        return []
    starts = _boundary_map(raw, pe, secs, entries)
    if not starts:
        return []
    return [rva for rva in candidates if rva in starts]


def neutralize_prefetchw(data: bytearray, verify: bool = False) -> list:
    """Rewrite PREFETCHW in the image.  Returns the patched RVAs.

    verify=True  requires capstone and checks every candidate against an
                 instruction-boundary map (recommended for ntoskrnl on builds
                 where a plain scan is known to over-match, e.g. 14393).
    verify=False keeps the original heuristic: skip candidates that sit inside
                 a CALL/JMP rel32 displacement.
    """
    pe = pefile.PE(data=bytes(data), fast_load=True)
    try:
        secs = _sections(pe)
        raw = bytes(data)
        cands = _candidates(raw, secs)

        if verify and HAVE_CAPSTONE:
            verified = _verify(raw, pe, secs, cands)
            if verified:
                if len(verified) != len(cands):
                    print(
                        "[*] prefetchw: %d candidate(s), %d verified as"
                        " instructions (%d skipped as data/mid-instruction)."
                        % (len(cands), len(verified), len(cands) - len(verified))
                    )
            else:
                print("[-] prefetchw verification found nothing; falling back"
                      " to the byte heuristic.")
                verified = None
        elif verify and not HAVE_CAPSTONE:
            print("[!] capstone is not installed - cannot verify prefetchw"
                  " candidates.  pip install capstone")
            verified = None
        else:
            verified = None

        if verified is None:
            verified = []
            for rva in cands:
                inside = False
                for back in range(1, 5):
                    off = _rva_to_off(secs, rva - back)
                    if off is not None and data[off] in (0xE8, 0xE9):
                        inside = True
                        break
                if not inside:
                    verified.append(rva)

        patched = []
        for rva in verified:
            off = _rva_to_off(secs, rva)
            modrm = data[off + 2]
            data[off + 1] = 0x1F
            data[off + 2] = modrm & 0xC7
            patched.append(rva)
        return patched
    finally:
        pe.close()
