"""CPU-feature patches for builds that must run on pre-2006 processors.

A Pentium 4 (Prescott) and a first-generation Socket 754 Athlon 64 share the
same gaps: no CET, no XSAVE, no RDRAND, no CMPXCHG16B, no PREFETCHW.

`cmpatch.py` covers the last two.  This module covers the rest, and every
location is derived from symbols or from the instruction encoding, never from a
hand-written RVA:

===============  =====================================================
KiInitializeXSave                -> xor eax,eax; ret   (no XSAVE state)
KiInitializeKernelShadowStacks   -> xor eax,eax; ret   (no shadow stacks)
KiIsKvaShadowDisabled            -> mov al,1; ret      (no KVA shadow)
`mov ecx,0x6A2; wrmsr`           -> NOP                (IA32_S_CET)
CET instructions                 -> NOP                (setssbsy, rdsspq, ...)
RDRAND gate (`jae` over the read)-> jmp                (use the fallback)
===============  =====================================================

The CET instructions are searched by encoding and only accepted when they sit
on a real instruction boundary (capstone + .pdata), because the same bytes can
appear inside data.
"""

import struct

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    HAVE_CAPSTONE = True
except ImportError:                                  # pragma: no cover
    HAVE_CAPSTONE = False

IMAGE_SCN_MEM_EXECUTE = 0x20000000


def _ret_zero():
    return bytes.fromhex("33c0c3")                   # xor eax,eax ; ret


def _ret_one():
    return bytes.fromhex("b001c3")                   # mov al,1 ; ret


def _sections(pe):
    return [{"name": s.Name.rstrip(b"\0").decode("latin1"),
             "va": s.VirtualAddress, "vsize": s.Misc_VirtualSize,
             "raw": s.PointerToRawData, "rawsize": s.SizeOfRawData,
             "chars": s.Characteristics} for s in pe.sections]


def _rva2off(secs, rva):
    for s in secs:
        if s["va"] <= rva < s["va"] + max(s["vsize"], s["rawsize"]):
            return s["raw"] + (rva - s["va"])
    return None


def _patch_symbol(data, secs, syms, name, payload, verbose=True, pad=True):
    rva = syms.get(name)
    if rva is None:
        return False
    off = _rva2off(secs, rva)
    if off is None:
        return False
    data[off:off + len(payload)] = payload
    if pad:
        for k in range(len(payload), 5):
            data[off + k] = 0x90
    if verbose:
        print("    [+] %s -> %s" % (name, payload.hex(" ")))
    return True


def _patch_cet_wrmsr(data, secs, verbose=True):
    """NOP `mov ecx, 0x6A2` + `wrmsr` (IA32_S_CET) wherever it appears."""
    pat = bytes.fromhex("b9a2060000")
    n = 0
    sites = []
    for s in secs:
        if not (s["chars"] & IMAGE_SCN_MEM_EXECUTE) or not s["rawsize"]:
            continue
        blob = data[s["raw"]:s["raw"] + s["rawsize"]]
        i = 0
        while True:
            j = blob.find(pat, i)
            if j < 0:
                break
            i = j + 1
            if blob[j + 5:j + 7] != b"\x0f\x30":      # mov ecx,imm ; wrmsr
                continue
            for k in range(7):
                data[s["raw"] + j + k] = 0x90
            sites.append(s["va"] + j)
            n += 1
    if n and verbose:
        print("    [+] nop'ed %d IA32_S_CET write(s)" % n)
    return n, sites


CET_OPCODES = (
    bytes.fromhex("f30f01e8"),       # setssbsy
    bytes.fromhex("f30f01ea"),       # saveprevssp
    bytes.fromhex("f30f0128"),       # rstorssp
    bytes.fromhex("f30f0129"),       # rstorssp (variant encoding)
    bytes.fromhex("f3410f0128"),     # rstorssp (r8)
    bytes.fromhex("f3410f0129"),     # rstorssp (r8, variant)
    bytes.fromhex("f3480f1eca"),     # rdsspq rdx
    bytes.fromhex("f3480f1ec8"),     # rdsspq rax
    bytes.fromhex("f3480f1ec9"),     # rdsspq rcx
    bytes.fromhex("f3480faee8"),     # incsspq rax
    bytes.fromhex("f30faee8"),       # incsspq eax
    bytes.fromhex("0f01cb"),         # stac
    bytes.fromhex("0f01ca"),         # clac
)


def _patch_cet_instructions(data, secs, verbose=True):
    """NOP CET instructions found on real instruction boundaries."""
    n = 0
    for s in secs:
        if not (s["chars"] & IMAGE_SCN_MEM_EXECUTE) or not s["rawsize"]:
            continue
        blob = bytes(data[s["raw"]:s["raw"] + s["rawsize"]])
        for op in CET_OPCODES:
            i = 0
            while True:
                j = blob.find(op, i)
                if j < 0:
                    break
                i = j + 1
                rva = s["va"] + j
                if not _is_instruction_start(data, secs, rva):
                    continue
                for k in range(len(op)):
                    data[s["raw"] + j + k] = 0x90
                n += 1
    if n and verbose:
        print("    [+] nop'ed %d CET instruction(s)" % n)
    return n


def _pdata_ranges(data, pe, secs):
    out = []
    try:
        dd = pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
    except Exception:
        return out
    off = _rva2off(secs, dd.VirtualAddress)
    if off is None or not dd.Size:
        return out
    for i in range(dd.Size // 12):
        b, e = struct.unpack_from("<II", data, off + i * 12)
        if b and e > b:
            out.append((b, e))
    return out


def _instruction_starts(data, secs, begin, end):
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    o = _rva2off(secs, begin)
    if o is None:
        return set()
    return {i.address for i in md.disasm(bytes(data[o:o + (end - begin)]), begin)}


def _patch_cet_instructions(data, secs, pe=None, syms=None, verbose=True, extra_anchors=None):
    """NOP CET instructions inside the #UD handler only.

    The handler is the one place that must not use CET instructions: it runs on
    a CPU that has none.  A global scan matches hundreds of false positives in
    ordinary code, so the search is limited to KiInvalidOpcodeFault.
    """
    if not HAVE_CAPSTONE or pe is None or not syms:
        return 0
    anchors = [syms.get("KiInvalidOpcodeFault")] + list(extra_anchors or [])
    all_ranges = _pdata_ranges(data, pe, secs)
    ranges = []
    for a in anchors:
        if a is None:
            continue
        hit = [r for r in all_ranges if r[0] <= a < r[1]]
        ranges.extend(hit if hit else [(a, a + 0x400)])
    cache = {}
    n = 0
    for s in secs:
        if not (s["chars"] & IMAGE_SCN_MEM_EXECUTE) or not s["rawsize"]:
            continue
        blob = bytes(data[s["raw"]:s["raw"] + s["rawsize"]])
        for op in CET_OPCODES:
            i = 0
            while True:
                j = blob.find(op, i)
                if j < 0:
                    break
                i = j + 1
                rva = s["va"] + j
                owner = next((r for r in ranges if r[0] <= rva < r[1]), None)
                if owner is None:
                    continue
                if owner not in cache:
                    cache[owner] = _instruction_starts(data, secs, *owner)
                if rva not in cache[owner]:
                    continue
                for k in range(len(op)):
                    data[s["raw"] + j + k] = 0x90
                n += 1
    if n and verbose:
        print("    [+] nop'ed %d CET instruction(s)" % n)
    return n


def _patch_rdrand(data, secs, verbose=True):
    """Turn the `jae` that guards a RDRAND read into an unconditional jump.

    Windows probes RDRAND with CPUID and then executes it guarded by a branch.
    On a CPU without the instruction the guard is what matters: it must not be
    taken, so the probe falls back to the software generator.
    """
    pat = bytes.fromhex("33c9bf010000000fc7f2")       # xor ecx,ecx ; mov edi,1 ; rdrand edx
    n = 0
    for s in secs:
        if not (s["chars"] & IMAGE_SCN_MEM_EXECUTE) or not s["rawsize"]:
            continue
        blob = bytes(data[s["raw"]:s["raw"] + s["rawsize"]])
        i = 0
        while True:
            j = blob.find(pat, i)
            if j < 0:
                break
            i = j + 1
            if j >= 2 and blob[j - 2] == 0x73 and blob[j - 1] < 0x80:   # jae rel8
                data[s["raw"] + j - 2] = 0xEB
                n += 1
    if n and verbose:
        print("    [+] patched %d RDRAND gate(s) (jae -> jmp)" % n)
    return n


def patch_cpu_features(data, pe, secs, syms, verbose=True):
    """Apply the non-CX16 CPU-feature patches.  Returns a report dict."""
    report = {"xsave": False, "shadow_stacks": False, "kva_shadow": False,
              "cet_wrmsr": 0, "cet_insns": 0, "rdrand": 0}
    report["xsave"] = _patch_symbol(data, secs, syms, "KiInitializeXSave",
                                    _ret_zero(), verbose)
    report["shadow_stacks"] = _patch_symbol(
        data, secs, syms, "KiInitializeKernelShadowStacks", _ret_zero(), verbose,
        pad=False)
    report["kva_shadow"] = _patch_symbol(
        data, secs, syms, "KiIsKvaShadowDisabled", _ret_one(), verbose)
    if report["kva_shadow"]:
        off = _rva2off(secs, syms["KiIsKvaShadowDisabled"])
        for k in range(3, 11):                      # match the verified layout
            data[off + k] = 0x90
    report["cet_wrmsr"], cet_sites = _patch_cet_wrmsr(data, secs, verbose)
    report["cet_insns"] = _patch_cet_instructions(
        data, secs, pe, syms, verbose, extra_anchors=cet_sites)
    report["rdrand"] = _patch_rdrand(data, secs, verbose)
    return report
