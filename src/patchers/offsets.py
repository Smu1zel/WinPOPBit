"""Derive the patch offsets from symbols instead of hand-written RVAs.

Everything the kernel patcher needs is discoverable from the image itself plus
its public PDB:

  * `KiInvalidOpcodeFault`      - the #UD handler that gets hooked
  * `KiSetFeatureBits`          - the function with the "unsupported CPU" exits
  * the branches to those exits - found by locating every `mov ecx, 0x5D`
                                  block and keeping only the branches whose
                                  linear decode actually reaches such a block

The last part matters: a naive "branches that point near the 0x5D block" scan
also picks up branches into normal code that happens to sit next to the cold
block (that mistake cost a debugging session on 1607).

    offs = discover(exe_path)      # {'handler': rva, 'gates': [rva, ...]}
"""

import struct

from . import symbols

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    from capstone.x86 import X86_OP_IMM
    HAVE_CAPSTONE = True
except ImportError:                                  # pragma: no cover
    HAVE_CAPSTONE = False

IMAGE_SCN_MEM_EXECUTE = 0x20000000
BUGCHECK_5D = b"\xb9\x5d\x00\x00\x00"                # mov ecx, 0x5D


def _sections(pe):
    out = []
    for s in pe.sections:
        out.append({"name": s.Name.rstrip(b"\0").decode("latin1"),
                    "va": s.VirtualAddress,
                    "vsize": s.Misc_VirtualSize,
                    "raw": s.PointerToRawData,
                    "rawsize": s.SizeOfRawData,
                    "chars": s.Characteristics})
    return out


def _rva2off(secs, rva):
    for s in secs:
        if s["va"] <= rva < s["va"] + max(s["vsize"], s["rawsize"]):
            return s["raw"] + (rva - s["va"])
    return None


def find_5d_blocks(pe, secs):
    """Every `mov ecx,0x5D` in an executable section."""
    out = []
    for s in secs:
        if not (s["chars"] & IMAGE_SCN_MEM_EXECUTE) or not s["rawsize"]:
            continue
        blob = bytes(pe.data[s["raw"]:s["raw"] + s["rawsize"]])
        i = 0
        while True:
            j = blob.find(BUGCHECK_5D, i)
            if j < 0:
                break
            out.append(s["va"] + j)
            i = j + 1
    return out


def _linear_reaches(pe, secs, start, goal, limit=0x400):
    """True when linear decoding from `start` lands exactly on `goal`."""
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    off = _rva2off(secs, start)
    if off is None:
        return False
    addr = start
    for insn in md.disasm(bytes(pe.data[off:off + limit]), start):
        if insn.address == goal:
            return True
        addr = insn.address + insn.size
        if insn.mnemonic in ("ret", "int3", "ud2", "hlt"):
            return addr == goal
    return addr == goal


def find_bugcheck_branches(pe, secs, func_start, func_end):
    """Branches inside [func_start, func_end) that lead into a 0x5D block."""
    blocks = find_5d_blocks(pe, secs)
    if not blocks or not HAVE_CAPSTONE:
        return []
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    off = _rva2off(secs, func_start)
    if off is None:
        return []
    gates = []
    prev = None
    for insn in md.disasm(bytes(pe.data[off:off + (func_end - func_start)]), func_start):
        # A branch that tests the *return value* of a call must not be skipped:
        # the callee is reporting a failure, and continuing with that failure
        # state crashes later (IRQL_NOT_LESS_OR_EQUAL observed on 1511/1607).
        if prev is not None and prev.mnemonic == "call" and insn.mnemonic.startswith("j"):
            prev = insn
            continue
        if not insn.mnemonic.startswith("j") or not insn.operands:
            prev = insn
            continue
        if insn.operands[0].type != X86_OP_IMM:
            continue
        target = insn.operands[0].imm
        for blk in blocks:
            window_lo, window_hi = blk - 0x80, blk + 0x10
            if not (window_lo <= target <= window_hi):
                continue
            if target == blk or _linear_reaches(pe, secs, target, blk):
                gates.append(insn.address)
                break
        prev = insn
    return gates


def discover(exe_path, syms=None, verbose=True):
    """Return {'handler': rva|None, 'gates': [...], 'func': rva|None}."""
    import pefile

    with open(exe_path, "rb") as f:
        data = bytearray(f.read())
    pe = pefile.PE(data=bytes(data), fast_load=True)
    try:
        secs = _sections(pe)
        pe.data = data

        if syms is None:
            syms = symbols.resolve(exe_path, verbose=verbose)

        out = {"handler": syms.get("KiInvalidOpcodeFault"),
               "func": syms.get("KiSetFeatureBits"),
               "gates": []}
        if out["func"] is None:
            if verbose:
                print("[-] KiSetFeatureBits not in symbols")
            return out

        # the next symbol is often a label *inside* the same function, so use
        # the .pdata function range instead
        end = None
        try:
            dd = pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
            off = _rva2off(secs, dd.VirtualAddress)
            for i in range(dd.Size // 12):
                b, e = struct.unpack_from("<II", data, off + i * 12)
                if b <= out["func"] < e:
                    end = e
                    break
        except Exception:
            pass
        if end is None:
            later = sorted(v for v in syms.values() if v > out["func"])
            end = later[0] if later else out["func"] + 0x2000
        out["gates"] = find_bugcheck_branches(pe, secs, out["func"], end)
        if verbose:
            print("[*] symbols: handler=0x%X KiSetFeatureBits=0x%X..0x%X gates=%d"
                  % (out["handler"] or 0, out["func"], end, len(out["gates"])))
        return out
    finally:
        pe.close()
