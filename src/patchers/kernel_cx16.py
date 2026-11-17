import os
import struct

import pefile

from . import cpu_features as _cpu
from . import offsets as _offsets
from . import register_patcher
from .pe import fix_pe_checksum
from .prefetch import neutralize_prefetchw

# Thunk offsets inside each shim blob (see src/asm/*.s).  Two variants exist:
#   shim_nest.bin   full set of addressing forms, nesting-aware lock
#   shim_1909.bin   compact set, needed when the code cave is small
THUNK_TABLES = {
    "shim.bin": {"rdi": 0x99, "rsi": 0xA3, "r8": 0xAD, "r10": 0xB7, "r11": 0xC1, "r14": 0xCB, "r15": 0xD5, "rdi20": 0xDF, "r8d10": 0xEA, "r8d20": 0xF5, "r8d100": 0x100, "r8d150": 0x10E},
    "shim_nest.bin": {"rdi": 0x11C, "rsi": 0x126, "r8": 0x130, "r10": 0x13A, "r11": 0x144, "r14": 0x14E, "r15": 0x158, "rdi20": 0x162, "r9d20": 0x16D, "r8d10": 0x178, "r8d20": 0x183, "r8d100": 0x18E, "r8d150": 0x19C},
    "shim_skip_lock15.bin": {"rdi": 0xAD, "rsi": 0xB7, "r8": 0xC1, "r10": 0xCB, "r11": 0xD5, "r14": 0xDF, "r15": 0xE9, "rdi20": 0xF3, "r9d20": 0xFE, "r8d10": 0x109, "r8d20": 0x114, "r8d100": 0x11F, "r8d150": 0x12D, "r8d160": 0x13B, "r14d20": 0x149},
}

SITE_LEN = {"r8": 5, "rdi": 5, "rsi": 5, "r10": 5, "r11": 5, "r14": 5,
            "r15": 5, "rdi20": 6, "r8d10": 6, "r8d20": 6, "r9d20": 6,
            "r8d100": 9, "r8d150": 9, "r8d160": 9, "r14d20": 6}

REGS = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]

IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_WRITE = 0x80000000

# sections the kernel reuses or discards - never place code there
# KVASCODE looks like zeros in the file but is filled with the KVA shadow
# syscall code at boot, so a "cave" there is overwritten at runtime and the
# shadow entry can fall straight into our stub.
BAD_SECTIONS = {"POOLCODE", "INIT", "INITKDBG", "INITDATA", "PAGEVRFB",
                "KVASCODE", "PAGEVRFY", "PAGEBGFX"}

# Sections whose runtime properties have actually been verified on real
# hardware.  MINIEX/RETPOL/PAGEVRFY and friends are executable in the image but
# nobody knows whether they are resident when we jump into them; placing the
# trampoline there caused IRQL_NOT_LESS_OR_EQUAL on 22621.2428.
SAFE_SECTIONS = {".text", "PAGELK", "KVASCODE", "PAGEKD"}

HERE = os.path.dirname(os.path.abspath(__file__))
ASM_DIR = os.path.join(HERE, os.pardir, "asm")          # src/asm
BLOB_DIR = os.path.join(HERE, os.pardir, os.pardir, "blobs")


# ---------------------------------------------------------------- helpers
# site operand -> form name used by the thunk tables
FORMS = {
    ("rdi", 0): "rdi", ("rdi", 0x20): "rdi20", ("rsi", 0): "rsi",
    ("r8", 0): "r8", ("r8", 0x10): "r8d10", ("r8", 0x20): "r8d20",
    ("r8", 0x100): "r8d100", ("r8", 0x150): "r8d150", ("r8", 0x160): "r8d160",
    ("r14", 0x20): "r14d20",
    ("r9", 0x20): "r9d20", ("r10", 0): "r10",
    ("r11", 0): "r11", ("r14", 0): "r14",
    ("r15", 0): "r15",
}


def _sections(pe):
    out = []
    for s in pe.sections:
        out.append({"name": s.Name.rstrip(b"\0").decode("latin1"),
                    "va": s.VirtualAddress, "vsize": s.Misc_VirtualSize,
                    "raw": s.PointerToRawData, "rawsize": s.SizeOfRawData,
                    "chars": s.Characteristics})
    return out


def _rva2off(secs, rva):
    for s in secs:
        if s["va"] <= rva < s["va"] + max(s["vsize"], s["rawsize"]):
            return s["raw"] + (rva - s["va"])
    return None


def _extend_section(data, secs, rva, length, verbose=True):
    """Grow the containing section so `rva..rva+length` is actually mapped."""
    for idx, s in enumerate(secs):
        limit = secs[idx + 1]["va"] if idx + 1 < len(secs) else s["va"] + s["vsize"]
        if not (s["va"] <= rva < limit):
            continue
        need = (rva - s["va"]) + length
        if need <= s["vsize"]:
            return True
        if need > limit - s["va"]:
            raise ValueError("RVA 0x%X would run into the next section" % rva)
        if s["chars"] & IMAGE_SCN_MEM_EXECUTE and need > s["rawsize"]:
            raise ValueError("section %s has no room (raw 0x%X)"
                             % (s["name"], s["rawsize"]))
        struct.pack_into("<I", data, s["hdr"] + 8, need)
        s["vsize"] = need
        if verbose:
            print("    [+] %s VirtualSize -> 0x%X" % (s["name"], need))
        return True
    return False



def _add_code_section(data, secs, payload, name=b".p4c", verbose=True):
    """Append a new executable section holding `payload`; return its RVA.

    Finding a padding cave constrains us to whatever the build happens to
    have (and to sections whose runtime properties are unverified), which is
    why the user-mode trampoline could not be made big enough.  A dedicated
    section removes both limits: it is mapped by the loader like any other,
    it is not pageable, and its contents are under our control.
    """
    e0 = struct.unpack_from("<I", data, 0x3C)[0]
    nsec = struct.unpack_from("<H", data, e0 + 6)[0]
    optsz = struct.unpack_from("<H", data, e0 + 20)[0]
    table = e0 + 24 + optsz
    file_align = struct.unpack_from("<I", data, e0 + 24 + 36)[0]
    sect_align = struct.unpack_from("<I", data, e0 + 24 + 32)[0]

    last = secs[-1]
    new_va = (last["va"] + max(last["vsize"], last["rawsize"]) + sect_align - 1) \
        & ~(sect_align - 1)
    raw_off = (len(data) + file_align - 1) & ~(file_align - 1)
    raw_size = (len(payload) + file_align - 1) & ~(file_align - 1)
    data.extend(b"\x00" * (raw_off + raw_size - len(data)))
    data[raw_off:raw_off + len(payload)] = payload

    hdr = table + nsec * 40
    struct.pack_into("<8sIIIIIIHHI", data, hdr, name.ljust(8, b"\x00"),
                     len(payload), new_va, raw_size, raw_off, 0, 0, 0, 0,
                     0x60000020)
    struct.pack_into("<H", data, e0 + 6, nsec + 1)
    size_of_image = new_va + ((len(payload) + sect_align - 1) // sect_align) * sect_align
    struct.pack_into("<I", data, e0 + 24 + 56, size_of_image)
    secs.append({"name": name.decode(), "va": new_va, "vsize": len(payload),
                 "raw": raw_off, "rawsize": raw_size, "chars": 0x60000020,
                 "hdr": hdr})
    if verbose:
        print("    [+] new section %s at 0x%X (%d bytes)"
              % (name.decode(), new_va, len(payload)))
    return new_va


def _place(data, secs, blob, rva, lock_rva=None, verbose=True):
    if lock_rva is not None:
        ph = bytes.fromhex("44332211")
        i = blob.find(ph)
        while i >= 0:
            struct.pack_into("<i", blob, i, lock_rva - (rva + i + 4))
            i = blob.find(ph, i + 4)
    off = _rva2off(secs, rva)
    if off is None:
        raise ValueError("RVA 0x%X is not mapped" % rva)
    occupied = [k for k, b in enumerate(data[off:off + len(blob)])
                if b not in (0x00, 0xCC) and blob[k] != b]
    if occupied:
        raise ValueError("RVA 0x%X is not a cave (byte %02X at 0x%X)"
                         % (rva, data[off + occupied[0]], rva + occupied[0]))
    _extend_section(data, secs, rva, len(blob), verbose)
    data[off:off + len(blob)] = blob
    if verbose:
        print("    [+] blob at 0x%X (%d bytes)" % (rva, len(blob)))


def _derive_thunk_table(blob):
    """Rebuild {form: offset} from the shim itself.

    The static THUNK_TABLES go stale whenever a blob is rebuilt: the offsets
    drift and every redirected site starts calling into the middle of the
    worker's release path.  Deriving the table from the bytes we are about to
    embed cannot go stale, and also fixes `KeyError: 'r8d20'` for blobs whose
    static entry never listed that form.
    """
    try:
        from capstone import Cs, CS_ARCH_X86, CS_MODE_64
        import capstone.x86 as cx
    except Exception:
        return None
    regs = {getattr(cx, n): n[8:].lower() for n in dir(cx)
            if n.startswith("X86_REG_")}
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    ins = list(md.disasm(bytes(blob), 0))
    table = {}
    for a, b in zip(ins, ins[1:]):
        if not (a.mnemonic == "push" and a.op_str == "r9"):
            continue
        if not (b.mnemonic == "lea" and b.op_str.startswith("r9,")):
            continue
        m = b.operands[1].mem
        form = FORMS.get((regs.get(m.base, "?"), m.disp))
        if form:
            table[form] = a.address
    return table or None


def _pick_caves(pe, secs, sizes, verbose=True):
    """Pick one non-overlapping cave per requested size (largest first)."""
    runs = []
    for s in secs:
        if not (s["chars"] & IMAGE_SCN_MEM_EXECUTE) or not s["rawsize"]:
            continue
        if s["name"] in BAD_SECTIONS:
            continue                     # executable pool / discarded init code
        blob = bytes(pe.data[s["raw"]:s["raw"] + s["rawsize"]])
        i = 0
        while i < len(blob):
            if blob[i] in (0x00, 0xCC):
                j = i
                while j < len(blob) and blob[j] == blob[i]:
                    j += 1
                if j - i >= min(sizes):
                    va = s["va"] + i
                    aligned = va + ((-va) % 16)
                    runs.append({"rva": aligned, "end": s["va"] + j,
                                 "len": (s["va"] + j) - aligned,
                                 "name": s["name"],
                                 "pageable": s["name"].startswith("PAGE")})
                i = j
            else:
                i += 1
    # prefer sections we have booted from before anything else
    runs.sort(key=lambda c: (c["name"] not in SAFE_SECTIONS, c["pageable"], -c["len"]))
    if runs and runs[0]["name"] not in SAFE_SECTIONS and verbose:
        print("    [!] no cave in a verified section; falling back to %s"
              % runs[0]["name"])
    picked = []
    for need in sorted(sizes, reverse=True):
        for c in runs:
            if c["len"] < need or c["rva"] + need > c.get("end", c["rva"] + c["len"]):
                continue
            if any(c["rva"] < p["rva"] + p["need"] and p["rva"] < c["rva"] + need
                   for p in picked):
                continue
            picked.append({"rva": c["rva"], "need": need, "name": c["name"],
                           "len": c["len"], "pageable": c["pageable"]})
            break
    picked.sort(key=lambda p: -p["need"])
    if verbose:
        for c in picked:
            print("    [+] cave %s 0x%X (len 0x%X, need 0x%X%s)"
                  % (c["name"], c["rva"], c["len"], c["need"],
                     ", pageable" if c["pageable"] else ""))
    return picked


def _find_lock(pe, secs, verbose=True):
    best = None
    for s in secs:
        if not (s["chars"] & IMAGE_SCN_MEM_WRITE) or s["name"] in BAD_SECTIONS:
            continue
        # the lock word must never live in a pageable section: it would be
        # paged out while held and the next acquisition would hang.
        if s["name"].startswith("PAGE"):
            continue
        end = s["va"] + s["vsize"]
        page_end = (end + 0xFFF) & ~0xFFF
        slot = (end + 15) & ~0xF
        if page_end - slot < 32:
            continue
        if best is None or s["vsize"] > best[1]:
            best = (slot, s["vsize"], s["name"])
    if best and verbose:
        print("    [+] lock slot 0x%X in %s" % (best[0], best[2]))
    return best[0] if best else None


def _scan_sites(pe, secs):
    sites = []
    for s in secs:
        if not (s["chars"] & IMAGE_SCN_MEM_EXECUTE) or not s["rawsize"]:
            continue
        blob = bytes(pe.data[s["raw"]:s["raw"] + s["rawsize"]])
        i = 0
        while i < len(blob) - 10:
            j = blob.find(b"\xf0", i)
            if j < 0:
                break
            i = j + 1
            if blob[j + 1] not in (0x48, 0x49, 0x4C, 0x4D):
                continue
            if blob[j + 2] != 0x0F or blob[j + 3] != 0xC7:
                continue
            modrm = blob[j + 4]
            mod, reg, rm = modrm >> 6, (modrm >> 3) & 7, modrm & 7
            if reg != 1:
                continue
            base = REGS[rm | ((blob[j + 1] & 1) << 3)]
            ln, disp = 5, 0
            if mod == 0 and rm == 5:
                continue
            if mod == 1:
                disp = blob[j + 5] if blob[j + 5] < 0x80 else blob[j + 5] - 0x100
                ln = 6
            elif mod == 2:
                disp = int.from_bytes(blob[j + 5:j + 9], "little", signed=True)
                ln = 9
            elif mod == 0 and rm == 4:
                continue
            form = {("rdi", 0): "rdi", ("rdi", 0x20): "rdi20", ("rsi", 0): "rsi",
                    ("r8", 0): "r8", ("r8", 0x10): "r8d10", ("r8", 0x20): "r8d20",
                    ("r8", 0x100): "r8d100", ("r8", 0x150): "r8d150", ("r8", 0x160): "r8d160",
                    ("r14", 0x20): "r14d20",
                    ("r9", 0x20): "r9d20", ("r10", 0): "r10",
                    ("r11", 0): "r11", ("r14", 0): "r14",
                    ("r15", 0): "r15"}.get((base, disp))
            sites.append({"rva": s["va"] + j, "form": form, "len": ln})
    return sites


# ------------------------------------------------------------------ patch
# Per-build layout recovered from known-good images.  When the caller does not
# pin anything, these are used so that `build_all.py <version>` reproduces the
# verified kernel instead of guessing caves.
BUILD_PRESETS = {
    # 18362: the verified image keeps KiEnableKvaShadowing intact and does not
    # NOP the KiSetProcessorSignature branches; its shim lives at 0x350870,
    # the LAHF stub in RETPOL and the trampoline in KVASCODE.
    # 19041 has no room for the full blob set: shim in PAGELK (0x13F), the
    # trampoline in PAGE (0x105) and the LAHF stub in .text (0xC6).


}


def _build_number(exe_path):
    try:
        import pefile
        pe = pefile.PE(exe_path)
        ls = pe.VS_FIXEDFILEINFO[0].FileVersionLS
        return "%d" % (ls >> 16)          # 18362 etc.
    except Exception:
        return None


def patch_kernel_cx16_bytes(
    data: bytearray,
    exe_path: str = "",
    patch_prefetchw_flag: bool = True,
    verify_prefetchw: bool = False,
    emulate_cx16: bool = True,
    use_symbol_gates: bool = True,
    patch_cpu_features: bool = True,
    xsave_stub: bool = True,
    signature_gates: bool = False,
    kva_enable_stub: bool = True,
    sddl_quirk: bool = False,
    hook_ud: bool = True,
    gates: str = "",
    sites: str = "",
    shim_blob: str = "",
    lock_rva: str = "",
    handler_rva: str = "",
    handler_back: str = "",
    tramp_blob: str = "",
    lahf_blob: str = "",
    verbose: bool = True,
) -> tuple:
    """Make ntoskrnl bootable on a CPU without CMPXCHG16B / LAHF.

    Every RVA is optional: when omitted it is derived from the image's public
    symbols (`KiInvalidOpcodeFault`, `KiSetFeatureBits`) and from scanning the
    image (code caves, lock slot, cmpxchg16b sites).
    """
    _preset_used = False
    report = {"cpuid_table_patched": False, "lax_table_patched": False,
              "prefetchw_sites": 0, "gates_patched": 0,
              "cx16_sites_patched": 0, "trampoline_installed": False,
              "lahf_stub_installed": False}

    # Apply the recovered per-build layout when the caller did not pin
    # anything, so an unmodified `build_all.py <build>` reproduces the
    # verified image instead of guessing.
    if exe_path and not shim_blob and not tramp_blob and not lahf_blob:
        _bn = _build_number(exe_path)
        _pre = BUILD_PRESETS.get(_bn or "")
        if _pre:
            # A preset stores addresses only; the same build number can have
            # different layouts (19041.508 vs 19041.6093), so verify the three
            # slots really are caves here before trusting them.
            _okpre = True
            try:
                _pe0 = pefile.PE(data=bytes(data), fast_load=True)
                _pe0.data = data
                _secs0 = _sections(_pe0)
                for _k in ("shim_rva", "tramp_rva", "lahf_rva"):
                    _o = _rva2off(_secs0, _pre[_k])
                    if _o is None or any(b not in (0x00, 0xCC)
                                         for b in data[_o:_o + 0x60]):
                        _okpre = False
                        break
            except Exception:
                _okpre = False
            if not _okpre:
                print("    [!] preset %s does not fit this image "
                      "(build %s) - using auto cave discovery"
                      % (_pre["shim"], _bn))
                _pre = None
        if _pre:
            shim_blob = "%s@0x%X" % (_pre["shim"], _pre["shim_rva"])
            tramp_blob = "%s@0x%X" % (_pre["tramp"], _pre["tramp_rva"])
            lahf_blob = "%s@0x%X" % (_pre["lahf"], _pre["lahf_rva"])
            signature_gates = _pre.get("signature_gates", signature_gates)
            kva_enable_stub = _pre.get("kva_enable_stub", kva_enable_stub)
            _preset_used = True
            if verbose:
                print("    [*] build %s preset: %s" % (_bn, _pre["shim"]))

    pe = pefile.PE(data=bytes(data), fast_load=True)
    try:
        secs = _sections(pe)
        for s in secs:
            s["hdr"] = None
        # locate section headers for VirtualSize patching
        e0 = struct.unpack_from("<I", data, 0x3C)[0]
        nsec = struct.unpack_from("<H", data, e0 + 6)[0]
        optsz = struct.unpack_from("<H", data, e0 + 20)[0]
        table = e0 + 24 + optsz
        for i, s in enumerate(secs):
            s["hdr"] = table + i * 40
        pe.data = data

        # 0. optional 10586 quirk: the verified 1511 image has one byte of the
        # SDDL ControlLookup "P" entry cleared (RVA 0x255E95, 0x20 -> 0).  It is
        # NOT a CPU feature flag - clearing it changes SDDL parsing - so it is
        # opt-in and only useful for reproducing that exact image.
        if sddl_quirk:
            _sig = bytes.fromhex("01000000002000000200000000000000")
            _o = data.find(_sig)
            if _o >= 0 and data[_o + 5] == 0x20:
                data[_o + 5] = 0
                print("    [+] 10586 SDDL ControlLookup quirk applied")

        # 1. required CPU features (signature based)
        for key, lays in (("cpuid", (("01000000002000000200000001000000", 12),
                                     ("0100000000000000002000000200000001000000", 16))),
                          ("lax", (("01000080010000000200000001000000", 12),
                                   ("0100008000000000010000000200000001000000", 16)))):
            for sig, off in lays:
                # find the *first* live record of this layout anywhere
                start_rva = 0
                while True:
                    o = data.find(bytes.fromhex(sig), start_rva)
                    if o < 0:
                        break
                    # only accept records that look like a feature table entry:
                    # preceded by a pointer-sized value inside .rdata
                    if o >= 8:
                        data[o + off] = 0
                        report["cpuid_table_patched" if key == "cpuid"
                               else "lax_table_patched"] = True
                        if verbose:
                            print("    [+] cleared %s required flag at file off 0x%X"
                                  % (key, o + off))
                    break
                if report["cpuid_table_patched" if key == "cpuid" else "lax_table_patched"]:
                    break

        # 2. PREFETCHW
        if patch_prefetchw_flag:
            hits = neutralize_prefetchw(data, verify=verify_prefetchw)
            report["prefetchw_sites"] = len(hits)
            if hits:
                print("    [+] neutralised %d PREFETCHW site(s)" % len(hits))

        # 3. symbol-derived offsets
        derived = {}
        if use_symbol_gates and (not gates or not handler_rva) and exe_path:
            derived = _offsets.discover(exe_path, verbose=verbose)

        gate_list = [int(x, 16) for x in gates.replace(" ", "").split(",") if x]
        if not gate_list:
            gate_list = derived.get("gates", [])
        if not signature_gates and gate_list:
            # `func` is the start of KiSetFeatureBits: only the branches inside
            # it may be NOP'ed.  The rest come from KiSetProcessorSignature and
            # must stay (NOP'ing them gives 0x32).
            _fstart = derived.get("func")
            if _fstart is None:
                if "symbols" not in derived:
                    derived["symbols"] = _offsets.symbols.resolve(exe_path, verbose=False)
                _fstart = derived["symbols"].get("KiSetFeatureBits")
            if _fstart:
                # KiSetFeatureBits is a small function; anything further
                # away in the list belongs to KiSetProcessorSignature.
                _kept = [g for g in gate_list if abs(g - _fstart) <= 0x800]
                if len(_kept) != len(gate_list):
                    print("    [*] keeping %d KiSetProcessorSignature gate(s)"
                          % (len(gate_list) - len(_kept)))
                gate_list = _kept
        for g in gate_list:
            o = _rva2off(secs, g)
            if o is None:
                continue
            if data[o] != 0x0F or not (0x80 <= data[o + 1] <= 0x8F):
                continue
            data[o:o + 6] = b"\x90" * 6
            report["gates_patched"] += 1
        if report["gates_patched"]:
            print("    [+] nop'ed %d feature gate(s)" % report["gates_patched"])

        # 3b. non-CX16 CPU features (CET / XSAVE / RDRAND / KVA shadow)
        if exe_path and patch_cpu_features:
            if not derived:
                derived = {}
            if "symbols" not in derived:
                derived["symbols"] = _offsets.symbols.resolve(exe_path, verbose=False)
            # stay compatible with the upstream cpu_features signature, which
            # does not take the per-feature switches (older releases)
            import inspect as _inspect
            _kw = {}
            try:
                _params = _inspect.signature(_cpu.patch_cpu_features).parameters
                if "xsave" in _params:
                    _kw["xsave"] = xsave_stub
                if "kva_enable_stub" in _params:
                    _kw["kva_enable_stub"] = kva_enable_stub
            except Exception:
                pass
            report["cpu_features"] = _cpu.patch_cpu_features(
                data, pe, secs, derived["symbols"], verbose, **_kw)

        # 4. cmpxchg16b emulation
        if not emulate_cx16:
            print("    [*] cmpxchg16b emulation disabled (diagnostic build)")
            return data, report
        if not handler_rva:
            handler_rva = ("0x%X" % derived["handler"]) if derived.get("handler") else ""
        if not handler_rva:
            print("    [-] no #UD handler; skipping cmpxchg16b emulation")
            return data, report
        handler = int(handler_rva, 16)

        site_list = []
        if sites:
            for item in sites.replace(" ", "").split(","):
                if not item:
                    continue
                rva_s, form = item.split(":")
                site_list.append({"rva": int(rva_s, 16), "form": form,
                                  "len": SITE_LEN[form]})
        else:
            site_list = [s for s in _scan_sites(pe, secs) if s["form"]]
            print("    [+] scanned %d emulatable cmpxchg16b site(s)" % len(site_list))

        if not shim_blob:
            blobs = sorted(os.listdir(BLOB_DIR))
            for name in ("shim_nest.bin", "shim.bin"):
                if name in blobs:
                    shim_blob = name
                    break
        shim_name = os.path.basename(shim_blob.split("@")[0])
        if shim_name not in THUNK_TABLES:
            # Not fatal any more: the table is rebuilt from the blob itself,
            # so a blob recovered from a working image works without an entry.
            blob_path = shim_blob.split("@")[0]
            if not os.path.isabs(blob_path):
                blob_path = os.path.join(BLOB_DIR, blob_path)
            if not os.path.exists(blob_path):
                print("    [-] unknown shim blob '%s'" % shim_name)
                return data, report
            print("    [*] shim blob '%s' not in THUNK_TABLES - deriving it"
                  % shim_name)
        thunk = THUNK_TABLES.get(shim_name, {})

        # a blob spec may pin its placement: "blobs/shim.bin@0xAAAE81".
        # Explicit addresses win; anything left unset is auto-discovered.
        def _split(spec, default):
            if "@" in spec:
                path, rva = spec.split("@", 1)
                if not os.path.isabs(path):
                    path = os.path.join(BLOB_DIR, path)
                return path, int(rva, 16)
            return (os.path.join(BLOB_DIR, spec) if not os.path.isabs(spec) else spec), None

        shim_path, shim_pin = _split(shim_blob, None)
        tramp_path, tramp_pin = _split(tramp_blob or os.path.join(BLOB_DIR, "tramp.bin"), None)
        lahf_path, lahf_pin = _split(lahf_blob or os.path.join(BLOB_DIR, "lahf.bin"), None)

        def _wants_for(sp):
            w = []
            if shim_pin is None:
                w.append(("shim", len(open(sp, "rb").read())))
            if tramp_pin is None:
                w.append(("tramp", len(open(tramp_path, "rb").read())))
            if lahf_pin is None:
                w.append(("lahf", len(open(lahf_path, "rb").read())))
            return w

        wants = _wants_for(shim_path)
        auto = {}
        if wants:
            picked = _pick_caves(pe, secs, [w[1] for w in wants], verbose)
            # 18362 has no cave large enough for the default shim: fall back to
            # a smaller blob instead of giving up on the whole build.
            if len(picked) < len(wants) and shim_pin is None and _preset_used:
                for alt in ("shim.bin",):
                    cand = os.path.join(BLOB_DIR, alt)
                    if not os.path.exists(cand):
                        continue
                    if len(open(cand, "rb").read()) >= len(open(shim_path, "rb").read()):
                        continue
                    w2 = _wants_for(cand)
                    p2 = _pick_caves(pe, secs, [w[1] for w in w2], False)
                    if len(p2) == len(w2):
                        print("    [!] shim does not fit any cave here -> using %s"
                              % alt)
                        shim_path, shim_name = cand, alt
                        wants, picked = w2, p2
                        if verbose:
                            for c in picked:
                                print("    [+] cave %s 0x%X (len 0x%X, need 0x%X)"
                                      % (c["name"], c["rva"], c["len"], c["need"]))
                        break
            if len(picked) < len(wants):
                print("    [-] not enough code caves")
                return data, report
            for (name, _), c in zip(wants, sorted(picked, key=lambda c: -c["need"])):
                auto[name] = c["rva"]
        shim_rva = shim_pin if shim_pin is not None else auto["shim"]
        tramp_rva = tramp_pin if tramp_pin is not None else auto["tramp"]
        lahf_rva = lahf_pin if lahf_pin is not None else auto["lahf"]
        lock = int(lock_rva, 16) if lock_rva else _find_lock(pe, secs, verbose)
        if lock is None:
            print("    [-] no writable slot for the shim lock")
            return data, report

        shim = bytearray(open(shim_path, "rb").read())
        derived = _derive_thunk_table(shim)
        if derived:
            merged = dict(thunk)
            merged.update(derived)
            if merged != thunk and verbose:
                diff = {k: (thunk.get(k), v) for k, v in derived.items()
                        if thunk.get(k) != v}
                if diff:
                    print("    [!] thunk table rebuilt from the blob: %s"
                          % ", ".join("%s %s->0x%X" % (k, a, b)
                                      for k, (a, b) in sorted(diff.items())))
            thunk = merged
        _place(data, secs, shim, shim_rva, lock_rva=lock, verbose=verbose)

        lahf = bytearray(open(lahf_path, "rb").read())
        _place(data, secs, lahf, lahf_rva, verbose=verbose)
        report["lahf_stub_installed"] = True

        tramp = bytearray(open(tramp_path, "rb").read())
        while tramp and tramp[-1] in (0x90, 0xCC):
            tramp.pop()
        back = int(handler_back, 16) if handler_back else handler + 5
        for tag, target, what in ((b"\xe8\x22\x22\x22\x22", shim_rva, "worker"),
                                  (b"\xe8\x33\x33\x33\x33", shim_rva + thunk["r11"], "r11"),
                                  (b"\xe8\x44\x44\x44\x44", shim_rva + thunk["r10"], "r10"),
                                  (b"\xe9\x55\x66\x77\x88", back, "back"),
                                  (b"\xe9\x99\x99\x99\x99", lahf_rva, "lahf")):
            j = tramp.find(tag)
            if j < 0:
                # a trampoline variant may legitimately not use every slot
                print("    [*] trampoline placeholder %s not present" % what)
                continue
            struct.pack_into("<i", tramp, j + 1, target - (tramp_rva + j + 5))
        _place(data, secs, tramp, tramp_rva, verbose=verbose)
        print("    [+] trampoline at 0x%X (placeholders patched)" % tramp_rva)

        for s in site_list:
            o = _rva2off(secs, s["rva"])
            if o is None:
                continue
            if s["form"] not in thunk:
                print("    [!] no thunk for form %s at 0x%X - site left alone"
                      % (s["form"], s["rva"]))
                continue
            rel = (shim_rva + thunk[s["form"]]) - (s["rva"] + 5)
            data[o] = 0xE8
            struct.pack_into("<i", data, o + 1, rel)
            for k in range(5, s["len"]):
                data[o + k] = 0x90
            report["cx16_sites_patched"] += 1
        print("    [+] redirected %d site(s)" % report["cx16_sites_patched"])

        if not hook_ud:
            print("    [*] #UD handler hook disabled (kernel sites still emulated)")
            return data, report
        o = _rva2off(secs, handler)
        data[o] = 0xE9
        struct.pack_into("<i", data, o + 1, tramp_rva - (handler + 5))
        report["trampoline_installed"] = True
        print("    [+] hooked #UD handler 0x%X -> 0x%X" % (handler, tramp_rva))
        return data, report
    finally:
        pe.close()


@register_patcher("kernel_cx16")
def patch_kernel_cx16_file(input_path: str, output_path: str, **kwargs) -> bool:
    with open(input_path, "rb") as f:
        data = bytearray(f.read())
    data, report = patch_kernel_cx16_bytes(data, exe_path=input_path, **kwargs)
    with open(output_path, "wb") as f:
        f.write(data)
    fix_pe_checksum(output_path)
    print(f"[+] Written: {output_path}")
    return any((report["cpuid_table_patched"], report["lax_table_patched"],
                report["prefetchw_sites"], report["cx16_sites_patched"]))
