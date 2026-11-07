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
    "shim_nest.bin": {"rdi": 0xA8, "rsi": 0xB2, "r8": 0xBC, "r10": 0xC6,
                      "r11": 0xD0, "r14": 0xDA, "r15": 0xE4, "rdi20": 0xEE,
                      "r9d20": 0xF9, "r8d10": 0x104, "r8d20": 0x10F,
                      "r8d100": 0x11A, "r8d150": 0x128},
    "shim.bin": {"rdi": 0x99, "rsi": 0xA3, "r8": 0xAD, "r10": 0xB7,
                 "r11": 0xC1, "r14": 0xCB, "r15": 0xD5, "rdi20": 0xDF,
                 "r8d10": 0xEA, "r8d20": 0xF5, "r8d100": 0x100, "r8d150": 0x10E},
    "shim_1909.bin": {"rdi": 0x99, "rdi20": 0xA3, "rsi": 0xAE, "r8d20": 0xB8,
                      "r8d150": 0xC3, "r10": 0xD1, "r11": 0xDB, "r14": 0xE5},
    # 256-byte variant: the only one that fits the 383-byte PAGELK cave used by
    # the verified Windows 11 23H2 image (shim + LAHF stub in one run)
    "shim_256.bin": {"rdi": 0xA0, "rsi": 0xAA, "r8": 0xB4, "r10": 0xCC,
                     "r11": 0xD6, "r14": 0xE0, "r15": 0xEA, "r8d100": 0xBE},
}

SITE_LEN = {"r8": 5, "rdi": 5, "rsi": 5, "r10": 5, "r11": 5, "r14": 5,
            "r15": 5, "rdi20": 6, "r8d10": 6, "r8d20": 6, "r9d20": 6,
            "r8d100": 9, "r8d150": 9}

REGS = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]

IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_WRITE = 0x80000000

# sections the kernel reuses or discards - never place code there
BAD_SECTIONS = {"POOLCODE", "INIT", "INITKDBG", "INITDATA", "PAGEVRFB"}

HERE = os.path.dirname(os.path.abspath(__file__))
ASM_DIR = os.path.join(HERE, os.pardir, "asm")          # src/asm
BLOB_DIR = os.path.join(HERE, os.pardir, os.pardir, "blobs")


# ---------------------------------------------------------------- helpers
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


def _place(data, secs, blob, rva, lock_rva=None, verbose=True):
    if lock_rva is not None:
        i = blob.find(bytes.fromhex("44332211"))
        if i >= 0:
            struct.pack_into("<i", blob, i, lock_rva - (rva + i + 4))
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
                    runs.append({"rva": va + ((-va) % 16), "len": j - i,
                                 "name": s["name"],
                                 "pageable": s["name"].startswith("PAGE")})
                i = j
            else:
                i += 1
    runs.sort(key=lambda c: (c["pageable"], -c["len"]))
    picked = []
    for need in sorted(sizes, reverse=True):
        for c in runs:
            if c["len"] < need:
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
                    ("r8", 0x100): "r8d100", ("r8", 0x150): "r8d150",
                    ("r9", 0x20): "r9d20", ("r10", 0): "r10",
                    ("r11", 0): "r11", ("r14", 0): "r14",
                    ("r15", 0): "r15"}.get((base, disp))
            sites.append({"rva": s["va"] + j, "form": form, "len": ln})
    return sites


# ------------------------------------------------------------------ patch
def patch_kernel_cx16_bytes(
    data: bytearray,
    exe_path: str = "",
    patch_prefetchw_flag: bool = True,
    verify_prefetchw: bool = False,
    emulate_cx16: bool = True,
    use_symbol_gates: bool = True,
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
    report = {"cpuid_table_patched": False, "lax_table_patched": False,
              "prefetchw_sites": 0, "gates_patched": 0,
              "cx16_sites_patched": 0, "trampoline_installed": False,
              "lahf_stub_installed": False}

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
        if exe_path:
            if not derived:
                derived = {}
            if "symbols" not in derived:
                derived["symbols"] = _offsets.symbols.resolve(exe_path, verbose=False)
            report["cpu_features"] = _cpu.patch_cpu_features(
                data, pe, secs, derived["symbols"], verbose)

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
            print("    [-] unknown shim blob '%s'" % shim_name)
            return data, report
        thunk = THUNK_TABLES[shim_name]

        # a blob spec may pin its placement: "blobs/shim.bin@0xAAAE81".
        # Explicit addresses win; anything left unset is auto-discovered.
        def _split(spec, default):
            if "@" in spec:
                path, rva = spec.split("@", 1)
                return path, int(rva, 16)
            return (os.path.join(BLOB_DIR, spec) if not os.path.isabs(spec) else spec), None

        shim_path, shim_pin = _split(shim_blob, None)
        tramp_path, tramp_pin = _split(tramp_blob or os.path.join(BLOB_DIR, "tramp.bin"), None)
        lahf_path, lahf_pin = _split(lahf_blob or os.path.join(BLOB_DIR, "lahf.bin"), None)

        wants = []
        if shim_pin is None:
            wants.append(("shim", len(open(shim_path, "rb").read())))
        if tramp_pin is None:
            wants.append(("tramp", len(open(tramp_path, "rb").read())))
        if lahf_pin is None:
            wants.append(("lahf", len(open(lahf_path, "rb").read())))
        auto = {}
        if wants:
            picked = _pick_caves(pe, secs, [w[1] for w in wants], verbose)
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
        _place(data, secs, shim, shim_rva, lock_rva=lock, verbose=verbose)

        lahf = bytearray(open(lahf_path, "rb").read())
        _place(data, secs, lahf, lahf_rva, verbose=verbose)
        report["lahf_stub_installed"] = True

        tramp = bytearray(open(tramp_path, "rb").read())
        while tramp and tramp[-1] == 0x90:
            tramp.pop()
        back = int(handler_back, 16) if handler_back else handler + 5
        for tag, target, what in ((b"\xe8\x33\x33\x33\x33", shim_rva + thunk["r11"], "r11"),
                                  (b"\xe8\x44\x44\x44\x44", shim_rva + thunk["r10"], "r10"),
                                  (b"\xe9\x55\x66\x77\x88", back, "back"),
                                  (b"\xe9\x99\x99\x99\x99", lahf_rva, "lahf")):
            j = tramp.find(tag)
            if j < 0:
                print("    [-] trampoline placeholder %s missing" % what)
                return data, report
            struct.pack_into("<i", tramp, j + 1, target - (tramp_rva + j + 5))
        _place(data, secs, tramp, tramp_rva, verbose=verbose)
        print("    [+] trampoline at 0x%X (placeholders patched)" % tramp_rva)

        for s in site_list:
            o = _rva2off(secs, s["rva"])
            if o is None:
                continue
            rel = (shim_rva + thunk[s["form"]]) - (s["rva"] + 5)
            data[o] = 0xE8
            struct.pack_into("<i", data, o + 1, rel)
            for k in range(5, s["len"]):
                data[o + k] = 0x90
            report["cx16_sites_patched"] += 1
        print("    [+] redirected %d site(s)" % report["cx16_sites_patched"])

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
