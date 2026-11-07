import os
import struct

import pefile

from . import register_patcher
from .pe import fix_pe_checksum
from .prefetch import neutralize_prefetchw

# Thunk offsets inside each shim blob (see blobs/*.s).  Two variants exist:
#   shim.bin       full set of addressing forms
#   shim_1909.bin  compact set, needed when the code cave is small
THUNK_TABLES = {
    "shim.bin": {"rdi": 0x99, "rsi": 0xA3, "r8": 0xAD, "r10": 0xB7,
                 "r11": 0xC1, "r14": 0xCB, "r15": 0xD5, "rdi20": 0xDF,
                 "r8d10": 0xEA, "r8d20": 0xF5, "r8d100": 0x100, "r8d150": 0x10E},
    "shim_1909.bin": {"rdi": 0x99, "rdi20": 0xA3, "rsi": 0xAE, "r8d20": 0xB8,
                      "r8d150": 0xC3, "r10": 0xD1, "r11": 0xDB, "r14": 0xE5},
    # nesting-aware lock (owner + depth); correct on SMP
    "shim_nest.bin": {"rdi": 0xA8, "rsi": 0xB2, "r8": 0xBC, "r10": 0xC6,
                      "r11": 0xD0, "r14": 0xDA, "r15": 0xE4, "rdi20": 0xEE,
                      "r9d20": 0xF9, "r8d10": 0x104, "r8d20": 0x10F,
                      "r8d100": 0x11A, "r8d150": 0x128},
    # diagnostic variant without the inter-CPU lock (single-core only)
    "shim_nolock.bin": {"rdi": 0x55, "rsi": 0x5C, "r8": 0x63, "r10": 0x6A,
                        "r11": 0x71, "r14": 0x78, "r15": 0x7F, "rdi20": 0x89,
                        "r8d10": 0x94, "r8d20": 0x9F, "r8d100": 0xAA,
                        "r8d150": 0xB8},
}

# instruction length of each replaced form (call + NOP padding)
SITE_LEN = {"r8": 5, "rdi": 5, "rsi": 5, "r10": 5, "r11": 5, "r14": 5,
            "r15": 5, "rdi20": 6, "r8d10": 6, "r8d20": 6,
            "r8d100": 9, "r8d150": 9, "r9d20": 6}


def patch_kernel_cx16_bytes(
    data: bytearray,
    patch_cpuid: bool = True,
    patch_prefetchw_flag: bool = True,
    verify_prefetchw: bool = False,
    gates: str = "",
    sites: str = "",
    shim_blob: str = "",
    lock_rva: str = "0xD1C100",
    handler_rva: str = "",
    handler_back: str = "",
    tramp_blob: str = "",
    lahf_blob: str = "",
) -> tuple:
    """
    Makes ntoskrnl.exe bootable on CPUs without CMPXCHG16B and/or 64-bit
    LAHF/SAHF - Pentium 4 (Prescott), first-generation Socket 754 Athlon 64.

    Four separate problems, in boot order:

    1. PREFETCHW (0F 0D /1) is #UD on these CPUs.  The earliest occurrence runs
       before the IDT is installed, so the machine triple-faults instead of
       showing a bugcheck.  Rewritten to a length-preserving NOP.

    2. KiSetProcessorSignature walks a table of CPU features and bugchecks 0x5D
       when a `required` one is missing.  The bugcheck fires before
       KiInitializeIdt, which is why the failure is silent.  The `required`
       flag of the offending entries is cleared by signature:

         CMPXCHG16B  leaf 1,          mask 0x2000, ECX, flags 0x01
         LAHF/SAHF   leaf 0x80000001, mask 0x1,    ECX, flags 0x01

       Two record layouts exist and both are handled, so this step needs no
       RVA table.

    3. KiSetFeatureBits repeats six of those checks directly and jumps to the
       same 0x5D block.  Those branches are build specific and are passed in
       as a comma separated RVA list (`gates=0xA8A8FD,0xA8A908,...`).

    4. The instruction itself is emulated:

       * `sites`     - `rva:form` pairs of every `lock cmpxchg16b`
       * `shim_blob` - `<path>@<rva>` of an assembled stub that reproduces the
                       real semantics, including reloading RDX:RAX from memory
                       when the compare fails
       * `lock_rva`  - an 8-byte writable scratch slot that must not overlap a
                       real variable; the page padding after .data is the
                       usual choice
       * `handler_rva` / `handler_back` / `tramp_blob` / `lahf_blob` install
         the #UD trampoline.  It is needed for the user-mode sites: ntdll
         contains four `lock cmpxchg16b` instructions that cannot be reached by
         patching the kernel, so the exception handler has to recognise and
         emulate them.  `lahf_blob` provides the LAHF/SAHF emulation the
         trampoline jumps to.

    Every parameter except the two signature based ones is optional; a build
    only has to provide the ones it needs.
    """
    report = {
        "cpuid_table_patched": False,
        "lax_table_patched": False,
        "prefetchw_sites": 0,
        "gates_patched": 0,
        "cx16_sites_patched": 0,
        "trampoline_installed": False,
        "lahf_stub_installed": False,
    }

    # 1. required CPU features
    if patch_cpuid:
        # 22H2/23H2: stride 0x20, [leaf, subleaf, mask, reg, flags]
        # 1909/21390: stride 0x18, [leaf, mask, reg, flags]
        layouts = (
            ("01000000002000000200000001000000",
             "01000000002000000200000000000000", 12),
            ("0100000000000000002000000200000001000000",
             "0100000000000000002000000200000000000000", 16),
        )
        # find a not-yet-patched record first; only fall back to
        # "already cleared" when no live record exists in any layout
        hit = False
        for sig_on, _sig_done, off in layouts:
            idx = data.find(bytes.fromhex(sig_on))
            if idx != -1:
                data[idx + off] = 0x00
                report["cpuid_table_patched"] = True
                hit = True
                print(
                    f"[+] Cleared CMPXCHG16B required flag at offset 0x{idx:X} "
                    f"(flags 0x01 -> 0x00)."
                )
                break
        if not hit:
            for _sig_on, sig_done, _off in layouts:
                if data.find(bytes.fromhex(sig_done)) != -1:
                    report["cpuid_table_patched"] = True
                    print("[*] CMPXCHG16B required flag is already cleared.")
                    break

        layouts = (
            ("01000080010000000200000001000000",
             "01000080010000000200000000000000", 12),
            ("0100008000000000010000000200000001000000",
             "0100008000000000010000000200000000000000", 16),
        )
        hit = False
        for sig_on, _sig_done, off in layouts:
            idx = data.find(bytes.fromhex(sig_on))
            if idx != -1:
                data[idx + off] = 0x00
                report["lax_table_patched"] = True
                hit = True
                print(
                    f"[+] Cleared LAHF/SAHF required flag at offset 0x{idx:X} "
                    f"(flags 0x01 -> 0x00)."
                )
                break
        if not hit:
            for _sig_on, sig_done, _off in layouts:
                if data.find(bytes.fromhex(sig_done)) != -1:
                    report["lax_table_patched"] = True
                    print("[*] LAHF/SAHF required flag is already cleared.")
                    break

    # 2. PREFETCHW everywhere
    if patch_prefetchw_flag:
        hits = neutralize_prefetchw(data, verify=verify_prefetchw)
        report["prefetchw_sites"] = len(hits)
        if hits:
            print(f"[+] Neutralised {len(hits)} PREFETCHW site(s) (0F 0D /1 -> NOP).")

    # 3. KiSetFeatureBits gates
    if gates:
        for item in gates.replace(" ", "").split(","):
            if not item:
                continue
            rva = int(item, 16)
            off = _rva_to_off(data, rva)
            if off is None:
                print(f"[-] gate 0x{rva:X}: RVA not mapped, skipped.")
                continue
            if data[off] != 0x0F or not (0x80 <= data[off + 1] <= 0x8F):
                print(f"[-] gate 0x{rva:X}: not a conditional jump, skipped.")
                continue
            data[off:off + 6] = b"\x90" * 6
            report["gates_patched"] += 1
        if report["gates_patched"]:
            print(f"[+] NOP'ed {report['gates_patched']} KiSetFeatureBits gate(s).")

    # 4. CMPXCHG16B emulation
    if shim_blob:
        try:
            shim_rva = int(str(shim_blob).split("@")[1], 16)
            shim_path = str(shim_blob).split("@")[0]
        except (IndexError, ValueError):
            print("[-] shim_blob must be '<path>@<rva>', e.g. blobs/shim.bin@0xAAAE81")
            return data, report

        blob_name = os.path.basename(shim_path)
        if blob_name not in THUNK_TABLES:
            print(f"[-] unknown shim blob '{blob_name}'.")
            return data, report

        _extend_section(data, int(lock_rva, 16), 16)
        _write_blob(data, shim_path, shim_rva, int(lock_rva, 16), patch_lock=True)

        if tramp_blob:
            report["trampoline_installed"] = _install_trampoline(
                data, shim_rva, blob_name, handler_rva, handler_back,
                tramp_blob, lahf_blob, report,
            )

        if sites:
            report["cx16_sites_patched"] = _patch_cx16_sites(
                data, sites, shim_rva, blob_name)
            if report["cx16_sites_patched"]:
                print(
                    f"[+] Redirected {report['cx16_sites_patched']} CMPXCHG16B "
                    f"site(s) to the emulation shim."
                )

    return data, report


def _sections(data):
    pe = pefile.PE(data=bytes(data), fast_load=True)
    try:
        for sec in pe.sections:
            yield (sec.VirtualAddress,
                   max(sec.Misc_VirtualSize, sec.SizeOfRawData),
                   sec.PointerToRawData, sec.SizeOfRawData,
                   sec.Characteristics & 0x20000000)
    finally:
        pe.close()


def _rva_to_off(data, rva):
    for va, size, raw, rawsize, _exec in _sections(data):
        if va <= rva < va + max(size, rawsize):
            off = raw + (rva - va)
            return off if off < len(data) else None
    return None



def _extend_section(data, rva, length):
    """Make sure `rva`..`rva+length` is inside its section's VirtualSize.

    Writing a blob into the file-aligned padding after VirtualSize is not
    enough: the loader guarantees the declared range is mapped with the
    section's attributes, so code placed there crashes on the first call.
    D1/D2 on 1809 proved this - identical bytes, only the declared size
    differed.

    For data sections the declared size may legitimately exceed SizeOfRawData
    (the loader zero-fills the rest); for code sections the bytes must exist
    in the file.
    """
    import struct as _s
    e0 = _s.unpack_from("<I", data, 0x3C)[0]
    nsec = _s.unpack_from("<H", data, e0 + 6)[0]
    optsz = _s.unpack_from("<H", data, e0 + 20)[0]
    table = e0 + 24 + optsz

    secs = []
    for i in range(nsec):
        h = table + i * 40
        vsize, vaddr, rawsize, rawptr = _s.unpack_from("<IIII", data, h + 8)
        chars = _s.unpack_from("<I", data, h + 36)[0]
        secs.append((vaddr, vsize, rawsize, rawptr, chars, h))

    for idx, (vaddr, vsize, rawsize, rawptr, chars, h) in enumerate(secs):
        limit = secs[idx + 1][0] if idx + 1 < len(secs) else vaddr + vsize
        if vaddr <= rva < limit:
            need = (rva - vaddr) + length
            if need <= vsize:
                return True
            executable = bool(chars & 0x20000000)
            if executable and need > rawsize:
                raise ValueError(
                    f"section at 0x{vaddr:X}: raw size 0x{rawsize:X} is too "
                    f"small for a blob at 0x{rva:X}+0x{length:X}")
            if need > limit - vaddr:
                raise ValueError(
                    f"RVA 0x{rva:X} would run past the next section")
            _s.pack_into("<I", data, h + 8, need)
            print(f"[+] Extended section at 0x{vaddr:X}: VirtualSize "
                  f"0x{vsize:X} -> 0x{need:X} to cover RVA 0x{rva:X}.")
            return True
    return False


def _write_blob(data, path, rva, lock_rva=0, patch_lock=False, verbose=True):
    blob = bytearray(open(path, "rb").read())
    if patch_lock:
        i = blob.find(bytes.fromhex("44332211"))
        if i != -1:
            struct.pack_into("<i", blob, i, lock_rva - (rva + i + 4))
    off = _rva_to_off(data, rva)
    if off is None:
        raise ValueError(f"RVA 0x{rva:X} is not mapped; cannot place {path}")

    # Refuse to overwrite real code: a cave must be padding (00 or CC).
    # Getting this wrong silently corrupts the kernel and the machine just
    # reboots after the logo, which is very hard to trace back.
    occupied = [i for i, b in enumerate(data[off:off + len(blob)])
                if b not in (0x00, 0xCC) and blob[i] != b]
    if occupied:
        first = rva + occupied[0]
        raise ValueError(
            f"RVA 0x{rva:X} is not a cave - 0x{first:X} already contains code"
            f" ({data[off + occupied[0]]:02X}); pick an empty slot")

    _extend_section(data, rva, len(blob))
    data[off:off + len(blob)] = blob
    if verbose:
        print(f"[+] Placed {os.path.basename(path)} at RVA 0x{rva:X} ({len(blob)} bytes).")
    return len(blob)


def _install_trampoline(data, shim_rva, blob_name, handler_rva, handler_back,
                        tramp_blob, lahf_blob, report):
    """Hook KiInvalidOpcodeFault so user-mode cmpxchg16b gets emulated."""
    if not handler_rva or not tramp_blob:
        return False
    try:
        tramp_rva = int(str(tramp_blob).split("@")[1], 16)
        tramp_path = str(tramp_blob).split("@")[0]
    except (IndexError, ValueError):
        print("[-] tramp_blob must be '<path>@<rva>'.")
        return False

    thunk = THUNK_TABLES[blob_name]
    tramp = bytearray(open(tramp_path, "rb").read())
    while tramp and tramp[-1] == 0x90:
        tramp.pop()

    back = int(handler_back, 16) if handler_back else int(handler_rva, 16) + 5

    for tag, target, what in (
        (b"\xe8\x33\x33\x33\x33", shim_rva + thunk["r11"], "r11 thunk"),
        (b"\xe8\x44\x44\x44\x44", shim_rva + thunk["r10"], "r10 thunk"),
        (b"\xe9\x55\x66\x77\x88", back, "pass-through"),
    ):
        j = tramp.find(tag)
        if j < 0:
            print(f"[-] trampoline placeholder for {what} is missing.")
            return False
        struct.pack_into("<i", tramp, j + 1, target - (tramp_rva + j + 5))

    if lahf_blob:
        try:
            lahf_rva = int(str(lahf_blob).split("@")[1], 16)
            lahf_path = str(lahf_blob).split("@")[0]
        except (IndexError, ValueError):
            print("[-] lahf_blob must be '<path>@<rva>'.")
            lahf_rva = 0
        if lahf_rva:
            j = tramp.find(b"\xe9\x99\x99\x99\x99")
            if j >= 0:
                struct.pack_into("<i", tramp, j + 1,
                                 lahf_rva - (tramp_rva + j + 5))
            _write_blob(data, lahf_path, lahf_rva)
            report["lahf_stub_installed"] = True

    # write the PATCHED trampoline (never re-read the file: doing so would
    # silently restore the 0x33333333 / 0x44444444 call placeholders, which
    # sends the #UD handler into an unmapped address)
    _extend_section(data, tramp_rva, len(tramp))
    off = _rva_to_off(data, tramp_rva)
    if off is None:
        print(f"[-] trampoline RVA 0x{tramp_rva:X} is not mapped.")
        return False
    data[off:off + len(tramp)] = tramp
    print(f"[+] Placed tramp.bin at RVA 0x{tramp_rva:X} ({len(tramp)} bytes, patched).")

    h = int(handler_rva, 16)
    off = _rva_to_off(data, h)
    if off is None:
        print(f"[-] handler RVA 0x{h:X} is not mapped.")
        return False
    if data[off] != 0xE9:
        data[off] = 0xE9
        struct.pack_into("<i", data, off + 1, tramp_rva - (h + 5))
    print(f"[+] Hooked KiInvalidOpcodeFault at RVA 0x{h:X} -> 0x{tramp_rva:X}.")
    return True


def _patch_cx16_sites(data, sites, shim_rva, blob_name):
    thunk = THUNK_TABLES[blob_name]
    n = 0
    for item in sites.replace(" ", "").split(","):
        if not item:
            continue
        rva_s, form = item.split(":")
        rva = int(rva_s, 16)
        o = _rva_to_off(data, rva)
        if o is None:
            print(f"[-] site 0x{rva:X}: RVA not mapped, skipped.")
            continue
        rel = (shim_rva + thunk[form]) - (rva + 5)
        data[o] = 0xE8
        struct.pack_into("<i", data, o + 1, rel)
        for k in range(5, SITE_LEN[form]):
            data[o + k] = 0x90
        n += 1
    return n


@register_patcher("kernel_cx16")
def patch_kernel_cx16_file(
    input_path: str,
    output_path: str,
    patch_cpuid: bool = True,
    patch_prefetchw_flag: bool = True,
    verify_prefetchw: bool = False,
    gates: str = "",
    sites: str = "",
    shim_blob: str = "",
    lock_rva: str = "0xD1C100",
    handler_rva: str = "",
    handler_back: str = "",
    tramp_blob: str = "",
    lahf_blob: str = "",
    **kwargs,
) -> bool:
    with open(input_path, "rb") as f:
        data = bytearray(f.read())

    data, report = patch_kernel_cx16_bytes(
        data,
        patch_cpuid=patch_cpuid,
        patch_prefetchw_flag=patch_prefetchw_flag,
        verify_prefetchw=verify_prefetchw,
        gates=gates,
        sites=sites,
        shim_blob=shim_blob,
        lock_rva=lock_rva,
        handler_rva=handler_rva,
        handler_back=handler_back,
        tramp_blob=tramp_blob,
        lahf_blob=lahf_blob,
    )

    with open(output_path, "wb") as f:
        f.write(data)
    fix_pe_checksum(output_path)
    print(f"[+] Written: {output_path}")
    return any((report["cpuid_table_patched"], report["lax_table_patched"],
                report["prefetchw_sites"], report["cx16_sites_patched"]))
