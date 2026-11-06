import os
import struct

import pefile

from . import register_patcher
from .pe import fix_pe_checksum
from .prefetch import neutralize_prefetchw


# Thunk offsets inside each shim blob (see blobs/*.s).  Two variants exist:
#   shim.bin       full set of addressing forms
#   shim_1909.bin  compact set, needed when the code cave is only 368 bytes
THUNK_TABLES = {
    "shim.bin": {"rdi": 0x99, "rsi": 0xA3, "r8": 0xAD, "r10": 0xB7,
                 "r11": 0xC1, "r14": 0xCB, "r15": 0xD5, "rdi20": 0xDF,
                 "r8d10": 0xEA, "r8d20": 0xF5, "r8d100": 0x100, "r8d150": 0x10E},
    "shim_1909.bin": {"rdi": 0x99, "rdi20": 0xA3, "rsi": 0xAE, "r8d20": 0xB8,
                      "r8d150": 0xC3, "r10": 0xD1, "r11": 0xDB, "r14": 0xE5},
}


def patch_kernel_cx16_bytes(
    data: bytearray,
    patch_cpuid: bool = True,
    patch_prefetchw_flag: bool = True,
    gates: str = "",
    sites: str = "",
    shim_blob: str = "",
) -> tuple:
    """
    Makes ntoskrnl.exe bootable on CPUs without CMPXCHG16B and/or 64-bit
    LAHF/SAHF - Pentium 4 (Prescott), first-generation Socket 754 Athlon 64.

    Three separate problems, in boot order:

    1. PREFETCHW (0F 0D /1) is #UD on these CPUs.  The earliest occurrence runs
       before the IDT is installed, so the machine triple-faults instead of
       showing a bugcheck.  Rewritten to a length-preserving NOP.

    2. KiSetProcessorSignature walks a table of CPU features and bugchecks 0x5D
       when a `required` one is missing.  The bugcheck fires before
       KiInitializeIdt, which is why the failure is silent.  The `required`
       flag of the offending entries is cleared by signature:

         CMPXCHG16B  leaf 1,          mask 0x2000, ECX, flags 0x01
         LAHF/SAHF   leaf 0x80000001, mask 0x1,    ECX, flags 0x01

       Their 20-byte records start with the same five dwords in every build
       from Windows 10 to Windows 11, so no RVA table is needed.

    3. KiSetFeatureBits repeats six of those checks directly and jumps to the
       same 0x5D block.  Those branches are build specific and are passed in
       as a comma separated RVA list (`gates=0xA8A8FD,0xA8A908,...`).

    The instruction itself is emulated: `sites` lists the file offsets of the
    `lock cmpxchg16b` instructions as `rva:form` pairs and `shim_blob` points
    at an assembled stub that reproduces the real semantics (including
    reloading RDX:RAX from memory when the compare fails).  This is optional
    because locating and patching those sites needs per-build knowledge.
    """
    report = {
        "cpuid_table_patched": False,
        "lax_table_patched": False,
        "prefetchw_sites": 0,
        "gates_patched": 0,
        "cx16_sites_patched": 0,
    }

    # 1. CMPXCHG16B required flag: index 1, mask 0x2000, ECX, flags 0x01
    if patch_cpuid:
        # two record layouts exist:
        #   22H2/23H2  stride 0x20, [leaf, subleaf, mask, reg, flags]
        #   1909/21390 stride 0x18, [leaf, mask, reg, flags]
        sig_cx16_18 = bytes.fromhex("01000000002000000200000001000000")
        sig_cx16_18_done = bytes.fromhex("01000000002000000200000000000000")
        idx = data.find(sig_cx16_18)
        if idx != -1:
            data[idx + 12] = 0x00
            report["cpuid_table_patched"] = True
            print(
                f"[+] Cleared CMPXCHG16B required flag at offset 0x{idx:X} (flags 0x01 -> 0x00, 0x18 layout)."
            )
        elif data.find(sig_cx16_18_done) != -1:
            report["cpuid_table_patched"] = True
            print("[*] CMPXCHG16B required flag is already cleared (0x18 layout).")

        sig_cx16 = bytes.fromhex("0100000000000000002000000200000001000000")
        sig_cx16_done = bytes.fromhex("0100000000000000002000000200000000000000")
        idx = data.find(sig_cx16)
        if idx != -1:
            data[idx + 16] = 0x00
            report["cpuid_table_patched"] = True
            print(
                f"[+] Cleared CMPXCHG16B required flag at offset 0x{idx:X} (flags 0x01 -> 0x00)."
            )
        elif data.find(sig_cx16_done) != -1:
            report["cpuid_table_patched"] = True
            print("[*] CMPXCHG16B required flag is already cleared.")

        # LAHF/SAHF required flag: index 0x80000001, mask 0x1, ECX, flags 0x01
        sig_lahf_18 = bytes.fromhex("01000080010000000200000001000000")
        sig_lahf_18_done = bytes.fromhex("01000080010000000200000000000000")
        idx = data.find(sig_lahf_18)
        if idx != -1:
            data[idx + 12] = 0x00
            report["lax_table_patched"] = True
            print(
                f"[+] Cleared LAHF/SAHF required flag at offset 0x{idx:X} (flags 0x01 -> 0x00, 0x18 layout)."
            )
        elif data.find(sig_lahf_18_done) != -1:
            report["lax_table_patched"] = True
            print("[*] LAHF/SAHF required flag is already cleared (0x18 layout).")

        sig_lahf = bytes.fromhex("0100008000000000010000000200000001000000")
        sig_lahf_done = bytes.fromhex("0100008000000000010000000200000000000000")
        idx = data.find(sig_lahf)
        if idx != -1:
            data[idx + 16] = 0x00
            report["lax_table_patched"] = True
            print(
                f"[+] Cleared LAHF/SAHF required flag at offset 0x{idx:X} (flags 0x01 -> 0x00)."
            )
        elif data.find(sig_lahf_done) != -1:
            report["lax_table_patched"] = True
            print("[*] LAHF/SAHF required flag is already cleared.")

    # 2. PREFETCHW everywhere
    if patch_prefetchw_flag:
        hits = neutralize_prefetchw(data)
        report["prefetchw_sites"] = len(hits)
        if hits:
            print(f"[+] Neutralised {len(hits)} PREFETCHW site(s) (0F 0D /1 -> NOP).")

    # 3. KiSetFeatureBits gates passed in by the caller
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

    # 4. CMPXCHG16B sites (optional, build specific)
    if sites and shim_blob:
        patched = _patch_cx16_sites(data, sites, shim_blob)
        report["cx16_sites_patched"] = patched
        if patched:
            print(f"[+] Redirected {patched} CMPXCHG16B site(s) to the emulation shim.")

    return data, report


def _sections(data):
    pe = pefile.PE(data=bytes(data), fast_load=True)
    try:
        for sec in pe.sections:
            yield (sec.VirtualAddress, max(sec.Misc_VirtualSize, sec.SizeOfRawData),
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


def _patch_cx16_sites(data, sites, shim_blob):
    """Redirect `lock cmpxchg16b [mem]` to a shim.

    `sites` is "rva:form,rva:form,..." and `shim_blob` is the path of an
    assembled stub whose layout is described in blobs/shim.s.  The shim is
    linked in by the caller (it writes the blob plus its lock address), so this
    helper only redirects the call sites.
    """
    length = {"r8": 5, "rdi": 5, "rsi": 5, "r10": 5, "r11": 5, "r14": 5,
              "r15": 5, "rdi20": 6, "r8d10": 6, "r8d20": 6,
              "r8d100": 9, "r8d150": 9}

    shim_rva = 0
    try:
        shim_rva = int(str(shim_blob).split("@")[1], 16)
        blob_path = str(shim_blob).split("@")[0]
    except (IndexError, ValueError):
        print("[-] shim_blob must be given as '<path>@<rva>', e.g. blobs/shim.bin@0xAAAE81")
        return 0

    thunk = THUNK_TABLES[os.path.basename(blob_path)]
    blob = bytearray(open(blob_path, "rb").read())
    lock_rva = 0xD1C100
    i = blob.find(bytes.fromhex("44332211"))
    if i != -1:
        struct.pack_into("<i", blob, i, lock_rva - (shim_rva + i + 4))
    off = _rva_to_off(data, shim_rva)
    if off is None:
        print(f"[-] shim RVA 0x{shim_rva:X} is not mapped; extend the section first.")
        return 0
    data[off:off + len(blob)] = blob

    n = 0
    for item in sites.replace(" ", "").split(","):
        if not item:
            continue
        rva_s, form = item.split(":")
        rva = int(rva_s, 16)
        o = _rva_to_off(data, rva)
        if o is None:
            continue
        rel = (shim_rva + thunk[form]) - (rva + 5)
        data[o] = 0xE8
        struct.pack_into("<i", data, o + 1, rel)
        for k in range(5, length[form]):
            data[o + k] = 0x90
        n += 1
    return n


@register_patcher("kernel_cx16")
def patch_kernel_cx16_file(
    input_path: str,
    output_path: str,
    patch_cpuid: bool = True,
    patch_prefetchw_flag: bool = True,
    gates: str = "",
    sites: str = "",
    shim_blob: str = "",
    **kwargs,
) -> bool:
    with open(input_path, "rb") as f:
        data = bytearray(f.read())

    data, report = patch_kernel_cx16_bytes(
        data,
        patch_cpuid=patch_cpuid,
        patch_prefetchw_flag=patch_prefetchw_flag,
        gates=gates,
        sites=sites,
        shim_blob=shim_blob,
    )

    with open(output_path, "wb") as f:
        f.write(data)
    fix_pe_checksum(output_path)
    print(f"[+] Written: {output_path}")
    return report["cpuid_table_patched"] or report["lax_table_patched"] or \
        report["prefetchw_sites"] > 0
