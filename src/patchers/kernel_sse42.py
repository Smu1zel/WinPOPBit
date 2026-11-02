import os
import re
import struct
import pefile
from . import register_patcher
from .pe import fix_pe_checksum


def patch_kernel_bytes(
    data: bytearray,
    patch_cpuid: bool = True,
    patch_kiset: bool = False,
    enable_debug: bool = False,
    pcat_clk_removal_workaround: bool = True,
) -> tuple:
    """
    Applies the core WinPOPBit kernel modifications to a raw ntoskrnl.exe bytearray:

    1. CPUID Requirements Table Patch (SSE4.2 Flags 0x0D -> 0x0C):
       - Leaf: 1, Subleaf: 0, Mask: 0x00100000 (Bit 20: SSE4.2), Register: 2 (ECX), Flags: 0x0000000D
       - Patching Flags from 0x0D (Mandatory) to 0x0C (Optional) tells RtlDetectProcessorFeatures
         to continue booting even if CPUID does not report SSE4.2 support.

    2. KiSetFeatureBits Conditional Jumps Patch (Optional, disabled by default):
       - NOPs out hardcoded conditional branches in KiSetFeatureBits that guard processor feature bits.
       - Disabled by default since the CPUID table patch is sufficient for modern 24H2 builds.

    3. PC/AT Clock Removal Workaround (Enabled by default):
       - In Windows 11 24H2 (Build 25921+), Microsoft removed legacy PC/AT timer drivers (RTC / 8254 PIT).
       - On systems where HPET is absent (e.g. nForce 3/4/500) or disabled in BIOS (e.g. some AMD 785G boards),
         the kernel requires an Invariant Local APIC timer as the clock source.
       - HalpApicTimerIsInvariant checks if AMD CPU Family >= 0x15 (Bulldozer). Older AMD CPUs (K8, K10 Phenom/Athlon)
         fail this check (Family 0x0F/0x10), causing HalpTimerFindIdealClockSource to return NULL and BugCheck 0x5C
         (0x110, 0x5250631, 0x14, 0xC0000001).
       - Patches the AMD family check in HalpApicTimerIsInvariant to return 1 (True), allowing the Local APIC timer
         to be registered as invariant and used as the clock source regardless of CPUID family.

    4. KeBugCheckEx Debug Loop Patch (Optional, disabled by default):
       - Overwrites the first 2 bytes of KeBugCheckEx with 'EB FE' (jmp $, infinite loop).
       - Allows attaching QEMU GDB debugger (via qemu_gdb_debugger.py) when a BugCheck 0x5D occurs
         to inspect live guest registers, walk the call stack, and read the failed requirement entry.
    """
    report = {
        "cpuid_patched": False,
        "kiset_patched": False,
        "debug_loop_patched": False,
        "pcat_clk_patched": False,
    }

    # 1. CPUID Requirements Table Patch (Index 6: SSE4.2 Flags 0x0D -> 0x0C)
    if patch_cpuid:
        # 20-byte signature: Leaf=1, Subleaf=0, Mask=0x00100000, Reg=2 (ECX), Flags=0x0D
        req_sig_0d = bytes.fromhex("010000000000000000001000020000000D000000")
        req_sig_0c = bytes.fromhex("010000000000000000001000020000000C000000")

        req_idx = data.find(req_sig_0d)
        if req_idx != -1:
            # Overwrite Flags byte at offset 16 from 0x0D to 0x0C
            data[req_idx + 16] = 0x0C
            report["cpuid_patched"] = True
            print(
                f"[+] Patched CPUID requirements table entry at offset 0x{req_idx:X} (Flags: 0x0D -> 0x0C)."
            )
        else:
            idx_0c = data.find(req_sig_0c)
            if idx_0c != -1:
                report["cpuid_patched"] = True
                print(
                    f"[*] Notice: CPUID requirements table entry at offset 0x{idx_0c:X} is already patched (Flags: 0x0C)."
                )
            else:
                print(
                    "[-] Warning: Mandatory SSE4.2 CPUID requirement table entry (0x0D) not found in binary."
                )

    # 2. KiSetFeatureBits CPU branch jump checks (Disabled by default)
    if patch_kiset:
        # Signature matching the 4 primary branch comparisons in KiSetFeatureBits
        pattern = re.compile(
            b"\x3b\xc1"  # cmp eax, ecx
            + b"\x0f\x85.{4}"  # jne rel32
            + b"\x41\x0f\xba\xe6\x0b"  # bt r14d, 0Bh
            + b"\x0f\x83.{4}"  # jnb/jae rel32
            + b"\x41\x0f\xba\xe6\x14"  # bt r14d, 14h
            + b"\x0f\x83.{4}"  # jnb/jae rel32
            + b"\x41\x0f\xba\xe5\x0d"  # bt r13d, 0Dh
            + b"\x0f\x83.{4}",  # jnb/jae rel32
            re.DOTALL,
        )
        matches = list(pattern.finditer(data))
        if matches:
            start = matches[0].start()
            # NOP out the 4 main 6-byte jumps
            data[start + 2 : start + 8] = b"\x90" * 6
            data[start + 13 : start + 19] = b"\x90" * 6
            data[start + 24 : start + 30] = b"\x90" * 6
            data[start + 35 : start + 41] = b"\x90" * 6

            # NOP out 5th and 6th jumps if they match standard offsets
            if data[start + 50] == 0x0F and data[start + 51] == 0x84:
                data[start + 50 : start + 56] = b"\x90" * 6
            if data[start + 63] == 0x0F and data[start + 64] == 0x85:
                data[start + 63 : start + 69] = b"\x90" * 6
            report["kiset_patched"] = True
            print(
                f"[+] Patched KiSetFeatureBits conditional jumps at offset 0x{start:X}."
            )
        else:
            print("[-] Warning: KiSetFeatureBits CPU check signature not found.")

    # 3. PC/AT Legacy Timer Removal Workaround (HalpApicTimerIsInvariant AMD family check)
    if pcat_clk_removal_workaround:
        # Signature: mov rax, qword ptr gs:[0x20]; cmp byte ptr [rax + 0x40], 0x15
        # 65 48 8B 04 25 20 00 00 00 (mov rax, gs:[20h])
        # 80 78 40 15                (cmp byte ptr [rax+40h], 15h)
        apic_sig = bytes.fromhex("65488B04252000000080784015")
        already_patched_sig = bytes.fromhex("B0014883C4305DC3")

        idx = data.find(apic_sig)
        if idx != -1:
            # Replace family check with:
            # mov al, 1       (B0 01)
            # add rsp, 0x30   (48 83 C4 30)
            # pop rbp         (5D)
            # ret             (C3)
            # nop * 5         (90 90 90 90 90)
            patch_bytes = bytearray(bytes.fromhex("B0014883C4305DC39090909090"))
            data[idx : idx + 13] = patch_bytes

            # Clean up following jb if present (short 72 ?? or near 0F 82 ?? ?? ?? ??)
            if data[idx + 13] == 0x72:
                data[idx + 13 : idx + 15] = b"\x90\x90"
            elif data[idx + 13 : idx + 15] == b"\x0f\x82":
                data[idx + 13 : idx + 19] = b"\x90" * 6

            report["pcat_clk_patched"] = True
            print(
                f"[+] Patched HalpApicTimerIsInvariant AMD family check at offset 0x{idx:X} (pcat_clk_removal_workaround)."
            )
        else:
            already_idx = data.find(already_patched_sig)
            if already_idx != -1:
                report["pcat_clk_patched"] = True
                print(
                    f"[*] Notice: HalpApicTimerIsInvariant is already patched at offset 0x{already_idx:X}."
                )
            else:
                print(
                    "[-] Warning: HalpApicTimerIsInvariant AMD family check signature not found."
                )

    # 4. Optional KeBugCheckEx infinite loop patch (EB FE) for QEMU GDB debugging
    if enable_debug:
        try:
            pe = pefile.PE(data=bytes(data))
            kbc_rva = None
            # Resolve exported KeBugCheckEx function dynamically from Export Directory
            if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if (
                        exp.name
                        and exp.name.decode("latin1", errors="ignore") == "KeBugCheckEx"
                    ):
                        kbc_rva = exp.address
                        break
            if not kbc_rva:
                kbc_rva = 0x4F6880  # Standard RVA fallback

            kbc_offset = pe.get_offset_from_rva(kbc_rva)
            pe.close()
            # Write JMP $ (EB FE) at the start of KeBugCheckEx
            data[kbc_offset : kbc_offset + 2] = b"\xeb\xfe"
            report["debug_loop_patched"] = True
            print(
                f"[+] Patched KeBugCheckEx at offset 0x{kbc_offset:X} (RVA 0x{kbc_rva:X}) to EB FE infinite loop."
            )
        except Exception as e:
            print(f"[-] Warning: Failed to patch KeBugCheckEx debug loop: {e}")

    return data, report


@register_patcher("kernel_sse42")
def patch_kernel_file(
    input_path: str,
    output_path: str = None,
    patch_cpuid: bool = True,
    patch_kiset: bool = False,
    debug_loop: bool = False,
    enable_debug: bool = False,
    pcat_clk_removal_workaround: bool = False,
    **kwargs,
) -> bool:
    """
    Registered patch routine for Windows Kernel ('kernel_sse42').
    Reads the input binary, applies byte patches, writes output, and recalculates PE checksum.
    """
    if not os.path.exists(input_path):
        print(f"[-] Error: Kernel file not found: {input_path}")
        return False

    if output_path is None:
        output_path = input_path

    is_debug = debug_loop or enable_debug
    print(f"[*] Reading kernel binary: {input_path}")
    with open(input_path, "rb") as f:
        data = bytearray(f.read())

    modified_data, report = patch_kernel_bytes(
        data,
        patch_cpuid=patch_cpuid,
        patch_kiset=patch_kiset,
        enable_debug=is_debug,
        pcat_clk_removal_workaround=pcat_clk_removal_workaround,
    )

    with open(output_path, "wb") as f:
        f.write(modified_data)

    print(f"[+] Written patched binary to: {output_path}")
    if fix_pe_checksum(output_path):
        print("[+] Recalculated and updated PE Checksum successfully.")
    return True
