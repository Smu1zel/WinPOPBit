import os
import re
from . import register_patcher
from .pe import fix_pe_checksum


def patch_winload_nx_bytes(
    data: bytearray,
    patch_nx: bool = True,
    patch_msr_fallback: bool = True,
    patch_ci_filter: bool = False
) -> tuple:
    """
    Applies the NX (No-Execute) compatibility patches to a raw 32-bit x86 winload.exe bytearray:

    1. BlpLibraryParameters NX Flag Bypass (Primary / Option A):
       In OslMain, winload sets library initialization flags:
         mov dword ptr [esp + 0x48], 0x1A014  ; C7 44 24 48 14 A0 01 00
       Bit 16 (0x10000) corresponds to LF_ENABLE_NX.
       Patching 0x1A014 to 0x0A014 (14 A0 01 00 -> 14 A0 00 00) signals winload to skip
       all NX configuration:
       - ArchInitializeProcessorFeatures skips reading MSR 0x1A0 and writing MSR 0xC0000080 (EFER.NXE).
       - ArchRestoreProcessorFeatures skips restoring EFER.
       - BlpArchQueryCurrentAddressSpace / ArchFilterPage does not set bit 63 (XD) on page table entries.

    2. EFER WRMSR Safety Fallback (Defensive / Option B):
       NOPs out WRMSR (0F 30 -> 90 90) at:
       - ArchInitializeProcessorFeatures: or eax, 0x800; ...; wrmsr
       - ArchRestoreProcessorFeatures: and eax, ~0x800; wrmsr
       Prevents fatal #GP / triple-fault if MSR operations are ever reached.

    3. Code Integrity Validation Filter Bypass (Optional):
       In ImgpFilterValidationFailure, replaces prologue with:
         xor eax, eax  ; 31 C0
         ret 4         ; C2 04 00 (clean up 1 stack argument in 32-bit __fastcall)
       Forces STATUS_SUCCESS (0), allowing patched ntoskrnl.exe to boot without
       requiring manual 'Disable driver signature enforcement' from the F8 menu.
    """
    report = {
        "nx_flag_patched": False,
        "nx_flag_already_patched": False,
        "msr_init_patched": False,
        "msr_restore_patched": False,
        "ci_filter_patched": False,
        "ci_filter_already_patched": False,
    }

    if patch_nx:
        # Match mov dword ptr [esp+...], 0x1A014
        pattern_flag = re.compile(rb'(\xC7[\x44\x45].{1,2}\x14\xA0)\x01\x00')
        pattern_already = re.compile(rb'(\xC7[\x44\x45].{1,2}\x14\xA0)\x00\x00')
        m = pattern_flag.search(data)
        if m:
            idx = m.end() - 2
            data[idx] = 0x00
            report["nx_flag_patched"] = True
            print(f"[+] Patched OslMain BlpLibraryParameters NX flag at offset 0x{idx:X} (0x1A014 -> 0x0A014).")
        elif pattern_already.search(data):
            report["nx_flag_already_patched"] = True
            print("[*] Notice: OslMain BlpLibraryParameters NX flag is already patched (0x0A014).")
        else:
            print("[-] Warning: OslMain BlpLibraryParameters NX flag pattern (0x1A014) not found in winload.")

    if patch_msr_fallback:
        # ArchInitializeProcessorFeatures WRMSR: or eax, 0x800; ...; wrmsr
        m1 = re.search(rb'\x0D\x00\x08\x00\x00.{1,15}\x0F\x30', data)
        if m1:
            wrmsr_idx = m1.end() - 2
            data[wrmsr_idx : wrmsr_idx + 2] = b'\x90\x90'
            report["msr_init_patched"] = True
            print(f"[+] NOPed out ArchInitializeProcessorFeatures EFER WRMSR at offset 0x{wrmsr_idx:X}.")
        else:
            if re.search(rb'\x0D\x00\x08\x00\x00.{1,15}\x90\x90', data):
                print("[*] Notice: ArchInitializeProcessorFeatures EFER WRMSR is already NOPed.")
            else:
                print("[-] Notice: ArchInitializeProcessorFeatures EFER WRMSR pattern not found.")

        # ArchRestoreProcessorFeatures WRMSR: and eax, ~0x800; wrmsr
        m2 = re.search(rb'\x25\xFF\xF7\xFF\xFF\x0F\x30', data)
        if m2:
            wrmsr_idx2 = m2.end() - 2
            data[wrmsr_idx2 : wrmsr_idx2 + 2] = b'\x90\x90'
            report["msr_restore_patched"] = True
            print(f"[+] NOPed out ArchRestoreProcessorFeatures EFER WRMSR at offset 0x{wrmsr_idx2:X}.")
        else:
            if re.search(rb'\x25\xFF\xF7\xFF\xFF\x90\x90', data):
                print("[*] Notice: ArchRestoreProcessorFeatures EFER WRMSR is already NOPed.")
            else:
                print("[-] Notice: ArchRestoreProcessorFeatures EFER WRMSR pattern not found.")

    if patch_ci_filter:
        filter_sig = bytes.fromhex("8BFF558BEC515153568BF2894DFC5733FF8BDE81FE280400C0")
        filter_idx = data.find(filter_sig)
        if filter_idx != -1:
            data[filter_idx : filter_idx + 5] = bytes.fromhex("31C0C20400")
            report["ci_filter_patched"] = True
            print(f"[+] Patched ImgpFilterValidationFailure at offset 0x{filter_idx:X} (31 C0 C2 04 00 -> force STATUS_SUCCESS).")
        elif data.find(bytes.fromhex("31C0C20400")) != -1:
            report["ci_filter_already_patched"] = True
            print("[*] Notice: ImgpFilterValidationFailure is already patched.")
        else:
            print("[-] Warning: ImgpFilterValidationFailure signature not found in winload.")

    # 4. PTE / PDE XD Bit (Bit 63) Suppression:
    # Winload unconditionally sets bit 63 (0x80000000 in high DWORD) on read-only and data PTEs:
    # - MmPaepMapPhysicalAddress: or edx, 0x80000000 (81 CA 00 00 00 80)
    # - MmPaeSetVirtualAddressRangeAttributes: or dword ptr [edx+4], 0x80000000 (81 4A 04 00 00 00 80)
    # On CPUs without NX, bit 63 is a reserved bit in PAE mode. Setting it causes an immediate
    # Page Fault #PF with error code 0x000A (RSVD bit violation) as soon as the kernel touches
    # the page (e.g. KUSER_SHARED_DATA at 0xFFD00000). NOPing these ensures all PTEs remain valid.
    if patch_nx:
        # Patch 1: MmPaepMapPhysicalAddress: 74 06 81 CA 00 00 00 80 -> NOP 6 bytes
        pte1_sig = bytes.fromhex("740681CA00000080")
        pte1_idx = data.find(pte1_sig)
        if pte1_idx != -1:
            data[pte1_idx + 2 : pte1_idx + 8] = b'\x90' * 6
            report["pte1_xd_patched"] = True
            print(f"[+] NOPed out MmPaepMapPhysicalAddress PTE XD bit 63 write at offset 0x{pte1_idx + 2:X}.")
        elif data.find(bytes.fromhex("7406909090909090")) != -1:
            print("[*] Notice: MmPaepMapPhysicalAddress PTE XD bit 63 write is already NOPed.")

        # Patch 2: MmPaeSetVirtualAddressRangeAttributes: 83 22 FD 81 4A 04 00 00 00 80 -> NOP 7 bytes
        pte2_sig = bytes.fromhex("8322FD814A0400000080")
        pte2_idx = data.find(pte2_sig)
        if pte2_idx != -1:
            data[pte2_idx + 3 : pte2_idx + 10] = b'\x90' * 7
            report["pte2_xd_patched"] = True
            print(f"[+] NOPed out MmPaeSetVirtualAddressRangeAttributes PTE XD bit 63 write at offset 0x{pte2_idx + 3:X}.")
        elif data.find(bytes.fromhex("8322FD90909090909090")) != -1:
            print("[*] Notice: MmPaeSetVirtualAddressRangeAttributes PTE XD bit 63 write is already NOPed.")

    return data, report


@register_patcher("winload_nx")
def patch_winload_nx_file(
    input_path: str,
    output_path: str = None,
    patch_nx: bool = True,
    patch_msr_fallback: bool = True,
    patch_ci_filter: bool = False,
    **kwargs
) -> bool:
    """
    Registered patch routine for Windows Boot Loader ('winload_nx').
    Disables NX initialization in winload to allow booting Windows 10 x86 on CPUs without NX.
    """
    if not os.path.exists(input_path):
        print(f"[-] Error: Winload file not found: {input_path}")
        return False

    if output_path is None:
        output_path = input_path

    print(f"[*] Reading winload binary: {input_path}")
    with open(input_path, "rb") as f:
        data = bytearray(f.read())

    modified_data, report = patch_winload_nx_bytes(
        data,
        patch_nx=patch_nx,
        patch_msr_fallback=patch_msr_fallback,
        patch_ci_filter=patch_ci_filter
    )

    with open(output_path, "wb") as f:
        f.write(modified_data)

    print(f"[+] Written patched binary to: {output_path}")
    if fix_pe_checksum(output_path):
        print("[+] Recalculated and updated PE Checksum successfully.")
    return True
