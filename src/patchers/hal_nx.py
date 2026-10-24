import os
import re
from . import register_patcher
from .pe import fix_pe_checksum


def patch_hal_nx_bytes(
    data: bytearray,
    patch_pte: bool = True,
    patch_ap_trampoline: bool = True
) -> tuple:
    """
    Applies the NX (No-Execute) compatibility patches to a raw 32-bit x86 hal.dll bytearray:

    1. HalpRemapVirtualAddress64 PTE XD Bit 63 Suppression:
       Offset 0x5892 (VA 0x80016292):
         8D 04 C5 00 00 00 C0  ; lea eax, [eax*8 - 0x40000000]
         81 CE 00 00 00 80     ; or esi, 0x80000000 (Sets XD bit 63 on high DWORD)
       NOPs out 'or esi, 0x80000000' (6 bytes -> 90 * 6).

    2. HalpMap PTE XD Bit 63 Suppression:
       Offset 0x161B0 (VA 0x80026BB0):
         83 7D 0C 20           ; cmp dword ptr [ebp + 0xc], 0x20
         74 06                 ; je skip
         81 CE 00 00 00 80     ; or esi, 0x80000000 (Sets XD bit 63 on high DWORD)
       NOPs out 'or esi, 0x80000000' (6 bytes -> 90 * 6).

    3. Application Processor (AP) Real-Mode Trampoline Dynamic NX Detection:
       Replaces the static 39-byte MSR sequence at offset 0x45D70 with:
         mov eax, 0x80000001
         cpuid
         test edx, 0x00100000  ; NX / XD bit 20
         je skip_efer          ; Jumps over WRMSR if NX is not supported
         mov ecx, 0xC0000080
         rdmsr
         or eax, 0x800         ; EFER.NXE
         wrmsr
         skip_efer:
         nop * 6
       Ensures EFER.NXE is set when running on NX hardware (preventing SMP triple fault)
       while completely skipping the WRMSR on non-NX hardware (preventing #GP).
    """
    report = {
        "remap_xd_patched": False,
        "map_xd_patched": False,
        "ap_trampoline_patched": False,
    }

    if patch_pte:
        # Patch 1: HalpRemapVirtualAddress64 (lea eax, [eax*8 - 0x40000000]; or esi, 0x80000000)
        sig1 = bytes.fromhex("8D04C5000000C081CE00000080")
        p1 = data.find(sig1)
        if p1 != -1:
            data[p1 + 7 : p1 + 13] = b'\x90' * 6
            report["remap_xd_patched"] = True
            print(f"[+] NOPed out HalpRemapVirtualAddress64 PTE XD bit 63 write at offset 0x{p1 + 7:X}.")
        elif data.find(bytes.fromhex("8D04C5000000C0909090909090")) != -1:
            print("[*] Notice: HalpRemapVirtualAddress64 PTE XD bit 63 write is already NOPed.")
        else:
            print("[-] Warning: HalpRemapVirtualAddress64 signature not found in hal.dll.")

        # Patch 2: HalpMap (cmp dword ptr [ebp+0xC], 0x20; je +6; or esi, 0x80000000)
        sig2 = bytes.fromhex("837D0C20740681CE00000080")
        p2 = data.find(sig2)
        if p2 != -1:
            data[p2 + 6 : p2 + 12] = b'\x90' * 6
            report["map_xd_patched"] = True
            print(f"[+] NOPed out HalpMap PTE XD bit 63 write at offset 0x{p2 + 6:X}.")
        elif data.find(bytes.fromhex("837D0C207406909090909090")) != -1:
            print("[*] Notice: HalpMap PTE XD bit 63 write is already NOPed.")
        else:
            print("[-] Warning: HalpMap signature not found in hal.dll.")

    if patch_ap_trampoline:
        # Patch 3: AP Real-Mode Trampoline Dynamic NX Detection
        # Instead of unconditionally NOPing out EFER.NXE wrmsr (which causes triple-fault on SMP
        # when NX is enabled because page tables have bit 63 set but Core 1 EFER.NXE remains 0),
        # replace the sequence with a hardware CPUID check:
        #   mov eax, 0x80000001
        #   cpuid
        #   test edx, 0x00100000  ; Bit 20 = NX / XD feature bit
        #   je skip_efer          ; If NX not supported, jump straight past WRMSR!
        #   mov ecx, 0xC0000080   ; EFER MSR
        #   rdmsr
        #   or eax, 0x800         ; EFER.NXE
        #   wrmsr
        #   skip_efer:
        #   nop * 6
        orig_trampoline = bytes.fromhex("2EF70608000100740E66B9A00100000F326683E2FB0F3066B9800000C00F32660D000800000F30")
        old_noped_trampoline = bytes.fromhex("2EF70608000100740E66B9A00100000F326683E2FB0F30") + b'\x90' * 16
        dynamic_nx_trampoline = bytes.fromhex("66B8010000800FA266F7C200001000741666B9800000C00F32660D000800000F30909090909090")

        p3 = data.find(orig_trampoline)
        if p3 != -1:
            data[p3 : p3 + 39] = dynamic_nx_trampoline
            report["ap_trampoline_patched"] = True
            print(f"[+] Replaced AP trampoline at offset 0x{p3:X} with dynamic CPUID NX detection.")
        else:
            p3_old = data.find(old_noped_trampoline)
            if p3_old != -1:
                data[p3_old : p3_old + 39] = dynamic_nx_trampoline
                report["ap_trampoline_patched"] = True
                print(f"[+] Upgraded NOPed AP trampoline at offset 0x{p3_old:X} with dynamic CPUID NX detection.")
            elif data.find(dynamic_nx_trampoline) != -1:
                print("[*] Notice: AP trampoline dynamic CPUID NX detection is already installed.")
            else:
                print("[-] Warning: AP trampoline signature not found in hal.dll.")

    return data, report


@register_patcher("hal_nx")
def patch_hal_nx_file(
    input_path: str,
    output_path: str = None,
    patch_pte: bool = True,
    patch_ap_trampoline: bool = True,
    **kwargs
) -> bool:
    """
    Registered patch routine for Windows Hardware Abstraction Layer ('hal_nx').
    Disables PTE bit 63 setting and AP real-mode NXE initialization in hal.dll / halmacpi.dll.
    """
    if not os.path.exists(input_path):
        print(f"[-] Error: HAL file not found: {input_path}")
        return False

    if output_path is None:
        output_path = input_path

    print(f"[*] Reading HAL binary: {input_path}")
    with open(input_path, "rb") as f:
        data = bytearray(f.read())

    modified_data, report = patch_hal_nx_bytes(
        data,
        patch_pte=patch_pte,
        patch_ap_trampoline=patch_ap_trampoline
    )

    with open(output_path, "wb") as f:
        f.write(modified_data)

    print(f"[+] Written patched binary to: {output_path}")
    if fix_pe_checksum(output_path):
        print("[+] Recalculated and updated PE Checksum successfully.")
    return True
