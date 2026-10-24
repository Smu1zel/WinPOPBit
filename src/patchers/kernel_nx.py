import os
import re
import struct
from . import register_patcher
from .pe import fix_pe_checksum


def patch_kernel_nx_bytes(data: bytearray, patch_nx: bool = True, enable_debug: bool = False) -> tuple:
    """
    Applies the NX (No-Execute) requirement bypass patch to a raw 32-bit x86 Windows NT kernel bytearray:
    
    In KiInitializeProcessor, the kernel verifies that mandatory CPU features are present:
      mov ecx, 0x20013cb6
      and eax, ecx
      cmp eax, ecx
      jne BugCheck  ; 0x5D on BSP, 0x3E on APs
      
    Bit 29 (0x20000000) corresponds to KF_NX. If the CPU lacks NX/XD support, this check fails.
    Changing the mask from 0x20013CB6 to 0x00013CB6 (B9 B6 3C 01 20 -> B9 B6 3C 01 00) converts
    KF_NX into an optional feature, allowing the system to boot without NX.
    """
    report = {
        "nx_patched": False,
        "debug_loop_patched": False
    }

    if patch_nx:
        # Signature: mov ecx, 0x20013cb6; and eax, ecx; cmp eax, ecx
        pattern_0x20 = re.compile(b'\xB9\xB6\x3C\x01\x20\x23\xC1\x3B\xC1')
        pattern_0x00 = re.compile(b'\xB9\xB6\x3C\x01\x00\x23\xC1\x3B\xC1')

        matches = list(pattern_0x20.finditer(data))
        if matches:
            for m in matches:
                start = m.start()
                data[start + 4] = 0x00
                print(f"[+] Patched KiInitializeProcessor mandatory feature mask at offset 0x{start:X} (0x20013CB6 -> 0x00013CB6).")
            report["nx_patched"] = True
        else:
            already_patched = list(pattern_0x00.finditer(data))
            if already_patched:
                report["nx_patched"] = True
                print("[*] Notice: KiInitializeProcessor mandatory feature mask is already patched (0x00013CB6).")
            else:
                print("[-] Warning: Mandatory NX feature check signature (0x20013CB6) not found in binary.")

        # 2. MmProtectToPteMask XD Bit 63 Suppression:
        # Windows 10 hardcodes 0x8000000000000000 into the static table MmProtectToPteMask
        # for all 16 non-executable page protections. On CPUs without NX, bit 63 is an illegal
        # reserved bit in PAE mode. The instant the kernel touches any non-executable page (pools,
        # stacks, shared user data), a #PF (RSVD) fault is triggered.
        # Clearing bit 63 on all 32 entries (256 bytes) stops the kernel from ever setting bit 63.
        sig_table = bytes.fromhex("0000000000000080000000000000008000000000000000000000000000000000")
        p_table = data.find(sig_table)
        if p_table != -1:
            cleared_entries = 0
            for i in range(32):
                high_off = p_table + i * 8 + 4
                if data[high_off + 3] & 0x80:
                    data[high_off + 3] &= 0x7F
                    cleared_entries += 1
            report["pte_mask_cleared"] = True
            print(f"[+] Cleared bit 63 from {cleared_entries} entries in MmProtectToPteMask at offset 0x{p_table:X}.")
        else:
            sig_table_patched = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000000")
            if data.find(sig_table_patched) != -1:
                print("[*] Notice: MmProtectToPteMask entries already have bit 63 cleared.")
            else:
                print("[-] Warning: MmProtectToPteMask signature not found in kernel binary.")

        # 3. Suppress forced XD bit writes in shadow PTE routines (MiWritePteShadow, MiInitializeSharedUserData):
        # Pattern: 83 C8 00 74 28 81 CA 00 00 00 80 -> NOP 6 bytes of 'or edx, 0x80000000'
        pat_shadow = bytes.fromhex("83C800742881CA00000080")
        shadow_matches = list(re.finditer(re.escape(pat_shadow), bytes(data)))
        if shadow_matches:
            for sm in shadow_matches:
                s_off = sm.start() + 5
                data[s_off : s_off + 6] = b'\x90' * 6
                print(f"[+] NOPed out forced XD bit write in shadow PTE routine at offset 0x{s_off:X}.")
            report["shadow_xd_patched"] = True

        # 4. Suppress shifted XD bit writes (or edx, 0xFF800000; ...; shld edx, eax, 8):
        # In MiProtectSharedUserPage and other PTE constructors, the compiler sets
        # 0xFF800000 in edx and shifts it left by 8 via 'shld edx, eax, 8' (0xFF800000 << 8 = 0x80000000).
        # Changing 0xFF800000 to 0xFF000000 causes all 8 bits to shift out, leaving bit 31 = 0
        pat_shld_nx = re.compile(rb'(\x81\xCA\x00\x00)\x80(\xFF.{0,12}\x0F\xA4\xC2\x08)', re.DOTALL)
        shld_matches = list(pat_shld_nx.finditer(data))
        if shld_matches:
            for m in shld_matches:
                # Offset +4 is the 0x80 byte in '81 CA 00 00 80 FF'
                byte_off = m.start() + 4
                data[byte_off] = 0x00
                print(f"[+] Cleared shifted NX bit (0xFF800000 -> 0xFF000000) at offset 0x{byte_off:X}.")
            report["shld_nx_patched"] = True

        # 5. Suppress forced XD bit writes in Memory Manager PTE routines (Mi* / Mm*):
        # Blanket NOPing of '81 C9 00 00 00 80' (or ecx, 0x80000000) causes severe collateral damage:
        # it corrupts heap allocations (RtlpHpEnvAllocVA -> MEMORY_MANAGEMENT BSOD), processor initialization
        # (KiInitializeKernel), power dispatcher (PopEsWorkItemSchedule), and read-only strings.
        # Instead, we surgically match the actual Memory Manager PTE operations:
        # - MiMarkBootKernelStack (initial kernel stack protection)
        # - MmFreeLoaderBlock (converting loader memory blocks to system pages during boot)
        # - MiPerformSafePdeWrite (atomic 64-bit cmpxchg8b PDE writer)
        # - General PTE high DWORD loads: mov ecx, [reg+4]; or ecx, 0x80000000
        # - Shadow PTE with ecx (MiAllocateWsle, MiMakePageAvoidRead)
        mm_pte_patterns = [
            # MiMarkBootKernelStack: or eax, 0x62; or ecx, 0x80000000
            (re.compile(rb'(\x83\xC8\x62)\x81\xC9\x00\x00\x00\x80'), 3, "MiMarkBootKernelStack"),
            # MmFreeLoaderBlock (3 distinct boot-time memory conversion sites)
            (re.compile(rb'(\x8B\x48\x04)\x81\xC9\x00\x00\x00\x80'), 3, "MmFreeLoaderBlock[1]"),
            (re.compile(rb'(\x8B\x4C\x01\x04)\x81\xC9\x00\x00\x00\x80'), 4, "MmFreeLoaderBlock[2]"),
            (re.compile(rb'(\x8B\x0A)\x81\xC9\x00\x00\x00\x80\x83\xE8\x01'), 2, "MmFreeLoaderBlock[3]"),
            # MiPerformSafePdeWrite: atomic 64-bit cmpxchg8b PDE writer
            (re.compile(rb'\x81\xC9\x00\x00\x00\x80\xEB\xA9'), 0, "MiPerformSafePdeWrite"),
            # General PTE high DWORD loads: mov ecx, dword ptr [reg+4]; or ecx, 0x80000000
            (re.compile(rb'(\x8B[\x48\x49\x4A\x4B\x4E\x4F]\x04)\x81\xC9\x00\x00\x00\x80'), 3, "PteHighDwordLoad"),
            # Shadow PTE with ecx (MiAllocateWsle, MiMakePageAvoidRead)
            (re.compile(rb'(\x83\xC8\x00\x74[\x20-\x30].{1,6})\x81\xC9\x00\x00\x00\x80'), -6, "ShadowPteEcx"),
            # MiAllocateWsle: mov edi, [ebp+0x1c]; or edi, 0x80000000 (prepares PTE high DWORD)
            (re.compile(rb'(\x8B\x7D\x1C)\x81\xCF\x00\x00\x00\x80'), 3, "MiAllocateWsle[edi]"),
        ]

        patched_pte_sites = 0
        already_patched_pte = 0
        seen_offsets = set()

        for pat, offset_adj, desc in mm_pte_patterns:
            for m in pat.finditer(data):
                k_off = m.end() + offset_adj if offset_adj < 0 else m.start() + offset_adj
                if k_off not in seen_offsets:
                    seen_offsets.add(k_off)
                    if data[k_off] == 0x81 and data[k_off + 1] in (0xC9, 0xCF) and data[k_off + 2 : k_off + 6] == b'\x00\x00\x00\x80':
                        data[k_off : k_off + 6] = b'\x90' * 6
                        patched_pte_sites += 1
                        print(f"[+] NOPed out forced XD bit write in {desc} at offset 0x{k_off:X}.")
                    elif data[k_off : k_off + 6] == b'\x90' * 6:
                        already_patched_pte += 1

        if patched_pte_sites > 0 or already_patched_pte > 0:
            report["mm_pte_xd_patched"] = True
            print(f"[+] Memory Manager PTE XD bit suppression applied to {patched_pte_sites} sites ({already_patched_pte} already patched).")

    # Optional KeBugCheckEx infinite loop patch (EB FE) for QEMU GDB debugging
    if enable_debug:
        try:
            pe = pefile.PE(data=bytes(data))
            kbc_rva = None
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if exp.name and exp.name.decode('latin1', errors='ignore') == 'KeBugCheckEx':
                        kbc_rva = exp.address
                        break
            if kbc_rva:
                kbc_offset = pe.get_offset_from_rva(kbc_rva)
                data[kbc_offset : kbc_offset + 2] = b'\xEB\xFE'
                report["debug_loop_patched"] = True
                print(f"[+] Patched KeBugCheckEx at offset 0x{kbc_offset:X} (RVA 0x{kbc_rva:X}) to EB FE infinite loop.")
            pe.close()
        except Exception as e:
            print(f"[-] Warning: Failed to patch KeBugCheckEx debug loop: {e}")

    return data, report


@register_patcher("kernel_nx")
def patch_kernel_nx_file(input_path: str, output_path: str = None, patch_nx: bool = True, debug_loop: bool = False, enable_debug: bool = False, **kwargs) -> bool:
    """
    Registered patch routine for Windows Kernel ('kernel_nx').
    Patches KiInitializeProcessor to allow booting Windows 10 x86 without the NX (No-Execute) bit.
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

    modified_data, report = patch_kernel_nx_bytes(data, patch_nx, is_debug)

    with open(output_path, "wb") as f:
        f.write(modified_data)

    print(f"[+] Written patched binary to: {output_path}")
    if fix_pe_checksum(output_path):
        print("[+] Recalculated and updated PE Checksum successfully.")
    return True
