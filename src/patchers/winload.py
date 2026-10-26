import os
import re
from . import register_patcher
from .pe import fix_pe_checksum


def patch_winload_bytes(data: bytearray, patch_ci_filter: bool = True, patch_boot_options: bool = True) -> tuple:
    """
    Applies the winload Code Integrity (CI) and boot options bypass modifications:
    
    1. ImgpFilterValidationFailure -> xor eax, eax; ret (31 C0 C3):
       Forces the Code Integrity validation filter to return STATUS_SUCCESS (0),
       preventing winload from rejecting the patched ntoskrnl.exe binary.
       
    2. BlRemoveBootOption Stripping NOPs:
       NOPs out calls to BlRemoveBootOption that strip critical boot options:
       - 0x16000048: nointegritychecks
       - 0x260000E1: testsigning
       Preserving these options avoids having to enter the legacy F8 menu on every boot.
    """
    report = {
        "ci_filter_patched": False,
        "ci_filter_already_patched": False,
        "nointegritychecks_patched": False,
        "testsigning_patched": False
    }

    # 1. Patch ImgpFilterValidationFailure
    if patch_ci_filter:
        # Signature matching the function prologue of ImgpFilterValidationFailure:
        # 48 8B C4 48 89 58 08 48 89 68 10 48 89 70 18 48 89 78 20 41 56 48 83 EC 40
        filter_sig = bytes.fromhex("488BC44889580848896810488970184889782041564883EC40")
        filter_idx = data.find(filter_sig)
        if filter_idx != -1:
            data[filter_idx : filter_idx + 3] = bytes.fromhex("31C0C3")
            report["ci_filter_patched"] = True
            print(f"[+] Patched ImgpFilterValidationFailure at offset 0x{filter_idx:X} (31 C0 C3 -> force STATUS_SUCCESS).")
        else:
            if (data.find(bytes.fromhex("31C0C348895808")) != -1 or 
                data.find(bytes.fromhex("31C0C348896810")) != -1):
                report["ci_filter_already_patched"] = True
                print("[*] Notice: ImgpFilterValidationFailure is already patched (31 C0 C3).")
            else:
                print("[-] Warning: ImgpFilterValidationFailure signature not found in winload binary.")

    # 2. Patch BlRemoveBootOption calls
    if patch_boot_options:
        # 2a. Option 0x16000048 (nointegritychecks)
        sig_opt1 = bytes.fromhex("BA48000016")
        idx1 = data.find(sig_opt1)
        if idx1 != -1:
            for i in range(idx1, min(idx1 + 20, len(data))):
                if data[i] == 0xE8:
                    data[i : i + 5] = b'\x90' * 5
                    report["nointegritychecks_patched"] = True
                    print(f"[+] NOPed out BlRemoveBootOption(nointegritychecks) call at offset 0x{i:X}.")
                    break
        else:
            print("[-] Notice: nointegritychecks (0x16000048) removal signature not found.")

        # 2b. Option 0x260000E1 (testsigning)
        sig_opt2 = bytes.fromhex("BAE1000026")
        idx2 = data.find(sig_opt2)
        if idx2 != -1:
            for i in range(idx2, min(idx2 + 20, len(data))):
                if data[i] == 0xE8:
                    data[i : i + 5] = b'\x90' * 5
                    report["testsigning_patched"] = True
                    print(f"[+] NOPed out BlRemoveBootOption(testsigning) call at offset 0x{i:X}.")
                    break
        else:
            print("[-] Notice: testsigning (0x260000E1) removal signature not found.")

    return data, report


@register_patcher("winload")
def patch_winload_file(input_path: str, output_path: str = None, patch_ci_filter: bool = True, patch_boot_options: bool = True, **kwargs) -> bool:
    """
    Registered patch routine for Windows Boot Loader ('winload').
    Reads winload.exe or winload.efi, applies CI filter and boot option patches,
    writes output, and recalculates PE checksum.
    """
    if not os.path.exists(input_path):
        print(f"[-] Error: Winload file not found: {input_path}")
        return False

    if output_path is None:
        output_path = input_path

    print(f"[*] Reading winload binary: {input_path}")
    with open(input_path, "rb") as f:
        data = bytearray(f.read())

    modified_data, report = patch_winload_bytes(data, patch_ci_filter, patch_boot_options)

    with open(output_path, "wb") as f:
        f.write(modified_data)

    print(f"[+] Written patched binary to: {output_path}")
    if fix_pe_checksum(output_path):
        print("[+] Recalculated and updated PE Checksum successfully.")
    return True
