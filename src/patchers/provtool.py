import os
import re
from . import register_patcher
from .pe import fix_pe_checksum


def patch_provtool_bytes(data: bytearray) -> tuple:
    """
    Patches provtool.exe by overwriting its PE entry point with:
      xor eax, eax  ; 31 C0 (return STATUS_SUCCESS / 0)
      ret           ; C3
    
    When Windows Setup executes provtool during the post-install specialize/OOBE pass,
    it immediately exits with return code 0, preventing the unhandled SSE4.2 CRC32
    illegal instruction crash in ntdll.dll while allowing Setup to cleanly finish.
    """
    if len(data) < 0x200 or data[:2] != b"MZ":
        raise ValueError("Invalid DOS header in provtool binary.")

    pe_off = struct.unpack("<I", data[0x3C:0x40])[0]
    if pe_off + 0x100 > len(data) or data[pe_off:pe_off+4] != b"PE\x00\x00":
        raise ValueError("Invalid PE header in provtool binary.")

    ep_rva = struct.unpack("<I", data[pe_off + 24 + 16 : pe_off + 24 + 20])[0]
    num_sections = struct.unpack("<H", data[pe_off + 6 : pe_off + 8])[0]
    opt_hdr_size = struct.unpack("<H", data[pe_off + 20 : pe_off + 22])[0]
    sec_table_off = pe_off + 24 + opt_hdr_size

    ep_file_off = None
    for i in range(num_sections):
        sec_off = sec_table_off + i * 40
        vsize, vrva, rsize, roff = struct.unpack("<IIII", data[sec_off + 8 : sec_off + 24])
        if vrva <= ep_rva < vrva + max(vsize, rsize):
            ep_file_off = roff + (ep_rva - vrva)
            break

    if ep_file_off is None or ep_file_off + 3 > len(data):
        raise ValueError(f"Could not map entry point RVA 0x{ep_rva:X} to file offset.")

    if data[ep_file_off:ep_file_off+3] == b"\x31\xC0\xC3":
        print(f"[*] Notice: provtool.exe entry point at offset 0x{ep_file_off:X} is already patched (31 C0 C3).")
        return data, True

    data[ep_file_off:ep_file_off+3] = b"\x31\xC0\xC3"
    print(f"[+] Patched provtool.exe entry point at offset 0x{ep_file_off:X} (31 C0 C3 -> xor eax, eax; ret).")
    return data, True


@register_patcher("provtool_exit")
def patch_provtool_file(input_path: str, output_path: str = None, **kwargs) -> bool:
    """
    Registered patch routine for Windows Provisioning Tool ('provtool_exit').
    Patches entry point to return 0, avoiding the ntdll SSE4.2 CRC32 crash.
    """
    if not os.path.exists(input_path):
        print(f"[-] Error: provtool file not found: {input_path}")
        return False

    if output_path is None:
        output_path = input_path

    print(f"[*] Reading provtool binary: {input_path}")
    with open(input_path, "rb") as f:
        data = bytearray(f.read())

    try:
        modified_data, success = patch_provtool_bytes(data)
    except Exception as e:
        print(f"[-] Error patching provtool: {e}")
        return False

    with open(output_path, "wb") as f:
        f.write(modified_data)

    print(f"[+] Written patched binary to: {output_path}")
    if fix_pe_checksum(output_path):
        print("[+] Recalculated and updated PE Checksum successfully.")
    return True
