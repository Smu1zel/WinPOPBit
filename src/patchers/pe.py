import ctypes
import pefile


def fix_pe_checksum(file_path: str) -> bool:
    """
    Calculates and updates the PE OptionalHeader.CheckSum using Microsoft imagehlp.dll
    (MapFileAndCheckSumW). Windows kernel-mode binaries (ntoskrnl.exe, drivers, hal.dll)
    require a valid PE CheckSum; otherwise, the Windows Boot Manager (winload.exe)
    will refuse to load the image and trigger a 0xc0000221 STATUS_IMAGE_CHECKSUM_MISMATCH.
    """
    try:
        # Load imagehlp.dll from system32
        imagehlp = ctypes.windll.imagehlp
        imagehlp.MapFileAndCheckSumW.argtypes = [
            ctypes.c_wchar_p,
            ctypes.POINTER(ctypes.c_ulong),
            ctypes.POINTER(ctypes.c_ulong)
        ]
        imagehlp.MapFileAndCheckSumW.restype = ctypes.c_ulong
        
        orig_sum = ctypes.c_ulong(0)
        new_sum = ctypes.c_ulong(0)
        
        # CHECKSUM_SUCCESS is 0
        status = imagehlp.MapFileAndCheckSumW(file_path, ctypes.byref(orig_sum), ctypes.byref(new_sum))
        
        if status == 0:
            # Write calculated checksum directly to OptionalHeader.CheckSum in PE header
            with open(file_path, "r+b") as f:
                f.seek(0x3C) # e_lfanew offset in DOS header
                pe_offset = int.from_bytes(f.read(4), "little")
                f.seek(pe_offset)
                sig = f.read(4)
                if sig == b'PE\x00\x00':
                    # OptionalHeader.CheckSum is at offset 64 (0x40) from start of OptionalHeader
                    # PE signature (4) + FileHeader (20) + 64 = pe_offset + 88
                    checksum_offset = pe_offset + 24 + 64
                    f.seek(checksum_offset)
                    f.write(new_sum.value.to_bytes(4, "little"))
                    return True
    except Exception as e:
        print(f"[-] imagehlp.dll checksum calculation failed ({e}). Attempting pefile fallback...")

    # Fallback using pefile library if imagehlp is unavailable
    try:
        pe = pefile.PE(file_path)
        pe.OPTIONAL_HEADER.CheckSum = pe.generate_checksum()
        pe.write(file_path)
        pe.close()
        return True
    except Exception as e:
        print(f"[-] Failed to update PE CheckSum: {e}")
        return False
