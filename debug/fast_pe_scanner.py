import os
import sys
import struct
import capstone
import time

# Initialize Capstone
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True

unsupported_group_names = {"sse41", "sse42", "avx", "avx2", "avx512", "aes", "pclmul"}
sse4_mnemonics = {
    "mpsadbw",
    "phminposuw",
    "pmulld",
    "pmuldq",
    "dpps",
    "dppd",
    "blendps",
    "blendpd",
    "blendvps",
    "blendvpd",
    "pblendw",
    "pblendvb",
    "insertps",
    "pinsrb",
    "pinsrd",
    "pinsrq",
    "extractps",
    "pextrb",
    "pextrd",
    "pextrq",
    "pmovsxbw",
    "pmovsxbd",
    "pmovsxbq",
    "pmovsxwd",
    "pmovsxwq",
    "pmovsxdq",
    "pmovzxbw",
    "pmovzxbd",
    "pmovzxbq",
    "pmovzxwd",
    "pmovzxwq",
    "pmovzxdq",
    "ptest",
    "pcmpeqq",
    "packusdw",
    "pminsb",
    "pmaxsb",
    "pminuw",
    "pmaxuw",
    "pminud",
    "pmaxud",
    "pminsd",
    "pmaxsd",
    "roundps",
    "roundpd",
    "roundss",
    "roundsd",
    "movntdqa",
    "pcmpestri",
    "pcmpestrm",
    "pcmpistri",
    "pcmpistrm",
    "pcmpgtq",
}


def scan_pe_file(pe_path):
    try:
        with open(pe_path, "rb") as f:
            dos_header = f.read(64)
            if len(dos_header) < 64 or dos_header[0:2] != b"MZ":
                return None

            pe_offset = struct.unpack("<I", dos_header[0x3C:0x40])[0]
            f.seek(pe_offset)
            pe_sig = f.read(4)
            if pe_sig != b"PE\x00\x00":
                return None

            coff_header = f.read(20)
            machine, num_sections, _, _, _, size_optional_header, _ = struct.unpack(
                "<HHIIIHH", coff_header
            )

            if machine != 0x8664:  # AMD64 check
                return None

            f.seek(pe_offset + 24 + size_optional_header)

            sections = []
            text_section = None
            for _ in range(num_sections):
                sec_header = f.read(40)
                if len(sec_header) < 40:
                    break
                name = sec_header[0:8].rstrip(b"\x00").decode("latin1", errors="ignore")
                misc, va, size_raw, ptr_raw, _, _, _, _, _, _ = struct.unpack(
                    "<IIIIIIHHHH", sec_header[8:]
                )
                sec_info = {
                    "name": name,
                    "va": va,
                    "size_raw": size_raw,
                    "ptr_raw": ptr_raw,
                }
                sections.append(sec_info)
                if name == ".text":
                    text_section = sec_info

        if not text_section or text_section["ptr_raw"] == 0:
            return None

        with open(pe_path, "rb") as f:
            f.seek(text_section["ptr_raw"])
            text_bytes = f.read(text_section["size_raw"])

        # Fast byte signature matching for candidates:
        # F3 0F B8 (POPCNT - Phenom supports this, skip)
        # 0F 38 (SSE4.1/4.2/AES/PCLMULQDQ)
        # 0F 3A (SSE4.1/4.2)
        # C4, C5 (AVX VEX Prefixes)
        # 62 (AVX-512 EVEX Prefix)

        pos = 0
        size = len(text_bytes)
        base_va = 0x140000000 + text_section["va"]

        while pos < size:
            # Find next potential signature offset
            # We search for 0F 38, 0F 3A, C4, C5, 62
            idx_38 = text_bytes.find(b"\x0f\x38", pos)
            idx_3A = text_bytes.find(b"\x0f\x3a", pos)
            idx_C4 = text_bytes.find(b"\xc4", pos)
            idx_C5 = text_bytes.find(b"\xc5", pos)
            idx_62 = text_bytes.find(b"\x62", pos)

            indices = [i for i in [idx_38, idx_3A, idx_C4, idx_C5, idx_62] if i != -1]
            if not indices:
                break

            idx = min(indices)

            # Disassemble a small 15-byte window at this offset to confirm
            chunk = text_bytes[idx : idx + 15]
            va = base_va + idx

            for insn in md.disasm(chunk, va):
                if insn.address == va:
                    is_unsupported = False
                    matched_group = ""
                    for group in insn.groups:
                        group_name = insn.group_name(group).lower()
                        for unsup in unsupported_group_names:
                            if unsup in group_name:
                                is_unsupported = True
                                matched_group = group_name
                                break
                        if is_unsupported:
                            break

                    if not is_unsupported:
                        mnemonic = insn.mnemonic.lower()
                        if mnemonic in sse4_mnemonics:
                            is_unsupported = True
                            matched_group = "sse4 (mnemonic)"

                    if is_unsupported:
                        return {
                            "va": insn.address,
                            "mnemonic": insn.mnemonic,
                            "op_str": insn.op_str,
                            "group": matched_group,
                            "bytes": insn.bytes.hex().upper(),
                        }
                break  # Only verify the first instruction at the candidate offset

            pos = idx + 1

        return None
    except Exception:
        return None


def scan_directory(target_dir):
    print(f"Scanning directory: {target_dir}")
    start_time = time.time()

    bad_files = []
    scanned_count = 0

    for root, dirs, files in os.walk(target_dir):
        for file in files:
            if file.lower().endswith((".exe", ".dll")):
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, target_dir)
                scanned_count += 1

                res = scan_pe_file(full_path)
                if res:
                    bad_files.append((rel_path, res))
                    print(
                        f"  [BAD] {rel_path} -> {res['mnemonic']} {res['op_str']} ({res['group']})"
                    )

    duration = time.time() - start_time
    print(f"\nScan complete in {duration:.2f} seconds.")
    print(
        f"Scanned {scanned_count} files. Found {len(bad_files)} files containing unsupported instructions."
    )
    return bad_files


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python fast_pe_scanner.py <directory_to_scan>")
    else:
        scan_directory(sys.argv[1])
