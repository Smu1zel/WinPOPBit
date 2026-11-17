import os
import sys
import struct
import capstone

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


def analyze_pe(pe_path):
    if not os.path.exists(pe_path):
        print(f"File not found: {pe_path}")
        return

    try:
        with open(pe_path, "rb") as f:
            dos_header = f.read(64)
            if len(dos_header) < 64 or dos_header[0:2] != b"MZ":
                print("Not a valid PE file.")
                return
            pe_offset = struct.unpack("<I", dos_header[0x3C:0x40])[0]
            f.seek(pe_offset)
            pe_sig = f.read(4)
            if pe_sig != b"PE\x00\x00":
                print("Not a valid PE signature.")
                return
            coff_header = f.read(20)
            machine, num_sections, _, _, _, size_optional_header, _ = struct.unpack(
                "<HHIIIHH", coff_header
            )

            # Read entry point address from optional header
            f.seek(
                pe_offset + 24 + 16
            )  # AddressOfEntryPoint is at offset 16 in Optional Header
            entry_point_rva = struct.unpack("<I", f.read(4))[0]

            f.seek(pe_offset + 24 + size_optional_header)

            text_section = None
            for _ in range(num_sections):
                sec_header = f.read(40)
                name = sec_header[0:8].rstrip(b"\x00").decode("latin1", errors="ignore")
                misc, va, size_raw, ptr_raw, _, _, _, _, _, _ = struct.unpack(
                    "<IIIIIIHHHH", sec_header[8:]
                )
                if name == ".text":
                    text_section = {
                        "name": name,
                        "va": va,
                        "size_raw": size_raw,
                        "ptr_raw": ptr_raw,
                    }

        if not text_section:
            print("No .text section found.")
            return

        with open(pe_path, "rb") as f:
            f.seek(text_section["ptr_raw"])
            text_bytes = f.read(text_section["size_raw"])

        print(f"\nAnalyzing: {os.path.basename(pe_path)}")
        print(f"  .text size: {len(text_bytes) / 1024:.2f} KB")
        print(f"  Entry Point RVA: 0x{entry_point_rva:X}")

        # Scan for SSE4.1/4.2 and AVX instructions
        unsupported_insts = []
        base_va = 0x140000000 + text_section["va"]

        # Disassemble the whole section to do full stats
        # (This is fast enough for single-file analysis)
        for insn in md.disasm(text_bytes, base_va):
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
                unsupported_insts.append(
                    (insn.address, insn.mnemonic, insn.op_str, matched_group)
                )

        total_unsupported = len(unsupported_insts)
        print(f"  Total unsupported instructions: {total_unsupported}")

        if total_unsupported == 0:
            print("  Conclusion: No SSE4/AVX baseline requirements. Clean!")
            return

        density = (total_unsupported / (len(text_bytes) / 1024)) * 100
        print(f"  Instruction Density: {density:.4f}% of instructions/KB")

        # Check if entry point falls near any unsupported instructions
        # Entry point function is usually in the first few KB
        entry_va = 0x140000000 + entry_point_rva
        entry_hits = [
            inst
            for inst in unsupported_insts
            if entry_va <= inst[0] < entry_va + 0x1000
        ]

        print(
            f"  Unsupported instructions near Entry Point (first 4KB): {len(entry_hits)}"
        )
        for addr, mnem, op, grp in entry_hits[:5]:
            print(f"    [0x{addr:X}] {mnem} {op} ({grp})")

        # Determine clustering (Spread vs Clustered)
        # We calculate the span of addresses that contain these instructions
        if total_unsupported > 1:
            addresses = [inst[0] for inst in unsupported_insts]
            addr_span = addresses[-1] - addresses[0]
            span_ratio = addr_span / len(text_bytes)
            print(f"  Address Span Ratio: {span_ratio * 100:.2f}% of the .text section")

            if density > 0.05 or len(entry_hits) > 0 or span_ratio > 0.8:
                print(
                    "  Conclusion: High probability of UNCONDITIONAL SSE4.1/4.2 compilation (e.g. /arch:SSE4.1)."
                )
            else:
                print(
                    "  Conclusion: High probability of DYNAMIC DISPATCH (instructions are clustered/isolated)."
                )
        else:
            print("  Conclusion: Single instruction found. Likely dynamic dispatch.")

    except Exception as e:
        print(f"Error analyzing PE: {e}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python check_dll_dispatch.py <dll_path>")
    else:
        analyze_pe(sys.argv[1])
