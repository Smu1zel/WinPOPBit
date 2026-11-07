"""Local smoke test for the patcher package.

    python test_build.py <ntoskrnl.exe> [out.exe]

Runs the fully automatic path (no manual RVAs): symbols are downloaded from
the Microsoft symbol server, the feature gates and cmpxchg16b sites are
derived from the image, and the result is written back with the signature
stripped and the PE checksum fixed.
"""

import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from src.patchers import kernel_cx16                      # noqa: E402


def strip_and_sum(path):
    d = bytearray(open(path, "rb").read())
    e0 = struct.unpack_from("<I", d, 0x3C)[0]
    struct.pack_into("<II", d, e0 + 24 + 112 + 32, 0, 0)      # certificate dir
    cs = e0 + 24 + 64
    struct.pack_into("<I", d, cs, 0)
    t = 0
    for i in range(0, len(d), 2):
        t += d[i] | (d[i + 1] << 8)
        t = (t & 0xFFFF) + (t >> 16)
    t = (t & 0xFFFF) + (t >> 16)
    struct.pack_into("<I", d, cs, (t + len(d)) & 0xFFFFFFFF)
    open(path, "wb").write(d)
    return struct.unpack_from("<I", d, cs)[0]


def main():
    src = sys.argv[1]
    dst = sys.argv[2] if len(sys.argv) > 2 else \
        os.path.join(os.path.dirname(src), "patched_test.exe")

    data = bytearray(open(src, "rb").read())
    print("[*] input %s (%d bytes)" % (src, len(data)))
    out, report = kernel_cx16.patch_kernel_cx16_bytes(
        data, exe_path=src, verify_prefetchw=True)
    open(dst, "wb").write(out)
    csum = strip_and_sum(dst)

    print("\n[+] written %s" % dst)
    print("[+] checksum 0x%08X" % csum)
    print("[+] report:")
    for k, v in report.items():
        print("      %-24s %s" % (k, v))

    ok = (report["prefetchw_sites"] > 0 and report["cx16_sites_patched"] > 0
          and report["trampoline_installed"])
    print("\n[%s] automatic build looks %s"
          % ("PASS" if ok else "FAIL", "complete" if ok else "incomplete"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
