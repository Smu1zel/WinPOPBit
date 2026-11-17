"""Local smoke test for the patcher package.

    python test_build.py <ntoskrnl.exe> [out.exe] [--amd]

Runs the fully automatic path (no manual RVAs): symbols are downloaded from
the Microsoft symbol server, the feature gates and cmpxchg16b sites are
derived from the image, and the result is written back with the signature
stripped and the PE checksum fixed.

--amd selects the AMD K8 profile:

  * shim_skip_lock15.bin  - reports success for user-mode addresses instead of
                            writing them (a write to a user page while the shim
                            lock is held can fault and hang the boot);
  * signature_gates=True  - also NOP the nine KiSetProcessorSignature
                            branches; on K8 one of them never returns.

Without --amd the Intel profile is used: shim_nest.bin (true read/write) and
the signature branches are kept.
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
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    amd = "--amd" in sys.argv
    if not args:
        print("usage: python test_build.py <ntoskrnl.exe> [out.exe] [--amd]")
        return 2
    src = args[0]
    dst = args[1] if len(args) > 1 else \
        os.path.join(os.path.dirname(src), "patched_test.exe")

    profile = {}
    if amd:
        profile = {"shim_blob": "shim_skip_lock15.bin",
                   "signature_gates": True}
    print("[*] input %s (%d bytes)" % (src, len(bytearray(open(src, "rb").read()))))
    print("[*] profile: %s" % ("AMD K8 - skip user addresses, all gates NOP"
                               if amd else
                               "Intel - true write, signature gates kept"))

    data = bytearray(open(src, "rb").read())
    out, report = kernel_cx16.patch_kernel_cx16_bytes(
        data, exe_path=src, verify_prefetchw=True, **profile)
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
