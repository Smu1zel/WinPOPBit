"""Smoke test for the winload patcher.

    python test_winload.py <winload.exe|winload.efi> [out.exe]

Checks that the two things that matter for a CPU without PREFETCHW are
applied:

  1. `ImgpFilterValidationFailure` is forced to return success, so a patched
     ntoskrnl is not rejected with STATUS_INVALID_IMAGE_HASH;
  2. every PREFETCHW is rewritten - winload runs it before the kernel installs
     an IDT, which is a silent reset with no bugcheck on Pentium 4 and the
     first Socket 754 Athlon 64.

The boot-option NOPs are reported but not required: they only save the user
from having to set `nointegritychecks`/`testsigning` by hand.
"""

import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from src.patchers import winload                        # noqa: E402


def strip_and_sum(path):
    d = bytearray(open(path, "rb").read())
    e0 = struct.unpack_from("<I", d, 0x3C)[0]
    struct.pack_into("<II", d, e0 + 24 + 112 + 32, 0, 0)
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
        os.path.join(os.path.dirname(src), "winload_test.exe")

    data = bytearray(open(src, "rb").read())
    print("[*] input %s (%d bytes)" % (src, len(data)))
    out, report = winload.patch_winload_bytes(data, verify_prefetchw=True)
    open(dst, "wb").write(out)
    csum = strip_and_sum(dst)

    print("\n[+] written %s" % dst)
    print("[+] checksum 0x%08X" % csum)
    print("[+] report:")
    for k, v in report.items():
        print("      %-28s %s" % (k, v))

    ci = report.get("ci_filter_patched") or report.get("ci_filter_already_patched")
    pw = report.get("prefetchw_sites", 0)
    ok = bool(ci) and pw >= 1
    if not ci:
        print("[-] ImgpFilterValidationFailure was not found - a patched kernel"
              " will be rejected with STATUS_INVALID_IMAGE_HASH")
    if pw < 1:
        print("[-] no PREFETCHW found - either the image has none (fine on a"
              " CPU that supports it) or the scan missed them")
    print("\n[%s] winload build looks %s"
          % ("PASS" if ok else "FAIL", "complete" if ok else "incomplete"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
