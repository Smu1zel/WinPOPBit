#!/usr/bin/env python3
"""
================================================================================
WinPOPBit: Windows 11 SSE4.2 Requirements Patcher & ISO Builder
================================================================================
This tool allows CPUs with POPCNT but WITHOUT SSE4.2 (such as AMD Phenom II,
Athlon II, and K10 family CPUs) to install and boot Windows 11 24H2 and beyond.

How it works:
1. Windows 11 24H2 introduced hard CPU instruction requirements checked by
   ntoskrnl.exe and winload.exe via RtlDetectProcessorFeatures.
2. In the Windows kernel, a 59-entry CPUID Requirements Table in .rdata defines
   mandatory CPU features. Entry #6 corresponds to CPUID Leaf 1, Subleaf 0, ECX
   Bit 20 (SSE4.2) with Flags set to 0x0000000D (Mandatory).
3. Flipping this Flags value from 0x0D to 0x0C converts the check into an
   optional feature, bypassing the unsupported processor check without breaking
   kernel stability (since the kernel itself does not execute SSE4.2 instructions).
4. WindowsCodecs.dll is replaced with a 23H2 build to prevent crashes on
   SSE4.1 PMOVSXBW instructions during Windows Setup execution.
5. The offline registry and BCD stores are configured with DISABLE_INTEGRITY_CHECKS
   and TESTSIGNING to allow running the modified kernel with driver signature
   enforcement disabled (via the legacy F8 boot menu or via an experimental patch;
   see badblobs.xml).
================================================================================
"""

import os
import sys
import argparse
import shutil

from src.utils import is_windows8_or_newer, require_admin, get_app_dir
from src.patchers import PATCHER_REGISTRY
from src.database import BlobDatabase
from src.iso import build_iso

if not is_windows8_or_newer():
    print("Error: Windows 8 or newer is required.")
    sys.exit(1)


class UnifiedArgumentParser(argparse.ArgumentParser):
    """
    Custom ArgumentParser that automatically appends full parameter documentation
    for all registered subcommands directly into the top-level --help output.
    """
    def format_help(self):
        base_help = super().format_help()
        if hasattr(self, '_subparsers_ref') and self._subparsers_ref:
            sections = []
            sections.append("\n" + "=" * 78)
            sections.append("DETAILED SUBCOMMAND PARAMETER REFERENCE")
            sections.append("=" * 78 + "\n")
            for name, sub in self._subparsers_ref.choices.items():
                sections.append(f"--- [ COMMAND: {name.upper()} ] " + "-" * (58 - len(name)))
                sections.append(sub.format_help())
            return base_help + "\n".join(sections)
        return base_help


def main():
    parser = UnifiedArgumentParser(
        prog="winpopbit.py",
        description="""
================================================================================
WinPOPBit: Windows 11 SSE4.2 Requirements Patcher & ISO Builder
================================================================================
Bypasses mandatory SSE4.2 CPU instruction requirements on Windows 11 (24H2+)
for CPUs with POPCNT (AMD Phenom II, Athlon II, K10, etc.) by converting
kernel CPUID table entries from mandatory (0x0D) to optional (0x0C).
""",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
================================================================================
COMMON USAGE EXAMPLES:
================================================================================
  # 1. Build a full bootable Windows 11 ISO patching only Windows 11 Pro (Index 6):
  python winpopbit.py build -i Win11_24H2_x64.iso -o Win11_Patched.iso --index 6

  # 2. Build ISO patching ONLY boot.wim (skipping install.wim entirely):
  python winpopbit.py build -i Win11_24H2_x64.iso --boot-only

  # 3. Build with custom XML profile:
  python winpopbit.py build -i Win11_24H2_x64.iso -c custom_badblobs.xml

  # 4. Patch a standalone kernel file using the registered 'kernel_sse42' patcher:
  python winpopbit.py patch kernel_sse42 -i C:\\path\\to\\ntoskrnl.exe

  # 5. Patch kernel to a separate file with custom options:
  python winpopbit.py patch kernel_sse42 -i ntoskrnl.exe -o ntoskrnl_debug.exe -O debug_loop=true -O patch_kiset=true

  # 6. Interactive wizard (prompts for ISO path and edition index):
  python winpopbit.py
        """
    )

    subparsers = parser.add_subparsers(dest="mode", help="Execution mode (run 'winpopbit.py <command> --help' for command-specific help)")
    parser._subparsers_ref = subparsers

    # Mode 1: PATCH (Standalone binary patcher)
    patch_parser = subparsers.add_parser(
        "patch",
        help="Directly patch an individual binary file using a registered patcher routine",
        description="Applies a registered patch routine (e.g. 'kernel_sse42') directly to an individual PE binary file."
    )
    patch_parser.add_argument("patcher", help="Registered patcher routine to execute (e.g. 'kernel_sse42'). Available: " + ", ".join(PATCHER_REGISTRY.keys()))
    patch_parser.add_argument("-i", "--input", required=True, metavar="PATH", help="Path to input PE binary to patch (e.g. C:\\path\\to\\ntoskrnl.exe)")
    patch_parser.add_argument("-o", "--output", default=None, metavar="PATH", help="Destination path for patched binary. If omitted, the input binary is modified and overwritten in-place. [Default: overwrite input]")
    patch_parser.add_argument("-O", "--option", action="append", default=[], metavar="KEY=VALUE", help="Pass options to the patcher routine (e.g. -O patch_kiset=true -O debug_loop=true). Can be specified multiple times.")

    # Mode 2: BUILD (Full ISO pipeline)
    build_parser = subparsers.add_parser(
        "build",
        help="Build an end-to-end bootable patched Windows 11 ISO (DISM + Blobs + Registry + BCD + oscdimg)",
        description="Automates the full ISO build pipeline using configurations from badblobs.xml: mounts/extracts ISO media, patches boot.wim, patches install.wim/install.esd, injects replacement blobs, configures offline registry and BCD stores, and masters a dual-boot (UEFI + BIOS) ISO."
    )
    build_parser.add_argument("-i", "--input-iso", required=True, metavar="PATH", help="Path to source Windows 11 installation ISO file or an extracted directory containing setup media")
    build_parser.add_argument("-o", "--output-iso", default="patched_install.iso", metavar="PATH", help="Destination path and filename for the generated bootable patched ISO. [Default: 'patched_install.iso']")
    build_parser.add_argument("-w", "--work-dir", default=None, metavar="DIR", help="Temporary directory for ISO file staging, WIM mounting, and registry hives. [Default: './build_workspace']")
    build_parser.add_argument("-c", "--config", default=None, metavar="XML", help="Path to badblobs.xml profile defining patch handlers, replacement blobs, targets, and BCD commands. [Default: './badblobs.xml']")
    build_parser.add_argument("-b", "--blobs-dir", default=None, metavar="DIR", help="Directory containing binary replacement files (e.g. 23H2 WindowsCodecs.dll). [Default: './blobs']")
    index_group = build_parser.add_mutually_exclusive_group()
    index_group.add_argument("--index", default=None, metavar="INDEX", help="Specific Windows edition index in install.wim to patch (e.g. '6' for Windows 11 Pro, 'all' for every edition, or 'none' to skip install.wim entirely). Mutually exclusive with --boot-only. [Default: 'all']")
    index_group.add_argument("--boot-only", action="store_true", help="Only patch boot.wim (Setup wizard) and completely skip install.wim. Mutually exclusive with --index.")
    build_parser.add_argument("--clean", action="store_true", help="Force clean extraction of source ISO (wipes existing workspace ISO files)")
    build_parser.add_argument("--allow-missing-blobs", action="store_true", help="Downgrade missing replacement blob errors from fatal failures to warnings. [Default: False (fail-fast validation)]")
    build_parser.add_argument("--oscdimg-path", default=None, metavar="PATH", help="Explicit path to oscdimg.exe. If omitted or outdated (< v2.55), automatically searches ADK/MiniTool/PATH or auto-downloads official Microsoft ADK v2.56 (~74 KB)")

    # Interactive prompt fallback when run with no arguments or double-clicked
    custom_args = None
    if len(sys.argv) == 1:
        print("="*70)
        print("WinPOPBit - The Windows 11 SSE4.2 and Windows 10 NX Requirements Patcher")
        print("="*70)
        print("[!] This flow has not been updated for Windows 10 patching just yet; use manual commands.")
        print("="*70)
        print("1. Build Patched ISO (Automated)")
        print("2. Patch standalone ntoskrnl.exe")
        print("3. Exit")
        choice = input("\nSelect an option [1-3]: ").strip()

        if choice == "1":
            iso_input = input("Enter path to Windows 11 ISO: ").strip().strip('"')
            if not iso_input or not os.path.exists(iso_input):
                print("[-] Error: ISO file not found.")
                sys.exit(1)

            idx_input = input("Enter OS Index to patch (e.g. 6 for Pro, 'all' for all editions, or 'none' for boot.wim only) [default: 1]: ").strip()
            if not idx_input:
                idx_input = "1"

            custom_args = ["build", "-i", iso_input, "--index", idx_input]
        elif choice == "2":
            k_input = input("Enter path to ntoskrnl.exe: ").strip().strip('"')
            if not k_input or not os.path.exists(k_input):
                print("[-] Error: Kernel file not found.")
                sys.exit(1)
            custom_args = ["patch", "kernel_sse42", "-i", k_input]
        else:
            sys.exit(0)

    args = parser.parse_args(custom_args)
    app_dir = get_app_dir()

    # -------------------------------------------------------------------------
    # Execute Mode 1: PATCH
    # -------------------------------------------------------------------------
    if args.mode == "patch":
        if args.patcher not in PATCHER_REGISTRY:
            print(f"[-] Error: Unknown patcher '{args.patcher}'. Available registered patchers: {list(PATCHER_REGISTRY.keys())}")
            sys.exit(1)

        # Parse key=value options from -O / --option
        options = {}
        for opt in args.option:
            if "=" in opt:
                k, v = opt.split("=", 1)
                k = k.strip()
                v = v.strip()
                if v.lower() == "true":
                    val = True
                elif v.lower() == "false":
                    val = False
                else:
                    try:
                        val = int(v)
                    except ValueError:
                        val = v
                options[k] = val
            else:
                options[opt.strip()] = True

        out_file = args.output if args.output else args.input

        print("="*70)
        print(f"WinPOPBit Standalone Patch Mode: '{args.patcher}'")
        print(f"  Target:     {args.input}")
        print(f"  Output:     {out_file}")
        if options:
            print(f"  Options:    {options}")
        print("="*70)

        handler = PATCHER_REGISTRY[args.patcher]
        success = handler(args.input, out_file, **options)
        sys.exit(0 if success else 1)

    # -------------------------------------------------------------------------
    # Execute Mode 2: BUILD
    # -------------------------------------------------------------------------
    elif args.mode == "build":
        if args.config:
            xml_path = args.config
        elif os.path.exists("badblobs.xml"):
            xml_path = os.path.abspath("badblobs.xml")
        else:
            xml_path = os.path.join(app_dir, "badblobs.xml")

        if args.blobs_dir:
            blobs_dir = args.blobs_dir
        elif os.path.isdir("blobs"):
            blobs_dir = os.path.abspath("blobs")
        else:
            blobs_dir = os.path.join(app_dir, "blobs")

        if args.work_dir:
            work_dir = args.work_dir
        else:
            work_dir = os.path.join(app_dir, "build_workspace")

        db = BlobDatabase(xml_path, blobs_dir)
        print(f"[*] Loaded {len(db.blobs)} blob entries from {xml_path}.")

        # Enforce fail-fast integrity validation
        if not db.validate(allow_missing=args.allow_missing_blobs):
            print("[-] Build aborted due to validation errors. Use --allow-missing-blobs to bypass.")
            sys.exit(1)

        # Resolve index and boot_only mode
        selected_index = None
        boot_only = args.boot_only

        if args.index is not None:
            idx_str = str(args.index).strip().lower()
            if idx_str in ("none", "0", "bootonly", "boot-only"):
                boot_only = True
                selected_index = None
            elif idx_str in ("all", "*"):
                selected_index = None
            else:
                try:
                    selected_index = int(idx_str)
                except ValueError:
                    print(f"[-] Error: Invalid index '{args.index}'. Must be a number (e.g. 6), 'all', or 'none'.")
                    sys.exit(1)

        build_iso(
            input_iso=args.input_iso,
            output_iso=args.output_iso,
            work_dir=work_dir,
            db=db,
            blobs_dir=blobs_dir,
            selected_index=selected_index,
            boot_only=boot_only,
            clean=args.clean,
            oscdimg_path=args.oscdimg_path
        )


if __name__ == '__main__':
    main()
