import os
import sys
import subprocess
import shutil
import re
import urllib.request
import shlex
from .utils import get_app_dir, clear_readonly, safe_replace_file, take_ownership_and_grant, require_admin
from .wim import WimMountSession
from .database import BlobDatabase, DEFAULT_BCD_COMMANDS


def get_oscdimg_version(bin_path: str) -> float:
    """
    Returns the oscdimg version as a float (e.g. 2.56, 2.55) or 0.0 if cannot be determined.
    v2.55 or higher is strictly required for El Torito multi-platform UEFI + BIOS bootdata.
    """
    if not bin_path or not os.path.exists(bin_path):
        return 0.0
    try:
        res = subprocess.run([bin_path], capture_output=True, text=True)
        m = re.search(r"(?i)OSCDIMG\s+([0-9]+\.[0-9]+)", res.stdout)
        if m:
            return float(m.group(1))
    except Exception:
        pass
    return 0.0


def download_adk_oscdimg(target_dir: str) -> str:
    """
    Downloads the official Microsoft ADK oscdimg cabinet (~74 KB) directly from
    Microsoft CDN and extracts oscdimg.exe (x64 v2.56) using Windows built-in expand.exe.
    
    This eliminates the need to bundle third-party copyrighted binaries or install
    the full 5 GB Windows ADK suite.
    """
    os.makedirs(target_dir, exist_ok=True)
    out_exe = os.path.join(target_dir, "oscdimg.exe")

    # Check if already present and valid
    if os.path.exists(out_exe) and get_oscdimg_version(out_exe) >= 2.55:
        return out_exe

    cab_url = "http://download.microsoft.com/download/2/d/9/2d9c8902-3fcd-48a6-a22a-432b08bed61e/ADK/Installers/bbf55224a0290f00676ddc410f004498.cab"
    temp_cab = os.path.join(target_dir, "oscdimg_adk.cab")
    temp_extract = os.path.join(target_dir, "temp_expand")

    print("[*] Compatible oscdimg (v2.55+) not found locally.")
    print("[*] Downloading official Microsoft ADK Deployment payload (~74 KB) from Microsoft CDN...")

    req = urllib.request.Request(cab_url, headers={"User-Agent": "Burn"})
    try:
        with urllib.request.urlopen(req) as resp, open(temp_cab, "wb") as f:
            f.write(resp.read())
        print("[+] Download complete. Extracting oscdimg.exe using expand.exe...")

        os.makedirs(temp_extract, exist_ok=True)
        subprocess.run(["expand.exe", temp_cab, "-F:*", temp_extract], check=True, stdout=subprocess.DEVNULL)

        # Raw payload filename inside Microsoft ADK cabinet
        raw_payload = os.path.join(temp_extract, "fild40c79d789d460e48dc1cbd485d6fc2e")
        if os.path.exists(raw_payload):
            safe_replace_file(raw_payload, out_exe)
            ver = get_oscdimg_version(out_exe)
            print(f"[+] Successfully extracted and configured: {out_exe} (v{ver})")
            return out_exe
        else:
            raise RuntimeError("Expected payload binary not found in extracted cabinet.")
    except Exception as e:
        print(f"[-] Failed to download/extract ADK oscdimg from Microsoft CDN: {e}")
        return None
    finally:
        # Clean up temporary cabinet and extraction files
        if os.path.exists(temp_cab):
            try: os.remove(temp_cab)
            except Exception: pass
        if os.path.exists(temp_extract):
            shutil.rmtree(temp_extract, ignore_errors=True)


def find_oscdimg(custom_path: str = None) -> str:
    """
    Locates the Microsoft CD/DVD mastering utility (oscdimg.exe).
    
    1. Validates custom_path if specified (must be >= 2.55).
    2. Checks local ./tools/oscdimg.exe directory.
    3. Searches Windows ADK installations, MiniTool, and system PATH.
    4. If found version is < 2.55, warns the user that El Torito dual-boot is unsupported.
    5. If not found or too old, automatically downloads the 74 KB ADK payload from Microsoft.
    """
    app_dir = get_app_dir()
    tools_dir = os.path.join(app_dir, "tools")
    local_tool = os.path.join(tools_dir, "oscdimg.exe")

    # 1. User-supplied custom path
    if custom_path and os.path.exists(custom_path):
        ver = get_oscdimg_version(custom_path)
        if ver >= 2.55:
            return custom_path
        print(f"[-] Warning: Custom oscdimg at '{custom_path}' is version {ver} (< 2.55).")

    # 2. Local tools directory
    if os.path.exists(local_tool):
        ver = get_oscdimg_version(local_tool)
        if ver >= 2.55:
            return local_tool

    # 3. Standard system locations
    candidates = [
        r"C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\amd64\oscdimg.exe",
        r"C:\Program Files\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\amd64\oscdimg.exe",
        r"C:\Program Files (x86)\Windows Kits\11\Assessment and Deployment Kit\Deployment Tools\amd64\oscdimg.exe",
        r"C:\Program Files\MiniTool Partition Wizard 13\oscdimg.exe",
        r"C:\Program Files\MiniTool Partition Wizard 12\oscdimg.exe"
    ]
    path_which = shutil.which("oscdimg.exe")
    if path_which and path_which not in candidates:
        candidates.append(path_which)

    for p in candidates:
        if os.path.exists(p):
            ver = get_oscdimg_version(p)
            if ver >= 2.55:
                return p
            else:
                print(f"[-] Notice: Found oscdimg at '{p}' but version {ver} is too old (< 2.55). UEFI dual-boot requires v2.55+.")

    # 4. Automatic on-demand download from Microsoft CDN
    return download_adk_oscdimg(tools_dir)


def modify_bcd_stores(iso_files_dir: str, bcd_commands: list = None):
    """
    Configures both BIOS (boot\\bcd) and UEFI (efi\\microsoft\\boot\\bcd) BCD stores on the ISO
    using commands defined in badblobs.xml (or default fallback commands):
    - Disables integrity checks and enables testsigning/advancedoptions for the boot loader ({default}).
    - Enables the legacy F8 boot menu (bootmenupolicy legacy) so users can see loading bar progress in real time.
    """
    bcd_paths = [
        os.path.join(iso_files_dir, "boot", "bcd"),
        os.path.join(iso_files_dir, "efi", "microsoft", "boot", "bcd")
    ]
    commands_to_run = DEFAULT_BCD_COMMANDS if bcd_commands is None else bcd_commands

    for bcd in bcd_paths:
        if os.path.exists(bcd):
            print(f"[+] Patching BCD store: {bcd}")
            try:
                # Clear Read-Only file attribute copied from the source media
                os.chmod(bcd, 0o777)
            except Exception:
                pass

            for item in commands_to_run:
                if isinstance(item, (list, tuple)):
                    tokens = list(item)
                else:
                    tokens = [t[1:-1] if t.startswith('"') and t.endswith('"') and len(t) >= 2 else t
                              for t in shlex.split(item.strip(), posix=False)]

                if not tokens:
                    continue

                # Strip redundant bcdedit[.exe] if present
                if tokens[0].lower() in ("bcdedit", "bcdedit.exe"):
                    tokens.pop(0)

                # Strip redundant /store <path> if present
                if len(tokens) >= 2 and tokens[0].lower() == "/store":
                    tokens.pop(0)
                    tokens.pop(0)

                cmd = ["bcdedit.exe", "/store", bcd] + tokens
                print(f"  [+] bcdedit: {' '.join(tokens)}")
                subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def build_iso(
    input_iso: str,
    output_iso: str,
    work_dir: str,
    db: BlobDatabase,
    blobs_dir: str,
    selected_index: int = None,
    boot_only: bool = False,
    clean: bool = False,
    oscdimg_path: str = None
):
    """
    Orchestrates the complete automated ISO build pipeline:
    1. Elevates process privileges if needed.
    2. Mounts or extracts the source Windows 11 ISO.
    3. Patches boot.wim (Index 2: Setup environment) with badblobs and offline registry tweaks.
    4. Patches install.wim / install.esd (Main OS + nested winre.wim recovery environment).
    5. Modifies ISO BCD stores for legacy F8 menu and testsigning.
    6. Rebuilds dual-boot (UEFI + BIOS) bootable ISO using oscdimg.
    """
    require_admin()

    oscdimg_bin = find_oscdimg(oscdimg_path)
    if not oscdimg_bin:
        print("[-] Error: 'oscdimg.exe' not found! Please install the Windows ADK or specify --oscdimg-path.")
        sys.exit(1)

    print(f"[+] Using oscdimg: {oscdimg_bin}")

    iso_files_dir = os.path.join(work_dir, "iso_files")
    mount_dir = os.path.join(work_dir, "mount")
    re_mount_dir = os.path.join(work_dir, "mountRE")
    local_boot_wim = os.path.join(work_dir, "boot.wim")
    local_install_wim = os.path.join(work_dir, "install.wim")

    os.makedirs(work_dir, exist_ok=True)
    os.makedirs(mount_dir, exist_ok=True)
    os.makedirs(re_mount_dir, exist_ok=True)

    # Clean up any lingering mountpoints and registry handles from previous runs
    subprocess.run(["dism.exe", "/Cleanup-Mountpoints"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["reg.exe", "unload", "HKLM\\POP42_OfflineSystem"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    if clean and os.path.exists(iso_files_dir):
        print(f"[*] --clean specified. Wiping existing ISO workspace files: {iso_files_dir}...")
        clear_readonly(iso_files_dir)
        shutil.rmtree(iso_files_dir, ignore_errors=True)

    # Extract or copy source ISO media
    sources_dir = os.path.join(iso_files_dir, "sources")
    has_install = os.path.exists(os.path.join(sources_dir, "install.wim")) or os.path.exists(os.path.join(sources_dir, "install.esd"))

    if has_install:
        print(f"[*] Reusing existing workspace ISO files in: {iso_files_dir}")
    else:
        if input_iso.endswith(".iso") and os.path.exists(input_iso):
            print(f"[*] Mounting source ISO: {input_iso}...")
            ps_cmd = f"(Mount-DiskImage -ImagePath '{os.path.abspath(input_iso)}' -PassThru | Get-Volume).DriveLetter"
            res = subprocess.run(["powershell", "-NoProfile", "-Command", ps_cmd], capture_output=True, text=True)
            drive_letter = res.stdout.strip()
            if not drive_letter or len(drive_letter) != 1:
                print(f"[-] Error: Failed to mount source ISO: {input_iso}")
                sys.exit(1)
            
            source_drive = f"{drive_letter}:\\"
            print(f"[+] ISO mounted at drive {source_drive}. Copying files with Robocopy...")
            os.makedirs(iso_files_dir, exist_ok=True)
            # Multi-threaded copy of ISO filesystem
            subprocess.run(["robocopy", source_drive, iso_files_dir, "/E", "/MT:8", "/R:1", "/W:1"], stdout=subprocess.DEVNULL)
            
            # Dismount source ISO image
            subprocess.run(["powershell", "-NoProfile", "-Command", f"Dismount-DiskImage -ImagePath '{os.path.abspath(input_iso)}'"], stdout=subprocess.DEVNULL)
            
            # Clear read-only attributes inherited from ISO filesystem
            clear_readonly(iso_files_dir)
        elif os.path.isdir(input_iso):
            print(f"[*] Copying ISO directory structure from: {input_iso}...")
            os.makedirs(iso_files_dir, exist_ok=True)
            subprocess.run(["robocopy", input_iso, iso_files_dir, "/E", "/MT:8", "/R:1", "/W:1"], stdout=subprocess.DEVNULL)
            clear_readonly(iso_files_dir)
        else:
            print(f"[-] Error: Invalid input ISO path: {input_iso}")
            sys.exit(1)

    # -------------------------------------------------------------------------
    # PART 1: PATCH BOOT.WIM (Index 2 for Windows Setup Wizard)
    # -------------------------------------------------------------------------
    src_boot_wim = os.path.join(iso_files_dir, "sources", "boot.wim")
    if not os.path.exists(src_boot_wim):
        raise FileNotFoundError(f"boot.wim not found in {src_boot_wim}")

    print("\n" + "="*70)
    print("STEP 1: Patching boot.wim (Setup Environment)")
    print("="*70)
    clear_readonly(src_boot_wim)
    shutil.copy2(src_boot_wim, local_boot_wim)
    clear_readonly(local_boot_wim)

    with WimMountSession(local_boot_wim, index=2, mount_dir=mount_dir) as session:
        session.apply_blobs(db, blobs_dir)
        session.modify_offline_registry()
        session.commit()

    safe_replace_file(local_boot_wim, src_boot_wim)
    print("[+] boot.wim patched successfully.")

    # -------------------------------------------------------------------------
    # PART 2: PATCH INSTALL IMAGE (install.wim / install.esd)
    # -------------------------------------------------------------------------
    if not boot_only:
        print("\n" + "="*70)
        print("STEP 2: Patching Main OS Image (install.wim / install.esd)")
        print("="*70)
        
        is_esd = False
        install_img = os.path.join(iso_files_dir, "sources", "install.wim")
        if not os.path.exists(install_img):
            install_img = os.path.join(iso_files_dir, "sources", "install.esd")
            is_esd = True

        if not os.path.exists(install_img):
            raise FileNotFoundError("Could not find install.wim or install.esd in sources!")

        clear_readonly(install_img)

        # Query all image indexes using DISM
        info_res = subprocess.run(["dism.exe", "/English", "/Get-ImageInfo", f"/ImageFile:{install_img}"], capture_output=True, text=True)
        found_indexes = [int(m.group(1)) for m in re.finditer(r"(?i)Index\s*:\s*(\d+)", info_res.stdout)]

        if not found_indexes:
            raise RuntimeError(f"No indexes found in {install_img}")

        target_indexes = [selected_index] if selected_index else found_indexes
        print(f"[+] Target OS Indexes to patch: {target_indexes}")

        if is_esd:
            print("[*] Detected read-only install.esd. Converting selected indexes to local install.wim...")
            if os.path.exists(local_install_wim):
                clear_readonly(local_install_wim)
                os.remove(local_install_wim)
            for idx in target_indexes:
                print(f"  [+] Exporting Index {idx}...")
                subprocess.run(["dism.exe", "/English", "/Export-Image", f"/SourceImageFile:{install_img}", f"/SourceIndex:{idx}", f"/DestinationImageFile:{local_install_wim}", "/Compress:max"], check=True)
            wim_indexes = list(range(1, len(target_indexes) + 1))
        else:
            shutil.copy2(install_img, local_install_wim)
            clear_readonly(local_install_wim)
            wim_indexes = target_indexes

        # Mount and patch each selected OS index
        for idx in wim_indexes:
            print(f"\n[*] Mounting and patching install.wim Index {idx}...")
            with WimMountSession(local_install_wim, index=idx, mount_dir=mount_dir) as session:
                session.apply_blobs(db, blobs_dir)
                session.modify_offline_registry()

                # Patch nested WinRE (Windows Recovery Environment) inside the OS image
                winre_path = os.path.join(mount_dir, "Windows", "System32", "Recovery", "winre.wim")
                if os.path.exists(winre_path):
                    take_ownership_and_grant(winre_path)
                    clear_readonly(winre_path)
                    print(f"  [*] Patching nested Recovery Image (winre.wim)...")
                    with WimMountSession(winre_path, index=1, mount_dir=re_mount_dir) as re_session:
                        re_session.apply_blobs(db, blobs_dir)
                        re_session.modify_offline_registry()
                        re_session.commit()

                session.commit()

        # Replace the original install image in the ISO folder
        if is_esd:
            clear_readonly(install_img)
            os.remove(install_img) # Remove original install.esd
        dest_install_wim = os.path.join(iso_files_dir, "sources", "install.wim")
        safe_replace_file(local_install_wim, dest_install_wim)
        print("[+] Install image patch complete.")

    # -------------------------------------------------------------------------
    # PART 3: BCD STORES CONFIGURATION
    # -------------------------------------------------------------------------
    print("\n" + "="*70)
    print("STEP 3: Modifying ISO BCD Stores")
    print("="*70)
    modify_bcd_stores(iso_files_dir, db.bcd_commands if db else None)

    # -------------------------------------------------------------------------
    # PART 4: REBUILD BOOTABLE ISO
    # -------------------------------------------------------------------------
    print("\n" + "="*70)
    print("STEP 4: Rebuilding Dual-Boot (UEFI + BIOS) ISO")
    print("="*70)
    etfsboot = os.path.join(iso_files_dir, "boot", "etfsboot.com")
    efisys = os.path.join(iso_files_dir, "efi", "microsoft", "boot", "efisys.bin")

    # oscdimg arguments for El Torito multi-boot specification:
    # -bootdata:2#p0 (BIOS boot via etfsboot.com) #pEF (UEFI boot via efisys.bin)
    # -u2 -udfver102 (UDF 1.02 filesystem standard for Windows installation media)
    oscdimg_args = [
        oscdimg_bin,
        "-m",
        "-o",
        "-u2",
        "-udfver102",
        f"-bootdata:2#p0,e,b{etfsboot}#pEF,e,b{efisys}",
        iso_files_dir,
        output_iso
    ]

    print(f"[*] Running oscdimg to generate: {output_iso}...")
    subprocess.run(oscdimg_args, check=True)

    # Clean up temporary folders
    shutil.rmtree(mount_dir, ignore_errors=True)
    shutil.rmtree(re_mount_dir, ignore_errors=True)

    print("\n" + "="*70)
    print(f"SUCCESS: Patched ISO built successfully!")
    print(f"Output File: {os.path.abspath(output_iso)}")
    print("="*70)
