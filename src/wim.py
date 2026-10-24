import os
import subprocess
import shutil
import re
from .utils import take_ownership_and_grant, clear_readonly, safe_replace_file
from .patchers import PATCHER_REGISTRY
from .database import BlobDatabase


class WimMountSession:
    """
    Robust context manager for DISM WIM operations.
    Guarantees that mounted images and offline registry hives are safely cleaned up
    (unmounted with /Discard or /Commit and registry unhooked), even upon exceptions,
    keyboard interrupts (Ctrl+C), or fatal errors.
    """

    def __init__(self, wim_path: str, index: int, mount_dir: str):
        self.wim_path = wim_path
        self.index = index
        self.mount_dir = mount_dir
        self.mounted = False
        self.committed = False
        self.reg_loaded = False

    def __enter__(self):
        os.makedirs(self.mount_dir, exist_ok=True)
        print(f"[*] Mounting {os.path.basename(self.wim_path)} (Index {self.index}) -> {self.mount_dir}...")
        cmd = ["dism.exe", "/Mount-Image", f"/ImageFile:{self.wim_path}", f"/Index:{self.index}", f"/MountDir:{self.mount_dir}"]
        res = subprocess.run(cmd)
        if res.returncode != 0:
            raise RuntimeError(f"Failed to mount WIM: {self.wim_path} (Index {self.index})")
        self.mounted = True
        return self

    def apply_blobs(self, db: BlobDatabase, blobs_dir: str):
        """Applies all enabled blobs to the mounted WIM filesystem using options from badblobs.xml."""
        for b_id, blob in db.blobs.items():
            if not blob.enabled:
                continue

            target_full_path = os.path.join(self.mount_dir, blob.target.replace("/", "\\"))

            if blob.action == "patch":
                if blob.patcher in PATCHER_REGISTRY:
                    if os.path.exists(target_full_path):
                        print(f"  [+] Executing patch handler '{blob.patcher}' on '{b_id}' at {blob.target}...")
                        take_ownership_and_grant(target_full_path)
                        handler = PATCHER_REGISTRY[blob.patcher]
                        handler(target_full_path, target_full_path, **blob.options)
                    else:
                        print(f"  [-] Target '{blob.target}' not found in this image index. Skipping.")
                else:
                    print(f"  [-] Error: Unregistered patcher '{blob.patcher}' for blob '{b_id}'.")

            elif blob.action == "replace":
                replacement_path = os.path.join(blobs_dir, blob.filename)
                if not os.path.exists(replacement_path):
                    print(f"  [-] Warning: Replacement blob '{blob.filename}' missing. Skipping '{b_id}'.")
                    continue

                if os.path.exists(target_full_path):
                    print(f"  [+] Replacing blob '{b_id}' with {blob.filename} -> {blob.target}...")
                    take_ownership_and_grant(target_full_path)
                    shutil.copy2(replacement_path, target_full_path)
                else:
                    print(f"  [-] Target '{blob.target}' does not exist in this image index. Skipping.")

    def modify_offline_registry(self):
        """
        Loads the offline SYSTEM hive (Windows\\System32\\config\\SYSTEM) into HKLM\\POP42_OfflineSystem
        and configures SystemStartOptions with 'DISABLE_INTEGRITY_CHECKS TESTSIGNING' to allow
        the patched kernel to run with driver signature checks disabled.
        """
        system_hive = os.path.join(self.mount_dir, "Windows", "System32", "config", "SYSTEM")
        if not os.path.exists(system_hive):
            return

        print("  [+] Configuring offline registry (DISABLE_INTEGRITY_CHECKS TESTSIGNING, disabling ReFS)...")
        # Ensure any leftover hive from a prior interrupted session is unloaded
        subprocess.run(["reg.exe", "unload", "HKLM\\POP42_OfflineSystem"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        res = subprocess.run(["reg.exe", "load", "HKLM\\POP42_OfflineSystem", system_hive], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if res.returncode == 0:
            self.reg_loaded = True
            try:
                # Set SystemStartOptions in ControlSet001\\Control
                reg_cmd = [
                    "reg.exe", "add", "HKLM\\POP42_OfflineSystem\\ControlSet001\\Control",
                    "/v", "SystemStartOptions", "/t", "REG_SZ", "/d", "DISABLE_INTEGRITY_CHECKS TESTSIGNING", "/f"
                ]
                subprocess.run(reg_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

                # Disable ReFS & ReFSv1 services (Start=4, remove BootFlags and Group) to prevent WinPE auto-load
                for srv in ("ReFS", "ReFSv1"):
                    for cs in ("ControlSet001", "ControlSet002"):
                        srv_key = f"HKLM\\POP42_OfflineSystem\\{cs}\\Services\\{srv}"
                        subprocess.run([
                            "reg.exe", "add", srv_key,
                            "/v", "Start", "/t", "REG_DWORD", "/d", "4", "/f"
                        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                        # BootFlags=0x80 (CM_SERVICE_WINPE_BOOT_LOAD) forces WinPE to promote the driver to boot-start
                        subprocess.run(["reg.exe", "delete", srv_key, "/v", "BootFlags", "/f"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                        # Remove from 'Boot File System' load order group
                        subprocess.run(["reg.exe", "delete", srv_key, "/v", "Group", "/f"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            finally:
                # Unload hive to release file locks on the mount folder
                subprocess.run(["reg.exe", "unload", "HKLM\\POP42_OfflineSystem"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                self.reg_loaded = False

    def commit(self):
        """Commits modified changes back to the WIM image and dismounts."""
        if self.mounted and not self.committed:
            print(f"[*] Committing and dismounting {os.path.basename(self.wim_path)} (Index {self.index})...")
            cmd = ["dism.exe", "/Unmount-Image", f"/MountDir:{self.mount_dir}", "/Commit"]
            res = subprocess.run(cmd)
            if res.returncode != 0:
                raise RuntimeError("Failed to commit and unmount WIM image.")
            self.committed = True
            self.mounted = False

    def __exit__(self, exc_type, exc_val, exc_tb):
        # Guarantee offline registry hive is unloaded
        if self.reg_loaded:
            subprocess.run(["reg.exe", "unload", "HKLM\\POP42_OfflineSystem"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.reg_loaded = False

        # If an error occurred or commit() was not called, safely discard changes to prevent mount poisoning
        if self.mounted:
            print(f"[!] Exception or abort detected. Discarding changes for {self.mount_dir}...")
            subprocess.run(["dism.exe", "/Unmount-Image", f"/MountDir:{self.mount_dir}", "/Discard"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.mounted = False
