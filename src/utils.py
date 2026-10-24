import os
import sys
import subprocess
import shutil
import ctypes
from ctypes import wintypes


def is_windows8_or_newer():
    if sys.platform == "win32":
        ver = sys.getwindowsversion()
        return (ver.major, ver.minor) >= (6, 2)
    return False

if not is_windows8_or_newer():
    print("Error: Windows 8 or newer is required.")
    sys.exit(1)

def is_admin() -> bool:
    """
    Checks if the current process is running with elevated Administrator privileges.
    Returns True if elevated, False otherwise.
    """
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def get_app_dir() -> str:
    """
    Returns the root directory where the application/script resides.
    Handles Nuitka onefile / standalone binaries, PyInstaller, and raw Python execution.
    """
    if "NUITKA_ONEFILE_BINARY" in os.environ:
        return os.path.dirname(os.path.abspath(os.environ["NUITKA_ONEFILE_BINARY"]))

    if "__compiled__" in globals() or getattr(sys, "frozen", False) or hasattr(sys, "_MEIPASS"):
        return os.path.dirname(os.path.abspath(sys.executable))

    file_dir = os.path.dirname(os.path.abspath(__file__))
    if "onefile_" in file_dir or "temp" in file_dir.lower():
        exe_dir = os.path.dirname(os.path.abspath(sys.executable))
        if os.path.exists(os.path.join(exe_dir, "badblobs.xml")):
            return exe_dir

    return file_dir


def require_admin():
    """
    Ensures the script is running with elevated Administrator privileges.
    If running as standard user, triggers a UAC prompt to re-launch itself elevated.
    """
    if not is_admin():
        print("[*] Administrator privileges required for DISM and registry operations.")
        print("[*] Requesting UAC elevation...")
        params = " ".join([f'"{arg}"' if " " in arg else arg for arg in sys.argv])
        ret = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, params, None, 1
        )
        if ret > 32:
            # Successfully launched elevated child process; terminate standard instance
            sys.exit(0)
        else:
            print("[-] Error: UAC elevation was denied or failed. Please run this script as Administrator.")
            sys.exit(1)


def take_ownership_and_grant(file_path: str):
    """
    Takes ownership of protected Windows system files (TrustedInstaller) and grants
    Full Control permissions to the Administrators group.
    
    Uses the locale-independent SID '*S-1-5-32-544:F' (BUILTIN\\Administrators) to ensure
    compatibility across non-English Windows installations (e.g. German, French, Russian).
    """
    if os.path.exists(file_path):
        # /a grants ownership to Administrators group rather than the current user
        subprocess.run(["takeown", "/f", file_path, "/a"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # *S-1-5-32-544 is the universal SID for Administrators
        subprocess.run(["icacls", file_path, "/grant", "*S-1-5-32-544:F"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def clear_readonly(path: str):
    """Recursively removes the Read-Only attribute (FILE_ATTRIBUTE_READONLY) from files and directories."""
    if os.path.isdir(path):
        for root, dirs, files in os.walk(path):
            for d in dirs:
                full_d = os.path.join(root, d)
                try:
                    os.chmod(full_d, 0o777)
                    ctypes.windll.kernel32.SetFileAttributesW(full_d, 0x80) # FILE_ATTRIBUTE_NORMAL
                except Exception:
                    pass
            for f in files:
                full_f = os.path.join(root, f)
                try:
                    os.chmod(full_f, 0o777)
                    ctypes.windll.kernel32.SetFileAttributesW(full_f, 0x80)
                except Exception:
                    pass
    elif os.path.exists(path):
        try:
            os.chmod(path, 0o777)
            ctypes.windll.kernel32.SetFileAttributesW(path, 0x80)
        except Exception:
            pass


def safe_replace_file(src: str, dst: str):
    """Safely moves src to dst, clearing read-only attributes and overwriting any existing destination file."""
    clear_readonly(dst)
    if os.path.exists(dst):
        try:
            os.remove(dst)
        except Exception:
            pass
    shutil.move(src, dst)
    clear_readonly(dst)
