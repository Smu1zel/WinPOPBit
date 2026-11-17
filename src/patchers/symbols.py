"""Resolve kernel symbols from the Microsoft public symbol server.

The patchers need a handful of RVAs that move between Windows builds
(`KiInvalidOpcodeFault`, `KiSetFeatureBits`, ...).  Rather than asking the user
to look them up, download the matching PDB and ask dbghelp for them.

The PDB is identified by the RSDS record in the image's debug directory, which
is exactly what the symbol server indexes on:

    <name>/<GUID><age>/<name>

`dbghelp.dll` ships with Windows, so this adds no new dependency.

    syms = resolve(exe_path)               # {name: rva}
    rva = syms.get("KiInvalidOpcodeFault")
"""

import ctypes
import ctypes.wintypes as wt
import os
import struct
import urllib.request

SYMBOL_SERVER = "https://msdl.microsoft.com/download/symbols"
_CACHE = os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")),
                      "winpopbit-symbols")


# --------------------------------------------------------------- PE / RSDS
def _sections(data):
    e0 = struct.unpack_from("<I", data, 0x3C)[0]
    nsec = struct.unpack_from("<H", data, e0 + 6)[0]
    optsz = struct.unpack_from("<H", data, e0 + 20)[0]
    opt = e0 + 24
    magic = struct.unpack_from("<H", data, opt)[0]
    ddir = opt + (112 if magic == 0x20B else 96)
    table = e0 + 24 + optsz
    secs = []
    for i in range(nsec):
        h = table + i * 40
        vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", data, h + 8)
        secs.append((vaddr, vsize, rawptr, rawsize))
    return secs, ddir


def _rva2off(secs, rva):
    for vaddr, vsize, rawptr, rawsize in secs:
        if vaddr <= rva < vaddr + max(vsize, rawsize):
            return rawptr + (rva - vaddr)
    return None


def pdb_identity(data):
    """Return (pdb_name, guid_string, age) from the RSDS record, or None."""
    secs, ddir = _sections(data)
    off = _rva2off(secs, struct.unpack_from("<I", data, ddir + 6 * 8)[0])
    size = struct.unpack_from("<I", data, ddir + 6 * 8 + 4)[0]
    if off is None:
        return None
    for k in range(size // 28):
        o = off + k * 28
        typ = struct.unpack_from("<I", data, o + 12)[0]
        ptr = struct.unpack_from("<I", data, o + 24)[0]
        if typ != 2 or data[ptr:ptr + 4] != b"RSDS":
            continue
        guid = data[ptr + 4:ptr + 20]
        age = struct.unpack_from("<I", data, ptr + 20)[0]
        name = data[ptr + 24:ptr + 24 + 48].split(b"\x00")[0].decode("latin1")
        d1, = struct.unpack_from("<I", guid, 0)
        d2, = struct.unpack_from("<H", guid, 4)
        d3, = struct.unpack_from("<H", guid, 6)
        g = "%08X%04X%04X%s" % (d1, d2, d3, guid[8:].hex().upper())
        return name, g, age
    return None


def download_symbols(exe_path, cache_dir=_CACHE, timeout=120):
    """Fetch the PDB for `exe_path`.  Returns the local path or None."""
    with open(exe_path, "rb") as f:
        data = f.read()
    ident = pdb_identity(data)
    if not ident:
        return None
    name, guid, age = ident
    dst_dir = os.path.join(cache_dir, name, guid + "%X" % age)
    dst = os.path.join(dst_dir, name)
    if os.path.exists(dst):
        return dst
    os.makedirs(dst_dir, exist_ok=True)
    url = "%s/%s/%s%X/%s" % (SYMBOL_SERVER, name, guid, age, name)
    print("[*] downloading %s" % url)
    for attempt in range(3):
        try:
            with urllib.request.urlopen(url, timeout=timeout) as r:
                blob = r.read()
            with open(dst, "wb") as f:
                f.write(blob)
            return dst
        except Exception as e:
            print("[-] symbol download attempt %d failed: %s" % (attempt + 1, e))
    return None


# ------------------------------------------------------------------ dbghelp
def _enum_symbols(exe_path, pdb_path):
    """Enumerate function symbols; mirrors the working dbghelp call sequence."""
    dbghelp = ctypes.WinDLL("dbghelp.dll")
    hproc = ctypes.c_void_p(-1)                      # (HANDLE)-1, current process
    base = 0x180000000

    # dbghelp looks for <search>\\<pdb>\\<guid><age>\\<pdb>, which is exactly
    # the layout download_symbols() creates - no symsrv.dll needed.
    search = os.path.dirname(os.path.dirname(os.path.dirname(pdb_path)))
    dbghelp.SymSetOptions(0x2 | 0x400)               # UNDNAME | AUTO_PUBLICS
    if not dbghelp.SymInitializeW(hproc, search, False):
        print("[-] SymInitialize failed (%d)" % ctypes.get_last_error())
        return {}
    try:
        loaded = dbghelp.SymLoadModuleExW(
            hproc, None, exe_path, "target",
            ctypes.c_ulonglong(base), 0, None, 0)
        if not loaded:
            print("[-] SymLoadModuleEx failed (%d)" % ctypes.get_last_error())
            return {}

        result = {}
        CB = ctypes.WINFUNCTYPE(wt.BOOL, ctypes.c_void_p, wt.ULONG, ctypes.c_void_p)

        def cb(sym_info, size, ctx):
            try:
                addr = ctypes.c_int64.from_address(sym_info + 56).value
                tag = ctypes.c_int32.from_address(sym_info + 72).value
                name = ctypes.wstring_at(sym_info + 84)
                if tag in (5, 10) and addr > base and name:  # Function / PublicSymbol
                    result[name] = addr - base
            except Exception:
                pass
            return True

        dbghelp.SymEnumSymbolsW(hproc, ctypes.c_ulonglong(base), None, CB(cb), 0)
        return result
    finally:
        dbghelp.SymCleanup(hproc)


# --------------------------------------------------------------------- api
def resolve(exe_path, cache_dir=_CACHE, verbose=True):
    """Return {symbol_name: rva} for `exe_path`, downloading the PDB if needed."""
    pdb = download_symbols(exe_path, cache_dir)
    if not pdb:
        if verbose:
            print("[-] no PDB available; symbol-derived offsets will be missing")
        return {}
    syms = _enum_symbols(exe_path, pdb)
    if verbose:
        print("[*] %d symbols from %s" % (len(syms), os.path.basename(pdb)))
    return syms


if __name__ == "__main__":
    import sys
    s = resolve(sys.argv[1])
    for k in ("KiInvalidOpcodeFault", "KiSetFeatureBits", "KiInitializeXSave"):
        if k in s:
            print("%-26s 0x%X" % (k, s[k]))
