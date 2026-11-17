import socket
import sys
import ctypes
from ctypes import wintypes
import os
import time

try:
    import capstone

    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False

# ------------------------------------------------------------------------------
# 1. DBGHELP SYMBOL MANAGEMENT
# ------------------------------------------------------------------------------
DWORD64 = ctypes.c_uint64
HANDLE = wintypes.HANDLE
DWORD = wintypes.DWORD
BOOL = wintypes.BOOL
PCSTR = ctypes.c_char_p
ULONG = wintypes.ULONG
ULONG64 = ctypes.c_uint64
CHAR = ctypes.c_char

dbghelp = ctypes.windll.dbghelp
kernel32 = ctypes.windll.kernel32
h_process = kernel32.GetCurrentProcess()

dbghelp.SymInitialize.argtypes = [HANDLE, PCSTR, BOOL]
dbghelp.SymInitialize.restype = BOOL
dbghelp.SymLoadModuleEx.argtypes = [
    HANDLE,
    HANDLE,
    PCSTR,
    PCSTR,
    DWORD64,
    DWORD,
    ctypes.c_void_p,
    DWORD,
]
dbghelp.SymLoadModuleEx.restype = DWORD64


class SYMBOL_INFO(ctypes.Structure):
    _fields_ = [
        ("SizeOfStruct", ULONG),
        ("TypeIndex", ULONG),
        ("Reserved", ULONG64 * 2),
        ("Index", ULONG),
        ("Size", ULONG),
        ("ModBase", ULONG64),
        ("Flags", ULONG),
        ("Value", ULONG64),
        ("Address", ULONG64),
        ("Register", ULONG),
        ("Scope", ULONG),
        ("Tag", ULONG),
        ("NameLen", ULONG),
        ("MaxNameLen", ULONG),
        ("Name", CHAR * 2048),
    ]


EnumSymCallback = ctypes.WINFUNCTYPE(
    BOOL, ctypes.POINTER(SYMBOL_INFO), ULONG, ctypes.c_void_p
)


class SymbolResolver:
    def __init__(self, pdb_dir: str, pe_name: str = "ntoskrnl.exe"):
        self.symbols = []  # (rva, name)
        self.base_loaded = 0x10000000
        pe_path = os.path.join(pdb_dir, pe_name)
        if not os.path.exists(pe_path):
            print(f"[-] Warning: PE file not found: {pe_path}")
            return
        pe_size = os.path.getsize(pe_path)

        dbghelp.SymCleanup(h_process)
        dbghelp.SymInitialize(h_process, pdb_dir.encode("utf-8"), False)
        dbghelp.SymSetOptions(0x2 | 0x4)
        mod_base = dbghelp.SymLoadModuleEx(
            h_process,
            None,
            pe_path.encode("utf-8"),
            None,
            self.base_loaded,
            pe_size,
            None,
            0,
        )
        if not mod_base:
            print(f"[-] Warning: Failed to load symbols for {pe_path}")
            return

        def _enum_cb(p_sym, size, ctx):
            s = p_sym.contents
            name = s.Name[: s.NameLen].decode("utf-8", errors="ignore")
            rva = s.Address - self.base_loaded
            self.symbols.append((rva, name))
            return True

        dbghelp.SymEnumSymbols.argtypes = [
            HANDLE,
            ULONG64,
            PCSTR,
            EnumSymCallback,
            ctypes.c_void_p,
        ]
        dbghelp.SymEnumSymbols(
            h_process, ctypes.c_uint64(mod_base), b"*", EnumSymCallback(_enum_cb), None
        )
        self.symbols.sort(key=lambda x: x[0])
        print(f"[+] Loaded {len(self.symbols)} symbols from PDB.")

    def resolve_rva(self, rva: int):
        if not self.symbols:
            return "Unknown", 0
        low = 0
        high = len(self.symbols) - 1
        best_match = None
        while low <= high:
            mid = (low + high) // 2
            curr_rva, curr_name = self.symbols[mid]
            if curr_rva <= rva:
                best_match = (curr_rva, curr_name)
                low = mid + 1
            else:
                high = mid - 1

        if best_match:
            sym_rva, name = best_match
            diff = rva - sym_rva
            if diff < 0x20000:
                return name, diff
        return "Unknown", 0


# ------------------------------------------------------------------------------
# 2. GDB PROTOCOL CLIENT
# ------------------------------------------------------------------------------
def make_gdb_packet(data: bytes) -> bytes:
    checksum = sum(data) % 256
    return f"${data.decode('latin1')}#{checksum:02X}".encode("latin1")


def parse_gdb_packet(packet: bytes) -> bytes:
    if not packet.startswith(b"$") or b"#" not in packet:
        return b""
    return packet.split(b"#")[0][1:]


class QemuGdbClient:
    def __init__(self, host: str = "127.0.0.1", port: int = 1234):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(2.0)
        self.sock.connect((host, port))

    def cmd(self, command: bytes) -> bytes:
        self.sock.sendall(make_gdb_packet(command))
        try:
            ack = self.sock.recv(1)
        except socket.timeout:
            return b""
        resp = b""
        while True:
            try:
                char = self.sock.recv(1)
                resp += char
                if char == b"#":
                    resp += self.sock.recv(2)
                    break
            except socket.timeout:
                break
        return parse_gdb_packet(resp)

    def interrupt(self) -> bytes:
        self.sock.sendall(b"\x03")
        time.sleep(0.1)
        resp = b""
        while True:
            try:
                char = self.sock.recv(1)
                resp += char
                if char == b"#":
                    resp += self.sock.recv(2)
                    break
            except socket.timeout:
                break
        return parse_gdb_packet(resp)

    def resume(self):
        self.sock.sendall(make_gdb_packet(b"c"))
        self.sock.recv(1)

    def read_registers_32(self) -> dict:
        raw_hex = self.cmd(b"g").decode("latin1")
        reg_names = [
            "EAX",
            "ECX",
            "EDX",
            "EBX",
            "ESP",
            "EBP",
            "ESI",
            "EDI",
            "EIP",
            "EFLAGS",
            "CS",
            "SS",
            "DS",
            "ES",
            "FS",
            "GS",
        ]
        raw_bytes = bytes.fromhex(raw_hex[:128])
        regs = {}
        for i, name in enumerate(reg_names):
            val = int.from_bytes(raw_bytes[i * 4 : (i + 1) * 4], "little")
            regs[name] = val
        return regs

    def read_memory(self, addr: int, length: int) -> bytes:
        cmd_str = f"m{addr:X},{length:X}".encode("latin1")
        resp = self.cmd(cmd_str).decode("latin1")
        if not resp or resp.startswith("E"):
            return b""
        try:
            return bytes.fromhex(resp)
        except Exception:
            return b""

    def monitor(self, command: str) -> str:
        cmd_hex = command.encode("latin1").hex()
        qrcmd = f"qRcmd,{cmd_hex}".encode("latin1")
        resp = self.cmd(qrcmd).decode("latin1")
        out = ""
        # GDB protocol returns monitor output as 'O<hex>'
        if resp.startswith("O"):
            try:
                out = bytes.fromhex(resp[1:]).decode("latin1", errors="ignore")
            except Exception:
                pass
        return out

    def close(self):
        try:
            self.sock.close()
        except Exception:
            pass


# ------------------------------------------------------------------------------
# 3. KERNEL BASE FINDER & CALL STACK RESOLVER
# ------------------------------------------------------------------------------
def find_kernel_base(gdb: QemuGdbClient, hint_addr: int) -> int:
    """Walks backwards from a code address in memory to find the PE 'MZ' header."""
    curr = hint_addr & ~0xFFF
    for _ in range(5000):  # Scan up to ~20 MB backwards
        mem = gdb.read_memory(curr, 0x40)
        if len(mem) >= 0x40 and mem[:2] == b"MZ":
            e_lfanew = int.from_bytes(mem[0x3C:0x40], "little")
            if e_lfanew < 0x1000:
                pe_sig = gdb.read_memory(curr + e_lfanew, 4)
                if pe_sig == b"PE\x00\x00":
                    return curr
        curr -= 0x1000
    return 0


def dump_machine_state():
    print("=" * 78)
    print(" WinPOPBit QEMU GDB Live Debugger (x86 32-bit)")
    print("=" * 78)

    # 1. Load PDB symbols
    nx_dir = os.path.abspath("nx_work")
    resolver = SymbolResolver(nx_dir, "ntoskrnl.exe")

    # 2. Connect to QEMU GDB stub
    print("[*] Connecting to QEMU GDB stub at 127.0.0.1:1234...")
    try:
        gdb = QemuGdbClient("127.0.0.1", 1234)
    except Exception as e:
        print(f"[-] Could not connect to QEMU on 127.0.0.1:1234: {e}")
        print("[!] Ensure QEMU was started with '-s' or '-gdb tcp::1234'")
        return

    print("[+] Connected to QEMU! Sending interrupt (Ctrl-C / 0x03)...")
    stop_resp = gdb.interrupt()
    print(f"[+] VM Stopped. Status: {stop_resp.decode('latin1', errors='ignore')}")

    # 3. Read registers
    regs = gdb.read_registers_32()
    eip = regs["EIP"]
    esp = regs["ESP"]
    ebp = regs["EBP"]

    print("\n[+] General Purpose Registers (32-bit):")
    print(
        f"  EAX: 0x{regs['EAX']:08X}   ECX: 0x{regs['ECX']:08X}   EDX: 0x{regs['EDX']:08X}   EBX: 0x{regs['EBX']:08X}"
    )
    print(
        f"  ESP: 0x{regs['ESP']:08X}   EBP: 0x{regs['EBP']:08X}   ESI: 0x{regs['ESI']:08X}   EDI: 0x{regs['EDI']:08X}"
    )
    print(f"  EIP: 0x{regs['EIP']:08X}   EFLAGS: 0x{regs['EFLAGS']:08X}")
    print(
        f"  CS:  0x{regs['CS']:04X}       DS:  0x{regs['DS']:04X}       ES:  0x{regs['ES']:04X}       SS:  0x{regs['SS']:04X}"
    )

    # 4. Monitor control registers (CR0, CR3, CR4, EFER)
    print("\n[+] QEMU Control Registers & MSR Status:")
    mon_regs = gdb.monitor("info registers")
    if mon_regs:
        for line in mon_regs.splitlines():
            line_str = line.strip()
            if any(k in line_str for k in ["CR0", "CR3", "CR4", "EFER", "GDT", "IDT"]):
                print(f"  {line_str}")

    # 5. Determine Kernel Base Address
    print("\n[*] Searching memory for ntoskrnl.exe image base...")
    kbase = find_kernel_base(gdb, eip)
    if kbase:
        print(f"[+] Found ntoskrnl.exe Base Address in VM: 0x{kbase:08X}")
    else:
        # Fallback to inspecting stack addresses
        print("[-] Could not locate MZ header directly above EIP. Scanning stack...")
        stack_sample = gdb.read_memory(esp, 0x100)
        for i in range(0, len(stack_sample), 4):
            val = int.from_bytes(stack_sample[i : i + 4], "little")
            if val > 0x80000000:
                kbase = find_kernel_base(gdb, val)
                if kbase:
                    print(
                        f"[+] Found ntoskrnl.exe Base Address via stack: 0x{kbase:08X}"
                    )
                    break

    # 6. Disassemble Current Instruction at EIP
    print("\n[+] Disassembly at EIP (0x{:08X}):".format(eip))
    eip_code = gdb.read_memory(eip, 32)
    if HAS_CAPSTONE and eip_code:
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        insns = list(md.disasm(eip_code, eip))
        for insn in insns[:5]:
            marker = "==>" if insn.address == eip else "   "
            rva = insn.address - kbase if kbase else 0
            sym_str = ""
            if kbase:
                sym_name, diff = resolver.resolve_rva(rva)
                if sym_name != "Unknown":
                    sym_str = f" <{sym_name}+0x{diff:X}>"
            print(
                f"  {marker} 0x{insn.address:08X}: {insn.mnemonic:8s} {insn.op_str:20s}{sym_str}"
            )
    elif eip_code:
        print(f"  Raw Bytes: {eip_code.hex()}")

    # 7. Check if KeBugCheck / KeBugCheckEx was hit
    if kbase:
        eip_rva = eip - kbase
        sym_name, diff = resolver.resolve_rva(eip_rva)
        print(
            f"\n[+] Execution Location: {sym_name} + 0x{diff:X} (RVA: 0x{eip_rva:08X})"
        )
        if "BugCheck" in sym_name or "KiTrap" in sym_name:
            print("\n[!] BUGCHECK / TRAP DETECTED!")
            # BugCheck parameters are sitting on stack at [esp], [esp+4], [esp+8], etc.
            args = gdb.read_memory(esp, 24)
            if len(args) >= 20:
                p0 = int.from_bytes(args[0:4], "little")
                p1 = int.from_bytes(args[4:8], "little")
                p2 = int.from_bytes(args[8:12], "little")
                p3 = int.from_bytes(args[12:16], "little")
                p4 = int.from_bytes(args[16:20], "little")
                print(
                    f"  Stack Frame: 0x{p0:08X} 0x{p1:08X} 0x{p2:08X} 0x{p3:08X} 0x{p4:08X}"
                )

    # 8. Dump Call Stack
    print("\n[+] Call Stack (from ESP 0x{:08X}):".format(esp))
    stack_bytes = gdb.read_memory(esp, 0x180)  # Read 384 bytes (96 DWORDs)
    if stack_bytes:
        for i in range(0, len(stack_bytes), 4):
            addr = esp + i
            val = int.from_bytes(stack_bytes[i : i + 4], "little")
            sym_desc = ""
            if kbase and (kbase <= val <= kbase + 0x2000000):
                rva = val - kbase
                sym_name, diff = resolver.resolve_rva(rva)
                if sym_name != "Unknown":
                    sym_desc = f" -> {sym_name} + 0x{diff:X} (RVA: 0x{rva:08X})"
            print(f"  ESP+0x{i:03X} [0x{addr:08X}]: 0x{val:08X}{sym_desc}")

    print("\n" + "=" * 78)
    print(
        "Debug dump complete. Press [Enter] to resume VM execution, or Ctrl-C to quit."
    )
    print("=" * 78)
    try:
        input()
        print("[*] Resuming VM execution...")
        gdb.resume()
    except KeyboardInterrupt:
        pass
    finally:
        gdb.close()
        dbghelp.SymCleanup(h_process)


if __name__ == "__main__":
    dump_machine_state()
