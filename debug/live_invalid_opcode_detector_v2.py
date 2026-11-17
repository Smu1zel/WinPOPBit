import socket
import sys
import ctypes
from ctypes import wintypes
import os

# Define Windows Types for dbghelp
DWORD64 = ctypes.c_uint64
HANDLE = wintypes.HANDLE
DWORD = wintypes.DWORD
BOOL = wintypes.BOOL
PCSTR = ctypes.c_char_p
ULONG = wintypes.ULONG
ULONG64 = ctypes.c_uint64
CHAR = ctypes.c_char
PDWORD64 = ctypes.POINTER(DWORD64)

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


dbghelp.SymFromAddr.argtypes = [HANDLE, DWORD64, PDWORD64, ctypes.POINTER(SYMBOL_INFO)]
dbghelp.SymFromAddr.restype = BOOL

# Resolve symbol addresses during script startup
kebugcheck_rva = 0
ki_invalid_opcode_rva = 0

EnumSymCallback = ctypes.WINFUNCTYPE(
    BOOL, ctypes.POINTER(SYMBOL_INFO), ULONG, ctypes.c_void_p
)


def resolve_callback(p_sym, size, ctx):
    global kebugcheck_rva, ki_invalid_opcode_rva
    s = p_sym.contents
    name = s.Name[: s.NameLen].decode("utf-8", errors="ignore")
    if name == "KeBugCheckEx":
        kebugcheck_rva = s.Address - base_addr
    elif name == "KiInvalidOpcodeFault":
        ki_invalid_opcode_rva = s.Address - base_addr
    return True


print("Loading ntoskrnl.exe symbols to resolve required RVAs...")
curr_dir = os.path.abspath(os.path.dirname(__file__))
pdb_dir = os.path.join(curr_dir, "pdb_new")
if not os.path.exists(pdb_dir):
    pdb_dir = curr_dir

pe_path = os.path.join(curr_dir, "ntoskrnl.exe")
if not os.path.exists(pe_path):
    print("Error: ntoskrnl.exe not found in root directory!")
    sys.exit(1)
pe_size = os.path.getsize(pe_path)

dbghelp.SymCleanup(h_process)
dbghelp.SymInitialize(h_process, pdb_dir.encode("utf-8"), False)
dbghelp.SymSetOptions(0x2 | 0x4)
base_addr = dbghelp.SymLoadModuleEx(
    h_process, None, pe_path.encode("utf-8"), None, 0x140000000, pe_size, None, 0
)

if not base_addr:
    print("Failed to load symbols from PDB!")
    sys.exit(1)

dbghelp.SymEnumSymbols.argtypes = [
    HANDLE,
    ULONG64,
    PCSTR,
    EnumSymCallback,
    ctypes.c_void_p,
]
dbghelp.SymEnumSymbols(
    h_process, ctypes.c_uint64(base_addr), b"*", EnumSymCallback(resolve_callback), None
)

if not kebugcheck_rva or not ki_invalid_opcode_rva:
    print(
        f"Error: Could not resolve required symbol RVAs! KeBugCheckEx RVA: 0x{kebugcheck_rva:X}, KiInvalidOpcodeFault RVA: 0x{ki_invalid_opcode_rva:X}"
    )
    dbghelp.SymCleanup(h_process)
    sys.exit(1)

print(f"Symbol RVAs resolved:")
print(f"  KeBugCheckEx:         0x{kebugcheck_rva:X}")
print(f"  KiInvalidOpcodeFault: 0x{ki_invalid_opcode_rva:X}")


def get_symbol_at(target_va):
    displacement = DWORD64(0)
    symbol = SYMBOL_INFO()
    symbol.SizeOfStruct = 88
    symbol.MaxNameLen = 2048
    if dbghelp.SymFromAddr(
        h_process, DWORD64(target_va), ctypes.byref(displacement), ctypes.byref(symbol)
    ):
        name = symbol.Name[: symbol.NameLen].decode("utf-8", errors="ignore")
        return name, displacement.value
    return "Unknown", 0xFFFFFFFFFFFFFFFF


# GDB Protocol Helpers
def parse_gdb_packet(packet):
    if not packet.startswith(b"$") or b"#" not in packet:
        return b""
    content = packet.split(b"#")[0][1:]
    return content


def make_gdb_packet(data):
    checksum = sum(data) % 256
    return f"${data.decode('latin1')}#{checksum:02X}".encode("latin1")


def send_and_receive(sock, command):
    sock.sendall(make_gdb_packet(command))
    sock.recv(1)  # Read '+' ACK
    response = b""
    while True:
        char = sock.recv(1)
        response += char
        if char == b"#":
            response += sock.recv(2)
            break
    return parse_gdb_packet(response)


def find_kernel_base(sock):
    print("Scanning memory for ntoskrnl.exe KASLR base (2MB boundaries)...")
    # Kernel space starts around 0xFFFFF80000000000
    start_range = 0xFFFFF80000000000
    end_range = 0xFFFFF80800000000
    step = 2 * 1024 * 1024

    for candidate_base in range(start_range, end_range, step):
        # Read first 2 bytes to check for PE 'MZ' signature
        mem_cmd = f"m{candidate_base:x},2".encode("latin1")
        sock.sendall(make_gdb_packet(mem_cmd))
        sock.recv(1)  # ACK

        response = b""
        while True:
            char = sock.recv(1)
            response += char
            if char == b"#":
                response += sock.recv(2)
                break
        res_hex = parse_gdb_packet(response)

        # Check if the memory returns 'MZ' (hex 4d5a)
        if res_hex == b"4d5a" or res_hex == b"4D5A":
            # Verify PE signature location by reading e_lfanew
            mem_cmd = f"m{candidate_base + 0x3C:x},4".encode("latin1")
            pe_offset_hex = send_and_receive(sock, mem_cmd)
            if not pe_offset_hex or b"E" in pe_offset_hex:
                continue

            try:
                pe_offset = int.from_bytes(
                    bytes.fromhex(pe_offset_hex.decode("latin1")), "little"
                )
                if pe_offset < 0x40 or pe_offset > 0x1000:
                    continue

                # Read PE signature
                mem_cmd = f"m{candidate_base + pe_offset:x},4".encode("latin1")
                pe_sig_hex = send_and_receive(sock, mem_cmd)
                if pe_sig_hex == b"50450000":  # 'PE\0\0'
                    # Verify by testing KeBugCheckEx symbol resolution
                    test_pe_va = 0x140000000 + kebugcheck_rva
                    resolved_name, disp = get_symbol_at(test_pe_va)
                    if resolved_name == "KeBugCheckEx":
                        print(f"Found validated Kernel Base: 0x{candidate_base:X}")
                        return candidate_base
            except Exception:
                continue
    return None


def debug_live():
    print("Connecting to QEMU GDB stub...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect(("127.0.0.1", 1234))
    except Exception as e:
        print(f"Could not connect to QEMU GDB: {e}")
        dbghelp.SymCleanup(h_process)
        return

    print("Connected!")

    # Check if VM is already stopped by querying status with a 0.5s timeout.
    sock.settimeout(0.5)
    already_stopped = False
    try:
        status = send_and_receive(sock, b"?")
        if status:
            print(
                f"Target is already stopped. Status: {status.decode('latin1', errors='ignore')}"
            )
            already_stopped = True
    except socket.timeout:
        pass

    # Restore blocking mode for subsequent GDB commands
    sock.settimeout(None)

    if not already_stopped:
        print("Target is running. Interrupting target VM...")
        sock.sendall(b"\x03")

        stop_response = b""
        while True:
            char = sock.recv(1)
            stop_response += char
            if char == b"#":
                stop_response += sock.recv(2)
                break
        print(f"Target stopped: {stop_response.decode('latin1', errors='ignore')}")

    # Resolve live kernel base
    kernel_base = find_kernel_base(sock)
    if not kernel_base:
        print("Error: Could not locate kernel base in memory range.")
        sock.close()
        dbghelp.SymCleanup(h_process)
        return

    fault_address = kernel_base + ki_invalid_opcode_rva
    print(f"Setting Breakpoint at KiInvalidOpcodeFault (0x{fault_address:X})...")

    bp_cmd = f"Z0,{fault_address:x},1".encode("latin1")
    bp_response = send_and_receive(sock, bp_cmd)
    print(f"Breakpoint Response: {bp_response.decode('latin1', errors='ignore')}")

    print("\nResuming execution... GDB will halt when an invalid instruction is hit!")
    sock.sendall(make_gdb_packet(b"c"))
    sock.recv(1)  # ACK

    # Wait for the breakpoint to hit
    stop_reason = b""
    while True:
        char = sock.recv(1)
        stop_reason += char
        if char == b"#":
            stop_reason += sock.recv(2)
            break

    print(f"\n==============================================================")
    print(f"ILLEGAL INSTRUCTION (#UD) DETECTED!")
    print(f"==============================================================")
    print(f"Debugger stopped: {stop_reason.decode('latin1', errors='ignore')}")

    # Read registers
    regs_hex = send_and_receive(sock, b"g")

    def get_reg(idx):
        start = idx * 16
        end = start + 16
        b = bytes.fromhex(regs_hex[start:end].decode("latin1"))
        return int.from_bytes(b, "little")

    rsp = get_reg(7)
    rip = get_reg(16)

    # Read faulting instruction address from stack frame
    mem_cmd = f"m{rsp:x},8".encode("latin1")
    faulting_rip_hex = send_and_receive(sock, mem_cmd)
    faulting_rip = int.from_bytes(
        bytes.fromhex(faulting_rip_hex.decode("latin1")), "little"
    )
    print(f"Faulting Instruction RIP: 0x{faulting_rip:X}")

    # Check closest symbol to the faulting instruction
    # If it is inside ntoskrnl, we resolve it relative to ntoskrnl symbols
    rva = faulting_rip - kernel_base
    if 0 <= rva <= pe_size:
        pe_va = 0x140000000 + rva
        name, diff = get_symbol_at(pe_va)
        print(
            f"Location:                 ntoskrnl.exe!{name}+0x{diff:X} (RVA: 0x{rva:X})"
        )
    else:
        # It's in another DLL or user mode
        print(f"Location:                 External (RVA relative to base: 0x{rva:X})")

    # Read instruction bytes (15 bytes maximum size)
    mem_cmd = f"m{faulting_rip:x},f".encode("latin1")
    inst_hex = send_and_receive(sock, mem_cmd)
    inst_bytes = bytes.fromhex(inst_hex.decode("latin1"))

    hex_str = " ".join(f"{b:02X}" for b in inst_bytes)
    print(f"Faulting Opcode Bytes:   {hex_str}")

    # Read trap frame info
    mem_cmd = f"m{rsp:x},28".encode("latin1")
    frame_hex = send_and_receive(sock, mem_cmd)
    frame_bytes = bytes.fromhex(frame_hex.decode("latin1"))
    cs = int.from_bytes(frame_bytes[8:16], "little")
    rflags = int.from_bytes(frame_bytes[16:24], "little")
    user_rsp = int.from_bytes(frame_bytes[24:32], "little")

    print(f"CS: 0x{cs:X} | RFLAGS: 0x{rflags:X} | Stack Pointer: 0x{user_rsp:X}")

    # Clean up breakpoint
    print("\nRemoving breakpoint...")
    remove_bp_cmd = f"z0,{fault_address:x},1".encode("latin1")
    send_and_receive(sock, remove_bp_cmd)

    sock.close()
    dbghelp.SymCleanup(h_process)


if __name__ == "__main__":
    debug_live()
