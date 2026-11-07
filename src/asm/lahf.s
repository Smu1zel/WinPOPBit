.intel_syntax noprefix
.text
.globl lahfstub
lahfstub:
    cmp  byte ptr [r8], 0x9F
    jne  1f
    mov  r10d, dword ptr [rsp+0x30]
    and  r10d, 0xD5
    or   r10d, 0x02
    mov  r11, rax
    mov  r9, 0xFFFFFFFFFFFF00FF
    and  r11, r9
    shl  r10, 8
    or   r11, r10
    mov  rax, r11
    jmp  2f
1:  mov  r9, rax
    shr  r9, 8
    and  r9d, 0xFF
    and  r9d, 0xD5
    and  dword ptr [rsp+0x30], 0xFFFFFF2A
    or   dword ptr [rsp+0x30], r9d
2:  inc  qword ptr [rsp+0x20]
    mov  r9, qword ptr [rsp+0x28]
    test r9b, 3
    jz   3f
    swapgs
3:  pop  r11
    pop  r10
    pop  r9
    pop  r8
    iretq
