.intel_syntax noprefix
.text
.globl tramp
tramp:
    push r8
    push r9
    push r10
    push r11
    mov  r9, qword ptr [rsp+0x28]
    test r9b, 3
    jz   1f
    swapgs
1:  mov  r8, qword ptr [rsp+0x20]
    cmp  dword ptr [r8], 0xC70F49F0
    jne  8f
    movzx r9d, byte ptr [r8+4]
    cmp  r9b, 0x0A
    je   2f
    cmp  r9b, 0x0B
    jne  9f
    sti
    mov  r8, qword ptr [r11]
    .byte 0xE8, 0x33, 0x33, 0x33, 0x33
    jmp  3f
2:  sti
    mov  r8, qword ptr [r10]
    .byte 0xE8, 0x44, 0x44, 0x44, 0x44
3:  jz   4f
    and  dword ptr [rsp+0x30], 0xFFFFFFBF
    jmp  5f
4:  or   dword ptr [rsp+0x30], 0x40
5:  add  qword ptr [rsp+0x20], 5
    jmp  6f
8:  cmp  word ptr [r8], 0x0D0F
    jne  87f
    movzx r9d, byte ptr [r8+2]
    mov  r10d, r9d
    shr  r10d, 6
    and  r9d, 7
    mov  r11d, 3
    cmp  r9d, 4
    jne  81f
    inc  r11d
81: cmp  r10d, 0
    jne  82f
    cmp  r9d, 5
    jne  84f
    add  r11d, 4
    jmp  84f
82: cmp  r10d, 1
    jne  83f
    inc  r11d
    jmp  84f
83: add  r11d, 4
84: add  qword ptr [rsp+0x20], r11
    jmp  6f
87: cmp  byte ptr [r8], 0x9F
    je   88f
    cmp  byte ptr [r8], 0x9E
    jne  9f
88: .byte 0xE9, 0x99, 0x99, 0x99, 0x99
6:  mov  r9, qword ptr [rsp+0x28]
    test r9b, 3
    jz   85f
    swapgs
85: pop  r11
    pop  r10
    pop  r9
    pop  r8
    iretq
9:  mov  r10, qword ptr [rsp+0x28]
    test r10b, 3
    jz   7f
    swapgs
7:  pop  r11
    pop  r10
    pop  r9
    pop  r8
    sub  rsp, 8
    push rbp
    .byte 0xE9, 0x55, 0x66, 0x77, 0x88
