# WinP4Patch - CMPXCHG16B emulation shim, lock-free variant (diagnostic)
#
# Same semantics as shim.s but without the inter-CPU spin lock.  Useful to
# tell "the emulation logic is wrong" apart from "the lock slot can't be
# written": if this one boots and shim.s does not, the lock address is at
# fault, not the compare/store logic.
#
# Safe on single-core CPUs (Pentium 4, first-generation Athlon 64).  On an SMP
# machine two CPUs can interleave the two 8-byte stores, so do not ship this
# as the default.

.intel_syntax noprefix
.text

.globl worker
.globl th_rdi
.globl th_rsi
.globl th_r8
.globl th_r8d10
.globl th_r8d20
.globl th_r8d150
.globl th_r10
.globl th_r11
.globl th_r14
.globl th_r15
.globl th_rdi20
.globl th_r8d100

worker:
    push rbx
    push rcx
    push r10
    push r11
    push rax                 # [rsp+08] expected low
    push rdx                 # [rsp+00] expected high

    mov  rax, qword ptr [rsp+8]
    mov  rdx, qword ptr [rsp+0]
    mov  r11, rax
    mov  r10, rdx
    mov  rax, qword ptr [r9]
    mov  rdx, qword ptr [r9+8]
    cmp  r11, rax
    jne  4f
    cmp  r10, rdx
    jne  4f
    mov  qword ptr [r9], rbx
    mov  qword ptr [r9+8], rcx
    add  rsp, 16
    pop  r11
    pop  r10
    pop  rcx
    pop  rbx
    pop  r9
    pushfq
    or   dword ptr [rsp], 0x40
    popfq
    ret

4:  add  rsp, 16
    pop  r11
    pop  r10
    pop  rcx
    pop  rbx
    pop  r9
    pushfq
    and  dword ptr [rsp], 0xFFFFFFBF
    popfq
    ret

th_rdi:     push r9
            lea  r9, [rdi]
            jmp  worker
th_rsi:     push r9
            lea  r9, [rsi]
            jmp  worker
th_r8:      push r9
            lea  r9, [r8]
            jmp  worker
th_r10:     push r9
            lea  r9, [r10]
            jmp  worker
th_r11:     push r9
            lea  r9, [r11]
            jmp  worker
th_r14:     push r9
            lea  r9, [r14]
            jmp  worker
th_r15:     push r9
            lea  r9, [r15]
            jmp  worker
th_rdi20:   push r9
            lea  r9, [rdi+0x20]
            jmp  worker
th_r8d10:   push r9
            lea  r9, [r8+0x10]
            jmp  worker
th_r8d20:   push r9
            lea  r9, [r8+0x20]
            jmp  worker
th_r8d100:  push r9
            lea  r9, [r8+0x100]
            jmp  worker
th_r8d150:  push r9
            lea  r9, [r8+0x150]
            jmp  worker
