# WinP4Patch - CMPXCHG16B emulation shim (x86-64, GNU as syntax)
#
# Replaces `lock cmpxchg16b [mem]` at the patched sites.  Semantics match the
# real instruction:
#   * compare RDX:RAX with the 16 bytes at the target
#   * equal   -> store RCX:RBX, RAX/RDX unchanged, ZF = 1
#   * unequal -> load the memory value into RDX:RAX, ZF = 0
#
# Two properties matter more than speed:
#
#  1. interrupts stay ENABLED.  A demand-paging fault inside a `cli`'d
#     critical section lands in KiPageFault's IF=0 branch, which bugchecks
#     with IRQL_NOT_LESS_OR_EQUAL a few minutes into the session.
#
#  2. the spin lock records the owning CPU (KPCR self, gs:[0x18]) so a
#     page-fault handler that itself needs a CAS can re-enter instead of
#     deadlocking on a lock the same CPU already holds.
#
# A thunk adds the missing `push r9` and materialises the effective address:
#     push r9 ; lea r9,[base+disp] ; jmp worker
# worker pops r9 last, so the stack layout is the same for every form.

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
    push rsi
    push r8
    push r10
    push r11
    push rax                     # [rsp+08] expected low
    push rdx                     # [rsp+00] expected high
    mov  rsi, qword ptr gs:[0x18]
    lea  r8, [rip + 0x11223344]  # lock word
    cmp  qword ptr [r8], rsi
    je   2f
1:  xor  eax, eax
    lock cmpxchg qword ptr [r8], rsi
    jz   3f
    pause
    jmp  1b
3:  nop
2:  mov  rax, qword ptr [rsp+8]
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
    cmp  qword ptr [r8], rsi
    jne  5f
    mov  qword ptr [r8], 0
5:  add  rsp, 16
    pop  r11
    pop  r10
    pop  r8
    pop  rsi
    pop  rcx
    pop  rbx
    pop  r9
    pushfq
    or   dword ptr [rsp], 0x40
    popfq
    ret
4:  cmp  qword ptr [r8], rsi
    jne  6f
    mov  qword ptr [r8], 0
6:  add  rsp, 16
    pop  r11
    pop  r10
    pop  r8
    pop  rsi
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
