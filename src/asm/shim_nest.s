# WinP4Patch - CMPXCHG16B emulation shim, nesting-aware variant
#
# Same as shim.s but the lock word is a two-qword record:
#
#   [lock+0]  owning CPU (KPCR self, 0 = free)
#   [lock+8]  nesting depth of that CPU
#
# shim.s released the lock unconditionally when the owner exited, so a nested
# call (interrupt handler or page-fault handler inside the critical section)
# freed the lock while the outer call was still running.  Another CPU could
# then enter and observe a half-written 16-byte value.
#
# With a depth counter only the outermost exit releases, which is what makes
# this correct on SMP as well as on a single core.

.intel_syntax noprefix
.text

.globl worker
.globl th_rdi
.globl th_rsi
.globl th_r8
.globl th_r9d20
.globl th_r8d10
.globl th_r8d20
.globl th_r8d150
.globl th_r10
.globl th_r11
.globl th_r14
.globl th_r15
.globl th_rdi20
.globl th_r9d20
.globl th_r8d100

worker:
    push rbx
    push rcx
    push rsi
    push r8
    push r10
    push r11
    push rax                 # [rsp+08] expected low
    push rdx                 # [rsp+00] expected high

    mov  rsi, qword ptr gs:[0x18]
    lea  r8, [rip + 0x11223344]
    cmp  qword ptr [r8], rsi
    je   2f                  # already the owner: nested entry
1:  xor  eax, eax
    lock cmpxchg qword ptr [r8], rsi
    jz   3f
    pause
    jmp  1b
3:  mov  qword ptr [r8+8], 1
    jmp  4f
2:  inc  qword ptr [r8+8]

4:  mov  rax, qword ptr [rsp+8]
    mov  rdx, qword ptr [rsp+0]
    mov  r11, rax
    mov  r10, rdx
    mov  rax, qword ptr [r9]
    mov  rdx, qword ptr [r9+8]
    cmp  r11, rax
    jne  5f
    cmp  r10, rdx
    jne  5f
    mov  qword ptr [r9], rbx
    mov  qword ptr [r9+8], rcx

    dec  qword ptr [r8+8]
    jnz  6f
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
    or   dword ptr [rsp], 0x40
    popfq
    ret

5:  dec  qword ptr [r8+8]
    jnz  7f
    mov  qword ptr [r8], 0
7:  add  rsp, 16
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
th_r9d20:   push r9
            lea  r9, [r9+0x20]
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
