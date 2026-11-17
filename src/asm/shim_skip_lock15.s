# WinPOPBit - CMPXCHG16B shim: spinlock (gs:[0x18] owner) + user-address skip
#
# This is the variant that booted to the desktop on the Socket 754 machine
# (checksum 0x00B8E43C).  The interrupt-masked rewrite (cli) blue-screened
# there, so this file keeps the lock the original build used.
#
#   pushfq
#   acquire  qword [lock]  (owner = gs:[0x18], nesting counter at lock+8)
#   if the target is below the kernel boundary -> skip the write, report ZF=1
#   else 128-bit CAS, then release
#   popfq / pop r9 / ret
#
# r8/r10/r11 are scratch; rax/rdx hold the expected value, rbx/rcx the new one.

    .intel_syntax noprefix
    .text

    .globl worker
worker:
    pushfq
    push rbx
    push rcx
    push rsi
    push r8
    push r10
    push r11
    push rax                 # [rsp+08] expected low
    push rdx                 # [rsp+00] expected high

    lea  r8, [rip + 0x11223344]      # lock word
    mov  rsi, qword ptr gs:[0x18]
    cmp  qword ptr [r8], rsi
    je   2f                          # nested
1:  xor  eax, eax
    lock cmpxchg qword ptr [r8], rsi
    jz   3f
    pause
    jmp  1b
3:  mov  qword ptr [r8+8], 1
    jmp  4f
2:  inc  qword ptr [r8+8]

4:  mov  r11, 0xFFFF800000000000
    cmp  r9, r11
    jb   .Luseraddr

    mov  rax, qword ptr [rsp+8]
    mov  rdx, qword ptr [rsp+0]
    mov  r11, rax
    mov  r10, rdx
    mov  rax, qword ptr [r9]
    mov  rdx, qword ptr [r9+8]
    cmp  r11, rax
    jne  .Lfail
    cmp  r10, rdx
    jne  .Lfail
    mov  qword ptr [r9], rbx
    mov  qword ptr [r9+8], rcx
    or   qword ptr [rsp+0x40], 0x40            # ZF = 1
    jmp  .Ldone
.Lfail:
    mov  qword ptr [rsp+8], rax
    mov  qword ptr [rsp], rdx
    and  qword ptr [rsp+0x40], 0xFFFFFFFFFFFFFFBF
    jmp  .Ldone
.Luseraddr:
    or   qword ptr [rsp+0x40], 0x40            # pretend success

.Ldone:
    dec  qword ptr [r8+8]
    jnz  5f
    mov  qword ptr [r8], 0
5:  pop  rdx
    pop  rax
    pop  r11
    pop  r10
    pop  r8
    pop  rsi
    pop  rcx
    pop  rbx
    popfq
    pop  r9
    ret

    .globl th_rdi
th_rdi:
    push r9
    lea  r9, [rdi]
    jmp  worker
    .globl th_rsi
th_rsi:
    push r9
    lea  r9, [rsi]
    jmp  worker
    .globl th_r8
th_r8:
    push r9
    lea  r9, [r8]
    jmp  worker
    .globl th_r10
th_r10:
    push r9
    lea  r9, [r10]
    jmp  worker
    .globl th_r11
th_r11:
    push r9
    lea  r9, [r11]
    jmp  worker
    .globl th_r14
th_r14:
    push r9
    lea  r9, [r14]
    jmp  worker
    .globl th_r15
th_r15:
    push r9
    lea  r9, [r15]
    jmp  worker
    .globl th_rdi20
th_rdi20:
    push r9
    lea  r9, [rdi+0x20]
    jmp  worker
    .globl th_r9d20
th_r9d20:
    push r9
    lea  r9, [r9+0x20]
    jmp  worker
    .globl th_r8d10
th_r8d10:
    push r9
    lea  r9, [r8+0x10]
    jmp  worker
    .globl th_r8d20
th_r8d20:
    push r9
    lea  r9, [r8+0x20]
    jmp  worker
    .globl th_r8d100
th_r8d100:
    push r9
    lea  r9, [r8+0x100]
    jmp  worker
    .globl th_r8d150
th_r8d150:
    push r9
    lea  r9, [r8+0x150]
    jmp  worker

    .globl th_r8d160
th_r8d160:
    push r9
    lea  r9, [r8+0x160]
    jmp  worker
    .globl th_r14d20
th_r14d20:
    push r9
    lea  r9, [r14+0x20]
    jmp  worker
