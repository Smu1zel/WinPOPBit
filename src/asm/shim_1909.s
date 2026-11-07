.intel_syntax noprefix
.text
.globl worker
.globl th_rdi
.globl th_rdi20
.globl th_rsi
.globl th_r8d20
.globl th_r8d150
.globl th_r10
.globl th_r11
.globl th_r14

# CAS emulation without cli (same design as the 23H2 P7 shim):
#  - interrupts stay enabled so a demand-paging fault inside the critical
#    section is handled normally
#  - the spin lock stores the owning CPU (KPCR self, gs:[0x18]) so the same
#    CPU may re-enter from a page-fault handler without deadlocking
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
th_rdi20:   push r9
            lea  r9, [rdi+0x20]
            jmp  worker
th_rsi:     push r9
            lea  r9, [rsi]
            jmp  worker
th_r8d20:   push r9
            lea  r9, [r8+0x20]
            jmp  worker
th_r8d150:  push r9
            lea  r9, [r8+0x150]
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
