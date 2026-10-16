.syntax unified
.arm
.fpu vfpv3-d16

.section .text
.global _start
.type _start, %function
_start:
    movw r0, #0
    movt r0, #0x4220       @ 40.0f
    vmov s0, r0
    movw r1, #0
    movt r1, #0x4000       @ 2.0f
    vmov s1, r1
    vadd.f32 s2, s0, s1
    vmov r2, s2
    movw r3, #0
    movt r3, #0x4228       @ 42.0f
    cmp r2, r3
    movne r0, #1
    moveq r0, #42
    mov r7, #1             @ Linux ARM __NR_exit; intercepted by the fixture SVC handler.
    svc #0
.size _start, . - _start
