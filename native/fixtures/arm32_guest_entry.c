/* Cross-compiled by GitHub Actions and executed by the host ARM32 interpreter test. */
__attribute__((naked, used)) void _start(void) {
    __asm__ volatile(
        "mov r0, #40\n"
        "add r0, r0, #2\n"
        "mov r7, #1\n" /* Linux ARM __NR_exit; intercepted by the fixture SVC handler. */
        "svc #0\n"
    );
}
