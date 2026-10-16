/* Cross-compiled by GitHub Actions as a small ARM32 ET_DYN executable fixture. */
__attribute__((naked, used)) void _start(void) {
    __asm__ volatile(
        "mov r0, #0\n"
        "mov r7, #1\n" /* Linux ARM __NR_exit */
        "svc #0\n"
    );
}
