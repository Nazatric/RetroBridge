#include <errno.h>
#include <fcntl.h>
#include <jni.h>
#include <math.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>

typedef union FloatBits {
    float value;
    uint32_t bits;
} FloatBits;

static const char kDemoPath[] =
    "/data/data/org.retrobridge.guestdemo/files/native-demo.txt";

static float (*volatile g_sqrtf)(float) = sqrtf;

static int square_root_matches(uint32_t input_bits, uint32_t expected_bits) {
    FloatBits input = {.bits = input_bits};
    FloatBits result;
    result.value = g_sqrtf(input.value);
    return result.bits == expected_bits;
}

static int append_line(const char* line, size_t length) {
    const int descriptor = open(kDemoPath, O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (descriptor < 0) return -1000 - errno;
    const ssize_t written = write(descriptor, line, length);
    const int write_status = written == (ssize_t)length ? 0 : -2000 - errno;
    const int close_status = close(descriptor);
    if (write_status != 0) return write_status;
    return close_status == 0 ? 0 : -3000 - errno;
}

__attribute__((constructor)) static void retrobridge_demo_constructor(void) {
    if (square_root_matches(0x42a20000U, 0x41100000U)) {
        (void)append_line("constructor\n", sizeof("constructor\n") - 1U);
    } else {
        (void)append_line("constructor-math-failed\n", sizeof("constructor-math-failed\n") - 1U);
    }
}

__attribute__((destructor)) static void retrobridge_demo_destructor(void) {
    (void)append_line("destructor\n", sizeof("destructor\n") - 1U);
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* virtual_machine, void* reserved) {
    (void)virtual_machine;
    (void)reserved;
    (void)square_root_matches(0x42800000U, 0x41000000U);
    (void)append_line("JNI_OnLoad\n", sizeof("JNI_OnLoad\n") - 1U);
    return JNI_VERSION_1_6;
}

JNIEXPORT int retrobridge_main(void) {
    if (!square_root_matches(0x43100000U, 0x41400000U)) return -1;
    const int write_status = append_line("entrypoint\n", sizeof("entrypoint\n") - 1U);
    return write_status == 0 ? 42 : write_status;
}
