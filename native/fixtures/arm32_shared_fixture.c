/* Links against the NDK's Android libc stub to produce a real DT_NEEDED string. */
#include <unistd.h>

__attribute__((visibility("default"))) int retrobridge_fixture_add(int left, int right) {
    /* The function is inspected, never run. This reference keeps libc.so in DT_NEEDED. */
    (void)write(-1, "", 0);
    return left + right;
}
