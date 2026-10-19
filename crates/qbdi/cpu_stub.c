/* Outline-atomics CPU-feature globals without compiler-rt aarch64.c constructors.
 *
 * NDK -moutline-atomics plus libclang_rt.builtins aarch64.c.o registers
 * init_have_lse_atomics / __init_cpu_features in .init_array. Those call
 * getauxval(AT_HWCAP) and __system_property_get("ro.arch") (Exynos 9810
 * workaround). Inside a dlopen'd agent that only NEEDED liblog.so the
 * lookup hits a null table and SIGSEGVs. Hidden zeros keep LL/SC atomics.
 */
#include <stdbool.h>

__attribute__((visibility("hidden"), nocommon))
bool __aarch64_have_lse_atomics = false;

__attribute__((visibility("hidden"), nocommon))
struct {
    unsigned long long features;
} __aarch64_cpu_features;

__attribute__((visibility("hidden")))
void __init_cpu_features(void) {}

__attribute__((visibility("hidden")))
void __init_cpu_features_resolver(unsigned long hwcap, const void *arg) {
    (void)hwcap;
    (void)arg;
}
