/* QBDI/LLVM call __clear_cache after writing exec blocks.
 *
 * Clang's builtin of this name compiles to a call to this same symbol, so a
 * wrapper around that builtin recurses until the JS worker stack dies
 * (tombstone: SEGV_ACCERR, SP not in a rw map, identical 32-byte frames).
 * Inject cannot dlsym compiler-rt; emit DC/IC directly.
 */
void __clear_cache(void *start, void *end) {
    unsigned long s = (unsigned long)start;
    unsigned long e = (unsigned long)end;
    if (s >= e) {
        return;
    }

    unsigned long ctr;
    __asm__ volatile("mrs %0, ctr_el0" : "=r"(ctr));
    unsigned dsize = 4u << (unsigned)((ctr >> 16) & 15u);
    unsigned isize = 4u << (unsigned)(ctr & 15u);
    unsigned long addr = s & ~((unsigned long)dsize - 1ul);
    for (; addr < e; addr += dsize) {
        __asm__ volatile("dc cvau, %0" ::"r"(addr) : "memory");
    }
    __asm__ volatile("dsb ish" ::: "memory");
    addr = s & ~((unsigned long)isize - 1ul);
    for (; addr < e; addr += isize) {
        __asm__ volatile("ic ivau, %0" ::"r"(addr) : "memory");
    }
    __asm__ volatile("dsb ish" ::: "memory");
    __asm__ volatile("isb" ::: "memory");
}

void __aarch64_sync_cache_range(void *start, void *end) {
    __clear_cache(start, end);
}
