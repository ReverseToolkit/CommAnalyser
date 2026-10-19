/* Default-visibility trampolines. Symbols inside libQBDI.a are hidden, so
 * dlsym("qbdi_*") fails; these wrappers are the dynamic exports. */
typedef unsigned long rword;
typedef void *vm_ref;

void qbdi_initVM(vm_ref *instance, const char *cpu, const char **mattrs, unsigned opts);
void qbdi_terminateVM(vm_ref instance);
unsigned char qbdi_addInstrumentedModuleFromAddr(vm_ref instance, rword addr);
void qbdi_addInstrumentedRange(vm_ref instance, rword start, rword end);
void qbdi_removeInstrumentedRange(vm_ref instance, rword start, rword end);
unsigned char qbdi_run(vm_ref instance, rword start, rword stop);
void *qbdi_getGPRState(vm_ref instance);
unsigned qbdi_addCodeCB(vm_ref instance, unsigned pos, void *cbk, void *data, int priority);
unsigned qbdi_addMemAccessCB(vm_ref instance, unsigned kind, void *cbk, void *data, int priority);
const void *qbdi_getInstAnalysis(vm_ref instance, unsigned analysis);
void *qbdi_getInstMemoryAccess(vm_ref instance, unsigned long *size);
unsigned char qbdi_recordMemoryAccess(vm_ref instance, unsigned kind);

#define WRAP(ret, name, params, args)                                         \
    __attribute__((visibility("default"))) ret comm_##name params {           \
        return name args;                                                     \
    }

WRAP(void, qbdi_initVM, (vm_ref * instance, const char *cpu, const char **mattrs, unsigned opts),
     (instance, cpu, mattrs, opts))
WRAP(void, qbdi_terminateVM, (vm_ref instance), (instance))
WRAP(unsigned char, qbdi_addInstrumentedModuleFromAddr, (vm_ref instance, rword addr),
     (instance, addr))
WRAP(void, qbdi_addInstrumentedRange, (vm_ref instance, rword start, rword end),
     (instance, start, end))
WRAP(void, qbdi_removeInstrumentedRange, (vm_ref instance, rword start, rword end),
     (instance, start, end))
WRAP(unsigned char, qbdi_run, (vm_ref instance, rword start, rword stop), (instance, start, stop))
WRAP(void *, qbdi_getGPRState, (vm_ref instance), (instance))
WRAP(unsigned, qbdi_addCodeCB,
     (vm_ref instance, unsigned pos, void *cbk, void *data, int priority),
     (instance, pos, cbk, data, priority))
WRAP(unsigned, qbdi_addMemAccessCB,
     (vm_ref instance, unsigned kind, void *cbk, void *data, int priority),
     (instance, kind, cbk, data, priority))
WRAP(const void *, qbdi_getInstAnalysis, (vm_ref instance, unsigned analysis),
     (instance, analysis))
WRAP(void *, qbdi_getInstMemoryAccess, (vm_ref instance, unsigned long *size), (instance, size))
WRAP(unsigned char, qbdi_recordMemoryAccess, (vm_ref instance, unsigned kind), (instance, kind))
