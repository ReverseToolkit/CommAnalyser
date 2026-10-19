/* Force DT_NEEDED on bionic. rustc links the cdylib with --as-needed;
 * static libQBDI/libc++ then satisfy C names and ld drops libc.so, leaving
 * constructors to call a null getauxval/property table. */
#include <dlfcn.h>
#include <stdlib.h>
#include <sys/auxv.h>
#include <sys/system_properties.h>

__attribute__((used, retain, visibility("default")))
void *const commanalyser_bionic_needed[] = {
    (void *)malloc,
    (void *)free,
    (void *)getauxval,
    (void *)__system_property_get,
    (void *)dlopen,
    (void *)dlsym,
};
