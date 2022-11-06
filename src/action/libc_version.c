#include <features.h>
#ifdef __GNU_LIBRARY__
#include <gnu/libc-version.h>
#else
#include <stddef.h>
#endif

const char *libc_version(void) {
#ifdef __GNU_LIBRARY__
  return gnu_get_libc_version();
#else
  return NULL;
#endif
}
