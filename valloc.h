#ifndef VALLOC_H
#define VALLOC_H

#include <stddef.h>

#ifdef VALLOC_MALLOC
// stdlib allocator emulation layer
#define malloc(size) valloc(NULL, size)
#define calloc(size, count) vallocaz(NULL, size, count)
#define realloc(mem, size) valloc(mem, size)
#define reallocarray(mem, size, count) valloca(mem, size, count)
#define free(mem) (void)valloc(mem, 0)
#endif

void *valloc(void *mem, size_t size);
void *valloca(void *mem, size_t size, size_t count);

void *vallocz(void *mem, size_t size);
void *vallocaz(void *mem, size_t size, size_t count);

// Returns the length of the allocated block of memory
size_t vallocl(void *mem);

#endif
