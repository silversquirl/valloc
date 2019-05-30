#include <stdio.h>
#include <string.h>
#include "valloc.h"

#define KiB ((size_t)(1<<10))
#define MiB ((size_t)(KiB<<10))
#define GiB ((size_t)(MiB<<10))
#define TiB ((size_t)(GiB<<10))
#define PiB ((size_t)(TiB<<10))
#define EiB ((size_t)(PiB<<10))
#define ZiB ((size_t)(EiB<<10))
#define YiB ((size_t)(ZiB<<10))

const char *hello = "Hello, ", *world = "world!";

int main() {
	char *str = valloc(NULL, strlen(hello) + 1);
	printf("%p (%zu)\n", str, vallocl(str));

	strcpy(str, hello);
	printf("%s\n", str);

	str = valloc(str, strlen(hello) + strlen(world) + 1);
	printf("%p (%zu)\n", str, vallocl(str));

	strcat(str, world);
	printf("%s\n", str);

	// Reallocate lots more data
	// Hopefully, this won't copy, because the new page will be allocated after the previous one
	str = valloc(str, 4*KiB);
	printf("%p (%zu)\n", str, vallocl(str));
	printf("%s\n", str);

	// Reallocation in-place should be possible even if something has been allocated there previously
	char *tmp = valloc(NULL, 1);
	valloc(tmp, 0);
	str = valloc(str, 6*KiB);
	printf("%p (%zu)\n", str, vallocl(str));
	printf("%s\n", str);

	// Allocate some other data to separate things before reallocating again
	tmp = valloc(NULL, 1);
	// Reallocate more bigger again
	str = valloc(str, 8*KiB);
	printf("%p (%zu)\n", str, vallocl(str));
	printf("%s\n", str);
	// Free the temporary data
	valloc(tmp, 0);


	valloc(str, 0);

	// Allocate a large chunk of memory
	puts("----");
	size_t many_len = 4*MiB;
	unsigned char *many_data = valloc(NULL, many_len);

	many_data[0] = 0;
	for (size_t i = 1; i < many_len; i++) {
		many_data[i] = many_data[i-1] + 1;
	}

	for (size_t i = 1; i < many_len; i++) {
		if (many_data[i] != (unsigned char)(many_data[i-1]+1)) {
			printf("Mismatch at index %zu: expected %d, got %d\n", i, many_data[i-1]+1, many_data[i]);
			return 1;
		}
	}

	printf("many_data length: %zu\n", vallocl(many_data));

	valloc(many_data, 0);

	// Allocate way too much memory
	puts("----");
	size_t amount = TiB;
	printf("Attempting to allocate %zu bytes\n", amount);
	void *toomuch = valloc(NULL, amount);
	printf("%p\n", toomuch);
	if (toomuch) {
		printf("Allocating 1TiB succeeded. Either you have way too much RAM or swap, or something has gone wrong\n");
		printf("vallocl says %zu, amount says %zu\n", vallocl(toomuch), amount);
		return 1;
	}

	return 0;
}
