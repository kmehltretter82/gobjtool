// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Tiny test-only frontend for Linux's native x86 instruction decoder.
 *
 * Build this against a pinned Linux source and object tree, then pipe one
 * executable section to stdin.  Each output row is "offset length".  The
 * production gobjtool binary never links or calls this C code.
 */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define unlikely(condition) (condition)
#include <asm/insn.h>
#include <inat.c>
#include <insn.c>

int main(void)
{
	unsigned char *data = NULL;
	size_t size = 0;
	size_t capacity = 0;

	for (;;) {
		size_t count;

		if (size == capacity) {
			size_t next = capacity ? capacity * 2 : 4096;
			unsigned char *grown = realloc(data, next);

			if (!grown) {
				fprintf(stderr, "x86 oracle: allocation failed\n");
				free(data);
				return 2;
			}
			data = grown;
			capacity = next;
		}
		count = fread(data + size, 1, capacity - size, stdin);
		size += count;
		if (!count) {
			if (ferror(stdin)) {
				fprintf(stderr, "x86 oracle: read failed: %d\n", errno);
				free(data);
				return 2;
			}
			break;
		}
	}

	for (size_t offset = 0; offset < size;) {
		struct insn instruction;
		int result = insn_decode(&instruction, data + offset,
					 (int)(size - offset), INSN_MODE_64);

		if (result < 0 || !instruction.length) {
			fprintf(stderr, "x86 oracle: decode failed at %zu (%d)\n",
				offset, result);
			free(data);
			return 1;
		}
		printf("%zu %u\n", offset, instruction.length);
		offset += instruction.length;
	}

	free(data);
	return 0;
}
