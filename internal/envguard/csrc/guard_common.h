/* guard_common.h — shared redaction core for the env-guard interposers.
 *
 * The platform sources differ only in how they hook the write path (ELF symbol
 * precedence on Linux vs dyld interposing on macOS) and how they mark the process
 * un-attachable (prctl vs ptrace). The secret parsing and redaction below is
 * identical on every platform and lives here so the security-sensitive logic
 * cannot drift between them.
 *
 * Everything is `static`: this header is included by exactly one translation unit
 * per build (guard_linux.c OR guard_darwin.c), never linked together.
 *
 * The including .c MUST define the platform feature macro (_GNU_SOURCE on Linux,
 * _DARWIN_C_SOURCE on macOS) BEFORE including this header so memmem is declared.
 *
 * Secret values are supplied by the parent through AGENTSECRETS_MASK, joined by
 * the ASCII Unit Separator (0x1f), which cannot appear in an ordinary value.
 *
 * Redaction is HYGIENE, NOT A SECURITY BOUNDARY: a program that controls its own
 * bytes can always evade it (split the secret across writes, encode it, print
 * through a path not hooked here). It exists to catch accidental echoes, not to
 * stop deliberate exfiltration.
 */
#ifndef AGENTSECRETS_GUARD_COMMON_H
#define AGENTSECRETS_GUARD_COMMON_H

#include <stdlib.h>
#include <string.h>

#define MAX_SECRETS 256
#define REPLACEMENT "[REDACTED]"
#define REPLACEMENT_LEN 10

static char  *g_secret[MAX_SECRETS];
static size_t g_len[MAX_SECRETS];
static int    g_count;

static void parse_secrets(void) {
	const char *raw = getenv("AGENTSECRETS_MASK");
	if (!raw) {
		return;
	}
	const char *p = raw;
	while (*p && g_count < MAX_SECRETS) {
		const char *sep = strchr(p, 0x1f);
		size_t l = sep ? (size_t)(sep - p) : strlen(p);
		if (l >= 4) { /* very short values would redact unrelated text */
			g_secret[g_count] = malloc(l + 1);
			if (!g_secret[g_count]) {
				break;
			}
			memcpy(g_secret[g_count], p, l);
			g_secret[g_count][l] = 0;
			g_len[g_count] = l;
			g_count++;
		}
		if (!sep) {
			break;
		}
		p = sep + 1;
	}
}

/* redact replaces every secret occurrence in b[0..len) and returns the new length.
 * Callers must provide a buffer with room for REPLACEMENT_LEN - 1 extra bytes. */
static size_t redact(char *b, size_t len) {
	for (int i = 0; i < g_count; i++) {
		size_t sl = g_len[i];
		if (sl == 0 || sl > len) {
			continue;
		}
		char *pos;
		while ((pos = memmem(b, len, g_secret[i], sl)) != NULL) {
			size_t off = (size_t)(pos - b);
			memcpy(pos, REPLACEMENT, REPLACEMENT_LEN);
			memmove(pos + REPLACEMENT_LEN, pos + sl, len - off - sl + 1);
			len = len + REPLACEMENT_LEN - sl;
		}
	}
	return len;
}

#endif /* AGENTSECRETS_GUARD_COMMON_H */
