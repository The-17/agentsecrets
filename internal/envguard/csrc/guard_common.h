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
 * the ASCII Unit Separator (0x1f). Values containing the separator are
 * excluded upstream (they would fragment and match nothing); fragments that
 * arrive anyway are treated as independent values, harmlessly.
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
		/* Very short values would redact unrelated text; the literal
		 * replacement is never a secret (it would redact itself forever). */
		if (l >= 4 && (l != REPLACEMENT_LEN || memcmp(p, REPLACEMENT, l) != 0)) {
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

/* count_occ counts NON-OVERLAPPING occurrences of s in b, scanning forward.
 * Forward-only scanning is load-bearing: replaced regions are never
 * rescanned, so a replacement can never match (itself or another secret). */
static size_t count_occ(const char *b, size_t len, const char *s, size_t sl) {
	size_t n = 0;
	const char *p = b;
	size_t rem = len;
	while (rem >= sl && (p = memmem(p, rem, s, sl)) != NULL) {
		n++;
		p += sl;
		rem = len - (size_t)(p - b);
	}
	return n;
}

/* redact replaces every secret occurrence in *pbuf (of *plen bytes) and updates
 * *plen to the new length. Buffers that may GROW (any secret shorter than the
 * replacement) are enlarged with realloc to fit the worst case FIRST — the
 * size is counted, never guessed — so replacement can never overflow no
 * matter how short the secrets or how many occurrences. Scanning is strictly
 * forward: already-emitted output is never rescanned, which rules out
 * self-matching and cross-secret re-match loops by construction (a secret
 * equal to the replacement text is also refused at parse time).
 *
 * On realloc failure the buffer keeps whatever replacements completed so far
 * (fail-soft toward redacted, never toward corrupt). Callers MUST route every
 * replacement through this function — never write a growing replacement into
 * a fixed-size buffer. */
static void redact(char **pbuf, size_t *plen) {
	char *b = *pbuf;
	size_t len = *plen;
	for (int i = 0; i < g_count; i++) {
		size_t sl = g_len[i];
		if (sl == 0 || sl > len) {
			continue;
		}
		if (sl < REPLACEMENT_LEN) {
			size_t n = count_occ(b, len, g_secret[i], sl);
			if (n == 0) {
				continue;
			}
			char *nb = realloc(b, len + n * (REPLACEMENT_LEN - sl));
			if (!nb) {
				break;
			}
			b = nb;
		}
		size_t off = 0;
		while (off + sl <= len) {
			char *pos = memmem(b + off, len - off, g_secret[i], sl);
			if (!pos) {
				break;
			}
			size_t at = (size_t)(pos - b);
			/* Tail FIRST, then stamp: when growing, the tail overlaps the
			 * replacement zone, so stamping first would clobber the source.
			 * (The reverse order corrupts output — and with it, trust.) */
			memmove(pos + REPLACEMENT_LEN, pos + sl, len - at - sl);
			memcpy(pos, REPLACEMENT, REPLACEMENT_LEN);
			if (sl >= REPLACEMENT_LEN) {
				len = len - (sl - REPLACEMENT_LEN);
			} else {
				len = len + (REPLACEMENT_LEN - sl);
			}
			off = at + REPLACEMENT_LEN;
		}
	}
	*pbuf = b;
	*plen = len;
}

#endif /* AGENTSECRETS_GUARD_COMMON_H */
