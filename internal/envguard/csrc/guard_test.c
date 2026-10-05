/* guard_test.c — unit tests for guard_common.h redaction.
 *
 * Built and run by `make guard-test` (requires a C compiler; uses
 * AddressSanitizer so the historic heap-overflow class fails loudly, not
 * silently). NOT linked into any shipped artifact.
 *
 * Each test sets g_secret/g_len/g_count directly (bypassing parse) except
 * the parse tests, which drive parse_secrets() through the environment.
 */
#define _GNU_SOURCE
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "guard_common.h"

static int failures;

#define CHECK(cond, msg) do { \
	if (!(cond)) { printf("FAIL: %s\n", msg); failures++; } \
	else { printf("ok: %s\n", msg); } \
} while (0)

static void set_secrets(const char *vals[], size_t lens[], int n) {
	for (int i = 0; i < n; i++) {
		g_secret[i] = malloc(lens[i] + 1);
		memcpy(g_secret[i], vals[i], lens[i]);
		g_secret[i][lens[i]] = 0;
		g_len[i] = lens[i];
	}
	g_count = n;
}

static void clear_secrets(void) {
	for (int i = 0; i < g_count; i++) {
		free(g_secret[i]);
		g_secret[i] = NULL;
	}
	g_count = 0;
}

/* The historic bug: two 4-char secrets in one write overflowed n+10. */
static void test_short_secret_overflow(void) {
	const char *v[] = {"abcd"};
	size_t l[] = {4};
	set_secrets(v, l, 1);
	const char *in = "xxabcdYYabcdZZ";
	char *t = malloc(strlen(in) + 1);
	memcpy(t, in, strlen(in));
	size_t n = strlen(in);
	redact(&t, &n);
	CHECK(n == strlen("xx[REDACTED]YY[REDACTED]ZZ"), "short secret twice: length");
	CHECK(memcmp(t, "xx[REDACTED]YY[REDACTED]ZZ", n) == 0, "short secret twice: content");
	free(t);
	clear_secrets();
}

/* A secret equal to the replacement must not loop forever. */
static void test_self_match(void) {
	const char *v[] = {"[REDACTED]"};
	size_t l[] = {10};
	/* parse path refuses it; direct table must also terminate */
	set_secrets(v, l, 1);
	const char *in = "a[REDACTED]b";
	char *t = malloc(strlen(in) + 1);
	memcpy(t, in, strlen(in));
	size_t n = strlen(in);
	redact(&t, &n);
	CHECK(n == strlen(in), "self-match terminates");
	free(t);
	clear_secrets();
}

/* Long secrets shrink in place without corrupting neighbours. */
static void test_long_secret(void) {
	const char *v[] = {"supersecretvalue"};
	size_t l[] = {16};
	set_secrets(v, l, 1);
	const char *in = "pre-supersecretvalue-post";
	char *t = malloc(strlen(in) + 1);
	memcpy(t, in, strlen(in));
	size_t n = strlen(in);
	redact(&t, &n);
	CHECK(n == strlen("pre-[REDACTED]-post"), "long secret: length");
	CHECK(memcmp(t, "pre-[REDACTED]-post", n) == 0, "long secret: content");
	free(t);
	clear_secrets();
}

/* Overlapping occurrences are consumed left-to-right, forward-only. */
static void test_overlap(void) {
	const char *v[] = {"aaaa"};
	size_t l[] = {4};
	set_secrets(v, l, 1);
	const char *in = "aaaaaaaa"; /* two non-overlapping matches */
	char *t = malloc(strlen(in) + 1);
	memcpy(t, in, strlen(in));
	size_t n = strlen(in);
	redact(&t, &n);
	CHECK(n == 2 * 10, "overlap: length");
	free(t);
	clear_secrets();
}

/* parse: short fragments skipped, [REDACTED] literal refused, separator split. */
static void test_parse(void) {
	setenv("AGENTSECRETS_MASK", "ab\x1f" "goodsecret\x1f" "[REDACTED]\x1f", 1);
	parse_secrets();
	CHECK(g_count == 1, "parse keeps only goodsecret");
	if (g_count == 1) {
		CHECK(strcmp(g_secret[0], "goodsecret") == 0, "parse content");
	}
	clear_secrets();
	unsetenv("AGENTSECRETS_MASK");
}

int main(void) {
	test_short_secret_overflow();
	test_self_match();
	test_long_secret();
	test_overlap();
	test_parse();
	if (failures == 0) {
		printf("ALL GUARD TESTS PASS\n");
		return 0;
	}
	printf("%d FAILURES\n", failures);
	return 1;
}
